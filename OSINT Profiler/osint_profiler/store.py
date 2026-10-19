from __future__ import annotations
import base64
import json
import re
from collections import Counter
from datetime import date
from pathlib import Path
from . import adapters
from .authorization import AUTHORIZATIONS_DDL
from .util import MAX_FILE, data_root, database, digest, json_text, now, process_alive, required, rows, slug, uid, url_key

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS artifacts(id TEXT PRIMARY KEY,sha256 TEXT UNIQUE NOT NULL,name TEXT NOT NULL,path TEXT NOT NULL,adapter TEXT NOT NULL,metadata TEXT NOT NULL,added TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS entities(id TEXT PRIMARY KEY,kind TEXT NOT NULL,platform TEXT NOT NULL,label TEXT NOT NULL,identifier TEXT NOT NULL,identity_key TEXT UNIQUE NOT NULL,basis TEXT NOT NULL,added TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS observations(id TEXT PRIMARY KEY,artifact_id TEXT NOT NULL REFERENCES artifacts(id),selector TEXT NOT NULL,tool TEXT NOT NULL,query TEXT NOT NULL,identifier_kind TEXT NOT NULL,site TEXT NOT NULL,url TEXT NOT NULL,status TEXT NOT NULL,reported_status TEXT NOT NULL,extra TEXT NOT NULL,entity_id TEXT REFERENCES entities(id),fingerprint TEXT NOT NULL,added TEXT NOT NULL,UNIQUE(artifact_id,selector));
CREATE INDEX IF NOT EXISTS observation_fingerprint ON observations(fingerprint);
CREATE TABLE IF NOT EXISTS reviews(fingerprint TEXT PRIMARY KEY,status TEXT NOT NULL,reason TEXT NOT NULL,updated TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS relations(id TEXT PRIMARY KEY,source TEXT NOT NULL REFERENCES entities(id),target TEXT NOT NULL REFERENCES entities(id),kind TEXT NOT NULL,basis TEXT NOT NULL,status TEXT NOT NULL,note TEXT NOT NULL,since TEXT NOT NULL,until TEXT NOT NULL,added TEXT NOT NULL,updated TEXT NOT NULL,UNIQUE(source,target,kind,basis));
CREATE TABLE IF NOT EXISTS evidence(id TEXT PRIMARY KEY,relation_id TEXT NOT NULL REFERENCES relations(id),artifact_id TEXT NOT NULL REFERENCES artifacts(id),role TEXT NOT NULL,selector TEXT NOT NULL,note TEXT NOT NULL,added TEXT NOT NULL,UNIQUE(relation_id,artifact_id,role,selector));
CREATE TABLE IF NOT EXISTS notes(id TEXT PRIMARY KEY,kind TEXT NOT NULL,text TEXT NOT NULL,added TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS events(id TEXT PRIMARY KEY,action TEXT NOT NULL,subject TEXT NOT NULL,before_json TEXT NOT NULL,after_json TEXT NOT NULL,added TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY,tool TEXT NOT NULL,target TEXT NOT NULL,state TEXT NOT NULL,plan TEXT NOT NULL,path TEXT NOT NULL,started TEXT NOT NULL,ended TEXT,exit_code INTEGER,message TEXT NOT NULL DEFAULT '');
""" + AUTHORIZATIONS_DDL + ";"
SCHEMA_VERSION = "2"
KINDS = {"account", "person", "persona", "group", "server", "email", "phone", "transaction", "incident", "other"}
RELATIONS = {"same_entity", "associated_with", "owns", "purchased", "links_to", "advertises", "depicts"}
STATES = {"accepted", "proposed", "rejected"}

class Store:
    def __init__(self, root=None):
        self.root = data_root(root)
        self.cases = self.root / "cases"
        self.inbox = self.root / "inbox"
        self.migrated = set()
        self.cases.mkdir(parents=True, exist_ok=True)
        self.inbox.mkdir(parents=True, exist_ok=True)
        with database(self.inbox / "inbox.sqlite") as con:
            con.execute("CREATE TABLE IF NOT EXISTS imports(id TEXT PRIMARY KEY,sha256 TEXT UNIQUE,name TEXT,path TEXT,preview TEXT,added TEXT,state TEXT)")
            con.execute("CREATE TABLE IF NOT EXISTS assignments(import_id TEXT,case_id TEXT,selection TEXT,added TEXT,PRIMARY KEY(import_id,case_id,selection))")

    def case_dir(self, case_id):
        target = self.cases / slug(case_id)
        if not target.resolve().is_relative_to(self.cases.resolve()):
            raise ValueError("Case path escapes case storage.")
        return target

    def run_reference(self, case_id, value):
        """A run path in its stored form: relative to the case folder, POSIX separators. Absolute legacy values are normalized."""
        text = str(value or "")
        candidate = Path(text)
        if not text or not candidate.is_absolute():
            return text.replace("\\", "/")
        case_dir = self.case_dir(case_id)
        for base in (case_dir, case_dir.resolve()):
            try:
                return candidate.relative_to(base).as_posix()
            except ValueError:
                continue
        parts = candidate.parts
        if "runs" in parts:
            return "/".join(parts[len(parts) - 1 - parts[::-1].index("runs"):])
        return text

    def resolve_run_path(self, case_id, value):
        """The filesystem path for a stored run path, whether it is relative (current) or absolute (legacy)."""
        reference = self.run_reference(case_id, value)
        if not reference or Path(reference).is_absolute():
            return Path(reference)
        return self.case_dir(case_id) / reference

    def db_path(self, case_id):
        target = self.case_dir(case_id) / "case.sqlite"
        if not target.is_file():
            raise ValueError("Case is not initialized. Create it or adopt the existing case folder first.")
        self._migrate(target)
        return target

    def _migrate(self, database_path):
        if database_path in self.migrated:
            return
        with database(database_path) as con:
            con.execute(AUTHORIZATIONS_DDL)
            con.execute("INSERT OR REPLACE INTO meta VALUES('schema_version',?)", (SCHEMA_VERSION,))
        self.migrated.add(database_path)

    def event(self, con, action, subject, before=None, after=None):
        con.execute("INSERT INTO events VALUES(?,?,?,?,?,?)", (uid(), action, subject, json_text(before), json_text(after), now()))

    def create_case(self, case_id, question, title="", adopt=False):
        case_id = slug(case_id)
        question = required(question, "Case question")
        target = self.case_dir(case_id)
        if target.exists() and not adopt:
            raise ValueError("Case folder already exists. Open the case or explicitly adopt its existing notes.")
        if (target / "case.sqlite").exists():
            raise ValueError("Case already initialized.")
        target.mkdir(parents=True, exist_ok=True)
        with database(target / "case.sqlite") as con:
            con.executescript(SCHEMA)
            values = {"schema_version": SCHEMA_VERSION, "id": case_id, "title": title.strip() or case_id,
                      "question": question, "status": "open", "created": now()}
            con.executemany("INSERT INTO meta VALUES(?,?)", values.items())
            self.event(con, "create_case", case_id, after=values)
        if not (target / "case.md").exists():
            (target / "case.md").write_text(f"# {values['title']}\n\n{question}\n\nPersonal notes. Generated profiles live in exports/.\n", encoding="utf-8")
        return self.summary(case_id)

    def list_cases(self):
        result = []
        for path in sorted(self.cases.iterdir()):
            if not path.is_dir() or path.name.startswith("_"):
                continue
            try:
                if (path / "case.sqlite").is_file():
                    with database(self.db_path(path.name)) as con:
                        info = dict(con.execute("SELECT key,value FROM meta"))
                        info["legacy"] = False
                        result.append(info)
                elif (path / "case.md").exists():
                    result.append({"id": path.name, "title": path.name, "legacy": True, "status": "legacy", "question": "Existing notes; adopt to enable structured case management."})
            except (ValueError, OSError):
                continue
        return result

    def update_case(self, case_id, title=None, question=None, status=None):
        with database(self.db_path(case_id)) as con:
            old = dict(con.execute("SELECT key,value FROM meta"))
            changes = {}
            for key, value in (("title", title), ("question", question), ("status", status)):
                if value is None:
                    continue
                if key == "status" and value not in ("open", "closed"):
                    raise ValueError("Status must be open or closed.")
                changes[key] = required(value, key)
                con.execute("UPDATE meta SET value=? WHERE key=?", (changes[key], key))
            self.event(con, "update_case", case_id, old, changes)
        return self.summary(case_id)

    def _entity(self, con, kind, platform, label, identifier, basis, identity_key=""):
        if kind not in KINDS:
            raise ValueError("Unknown entity kind.")
        label = required(label, "Entity label", 1000)
        platform = str(platform or "").strip().lower()
        identifier = str(identifier or label).strip()
        key = identity_key or json_text([kind, platform, identifier])
        existing = con.execute("SELECT id FROM entities WHERE identity_key=?", (key,)).fetchone()
        if existing:
            return existing[0]
        entity_id = uid()
        con.execute("INSERT INTO entities VALUES(?,?,?,?,?,?,?,?)", (entity_id, kind, platform, label, identifier, key, basis, now()))
        return entity_id

    def add_entity(self, case_id, label, kind="account", platform="", identifier=""):
        with database(self.db_path(case_id)) as con:
            entity_id = self._entity(con, kind, platform, label, identifier, "user_declared")
            self.event(con, "add_entity", entity_id, after={"label": label, "kind": kind})
        return {"id": entity_id}

    def add_note(self, case_id, text, kind="note"):
        if kind not in ("note", "finding", "allegation", "question"):
            raise ValueError("Invalid note kind.")
        note_id = uid()
        with database(self.db_path(case_id)) as con:
            con.execute("INSERT INTO notes VALUES(?,?,?,?)", (note_id, kind, required(text, "Note"), now()))
            self.event(con, "add_note", note_id, after={"kind": kind})
        return {"id": note_id}

    def _relation(self, con, source, target, kind, basis, status, note, since="", until=""):
        if source == target:
            raise ValueError("Select two different entities.")
        if kind not in RELATIONS or status not in STATES:
            raise ValueError("Invalid relationship or review state.")
        for value in (since, until):
            if value:
                date.fromisoformat(value)
        if since and until and since > until:
            raise ValueError("End date precedes start date.")
        for entity in (source, target):
            if not con.execute("SELECT 1 FROM entities WHERE id=?", (entity,)).fetchone():
                raise ValueError("Entity is not in this case.")
        if kind in ("same_entity", "associated_with"):
            source, target = sorted((source, target))
        found = con.execute("SELECT * FROM relations WHERE source=? AND target=? AND kind=? AND basis=?", (source, target, kind, basis)).fetchone()
        if found:
            return found["id"]
        relation_id = uid()
        con.execute("INSERT INTO relations VALUES(?,?,?,?,?,?,?,?,?,?,?)", (relation_id, source, target, kind, basis, status, note, since, until, now(), now()))
        return relation_id

    def add_relation(self, case_id, source, target, kind="associated_with", note="", since="", until=""):
        with database(self.db_path(case_id)) as con:
            relation_id = self._relation(con, source, target, kind, "user_declared", "accepted", str(note), since, until)
            self.event(con, "add_relation", relation_id, after={"source": source, "target": target, "kind": kind, "basis": "user_declared"})
        return {"id": relation_id}

    def review_relation(self, case_id, relation_id, status, reason="", kind=None):
        if status not in STATES or (kind is not None and kind not in RELATIONS):
            raise ValueError("Invalid review state or relation kind.")
        with database(self.db_path(case_id)) as con:
            old = con.execute("SELECT * FROM relations WHERE id=?", (relation_id,)).fetchone()
            if not old:
                raise ValueError("Connection not found.")
            con.execute("UPDATE relations SET status=?,kind=?,updated=? WHERE id=?", (status, kind or old["kind"], now(), relation_id))
            self.event(con, "review_relation", relation_id, dict(old), {"status": status, "kind": kind or old["kind"], "reason": reason})
        return {"id": relation_id, "status": status}

    def review_observation(self, case_id, fingerprint, status, reason=""):
        if status not in ("relevant", "excluded", "unreviewed"):
            raise ValueError("Invalid observation review state.")
        with database(self.db_path(case_id)) as con:
            if not con.execute("SELECT 1 FROM observations WHERE fingerprint=?", (fingerprint,)).fetchone():
                raise ValueError("Observation not found.")
            old = con.execute("SELECT * FROM reviews WHERE fingerprint=?", (fingerprint,)).fetchone()
            con.execute("INSERT OR REPLACE INTO reviews VALUES(?,?,?,?)", (fingerprint, status, str(reason), now()))
            self.event(con, "review_observation", fingerprint, dict(old) if old else None, {"status": status, "reason": reason})
        return {"fingerprint": fingerprint, "status": status}

    def undo(self, case_id, event_id):
        with database(self.db_path(case_id)) as con:
            event = con.execute("SELECT * FROM events WHERE id=?", (event_id,)).fetchone()
            if not event or event["action"] not in ("review_relation", "review_observation"):
                raise ValueError("Only review decisions can be undone; retract a new link by rejecting it.")
            latest = con.execute("SELECT id FROM events WHERE subject=? ORDER BY rowid DESC LIMIT 1", (event["subject"],)).fetchone()
            if latest[0] != event_id:
                raise ValueError("A newer decision exists. Review the current state instead.")
            before = json.loads(event["before_json"])
            if event["action"] == "review_relation":
                con.execute("UPDATE relations SET status=?,kind=?,updated=? WHERE id=?", (before["status"], before["kind"], now(), event["subject"]))
            elif before:
                con.execute("INSERT OR REPLACE INTO reviews VALUES(?,?,?,?)", (before["fingerprint"], before["status"], before["reason"], now()))
            else:
                con.execute("DELETE FROM reviews WHERE fingerprint=?", (event["subject"],))
            self.event(con, "undo", event["subject"], after={"event_id": event_id})
        return {"undone": event_id}

    def preview_bytes(self, data, filename):
        if len(data) > MAX_FILE:
            raise ValueError("Maximum file size is 32 MiB. Select a consolidated report instead of an entire archive.")
        parsed = adapters.inspect(data, filename)
        return {**parsed, "sha256": digest(data), "bytes": len(data), "name": filename}

    def import_path(self, path, case_id=None, targets=None):
        path = Path(path).expanduser().resolve()
        if not path.is_file() or path.stat().st_size > MAX_FILE:
            raise ValueError("Select a file no larger than 32 MiB.")
        return self.import_bytes(path.read_bytes(), path.name, case_id, targets, str(path))

    def import_upload(self, filename, data, case_id=None, targets=None):
        try:
            content = base64.b64decode(data, validate=True)
        except ValueError:
            raise ValueError("Invalid upload encoding.") from None
        return self.import_bytes(content, filename, case_id, targets)

    def import_bytes(self, data, filename, case_id=None, targets=None, origin=""):
        filename = Path(str(filename).replace("\\", "/")).name
        filename = required(filename, "Filename", 240)
        if filename in (".", ".."):
            raise ValueError("Invalid filename.")
        preview = self.preview_bytes(data, filename)
        artifact_id = preview["sha256"][:24]
        # Store as an inert blob; filename remains metadata, never an executable path.
        location = self.inbox / "artifacts" / artifact_id / "source.bin"
        location.parent.mkdir(parents=True, exist_ok=True)
        if not location.exists():
            location.write_bytes(data)
        preview["origin"] = origin
        with database(self.inbox / "inbox.sqlite") as con:
            con.execute("INSERT OR IGNORE INTO imports VALUES(?,?,?,?,?,?,?)", (artifact_id, preview["sha256"], filename, str(location.relative_to(self.inbox)), json_text(preview), now(), "unassigned"))
        result = {"id": artifact_id, "preview": {k: v for k, v in preview.items() if k != "observations"}}
        if case_id:
            result["assignment"] = self.assign_import(artifact_id, case_id, targets)
        return result

    def list_inbox(self):
        with database(self.inbox / "inbox.sqlite") as con:
            items = rows(con, "SELECT * FROM imports ORDER BY added DESC")
            assignments = rows(con, "SELECT * FROM assignments")
        for item in items:
            item["preview"] = json.loads(item["preview"])
            item["preview"].pop("observations", None)
            item["assignments"] = [a for a in assignments if a["import_id"] == item["id"]]
        return items

    def assign_import(self, import_id, case_id, targets=None):
        case_db = self.db_path(case_id)
        with database(self.inbox / "inbox.sqlite") as con:
            record = con.execute("SELECT * FROM imports WHERE id=?", (import_id,)).fetchone()
        if not record:
            raise ValueError("Inbox item not found.")
        preview = json.loads(record["preview"])
        data = (self.inbox / record["path"]).read_bytes()
        if digest(data) != record["sha256"]:
            raise ValueError("Inbox evidence hash does not match its record.")
        case_dir = self.case_dir(case_id)
        location = case_dir / "imports" / import_id / "source.bin"
        location.parent.mkdir(parents=True, exist_ok=True)
        if not location.exists():
            location.write_bytes(data)
        if digest(location.read_bytes()) != record["sha256"]:
            raise ValueError("Case evidence has changed; refusing to replace it.")
        if targets is not None and not isinstance(targets, list):
            raise ValueError("Target selection must be a list.")
        selected = [o for o in preview["observations"] if targets is None or o["query"] in targets]
        if targets is not None and not selected:
            raise ValueError("No report records match the selected targets.")
        count = 0
        with database(case_db) as con:
            meta = {k: v for k, v in preview.items() if k != "observations"}
            con.execute("INSERT OR IGNORE INTO artifacts VALUES(?,?,?,?,?,?,?)", (import_id, record["sha256"], record["name"], str(location.relative_to(case_dir)), preview["adapter"], json_text(meta), now()))
            for obs in selected:
                entity_id = None
                url = url_key(obs["url"])
                if obs["status"] in ("hit", "metadata"):
                    # Registration hits with no account URL remain site-scoped observations.
                    identity = "url:" + url if url else json_text([obs["identifier_kind"], obs["site"].casefold(), obs["query"]])
                    entity_id = self._entity(con, "phone" if obs["identifier_kind"] == "phone" else "account", obs["site"], obs["query"], url or obs["query"], "scanner_reported", identity)
                fingerprint = digest(json_text({k: obs[k] for k in ("tool", "query", "site", "status", "url", "extra")}).encode())
                cur = con.execute("INSERT OR IGNORE INTO observations VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (uid(), import_id, obs["selector"], obs["tool"], obs["query"], obs["identifier_kind"], obs["site"], obs["url"], obs["status"], obs["reported_status"], json_text(obs["extra"]), entity_id, fingerprint, now()))
                count += cur.rowcount
            self._suggest(con)
            self.event(con, "import", import_id, after={"added_observations": count, "targets": targets, "issues": preview["issues"]})
        with database(self.inbox / "inbox.sqlite") as con:
            con.execute("INSERT OR IGNORE INTO assignments VALUES(?,?,?,?)", (import_id, slug(case_id), json_text(targets), now()))
            con.execute("UPDATE imports SET state='assigned' WHERE id=?", (import_id,))
        return {"case_id": case_id, "artifact_id": import_id, "added_observations": count, "issues": preview["issues"]}

    def _suggest(self, con):
        # Exact reported handle reuse is a candidate, never automatic common ownership.
        entities = rows(con, "SELECT * FROM entities WHERE kind='account'")
        buckets = {}
        for item in entities:
            buckets.setdefault(item["label"], []).append(item)
        for group in buckets.values():
            if len(group) > 60:
                continue  # avoid an unhelpful complete graph; source observations remain available
            for i, a in enumerate(group):
                for b in group[i+1:]:
                    relation = self._relation(con, a["id"], b["id"], "same_entity", "rule_suggested", "proposed", "Exact reported identifier reuse; common ownership is unverified. Rule handle-equality-v1.")
                    for observation in rows(con, "SELECT artifact_id,selector FROM observations WHERE entity_id IN (?,?)", (a["id"], b["id"])):
                        con.execute("INSERT OR IGNORE INTO evidence VALUES(?,?,?,?,?,?,?)", (uid(), relation, observation["artifact_id"], "context", observation["selector"], "Reported identifier; not proof of common ownership.", now()))
        # Only recognize URLs explicitly exposed in supported extra fields, without fetching.
        for obs in rows(con, "SELECT * FROM observations WHERE entity_id IS NOT NULL"):
            extra = json.loads(obs["extra"])
            def walk(value):
                if isinstance(value, str):
                    for match in re.findall(r'https?://[^\s<>"\[\],;]+', value):
                        yield match.rstrip(".)")
                elif isinstance(value, dict):
                    for v in value.values():
                        yield from walk(v)
                elif isinstance(value, list):
                    for v in value:
                        yield from walk(v)
            link_data = {k: extra[k] for k in ("ids_links", "extra", "ids") if k in extra}
            for link in set(walk(link_data)):
                canonical = url_key(link)
                target = con.execute("SELECT id FROM entities WHERE identity_key=?", ("url:" + canonical,)).fetchone()
                if target and target[0] != obs["entity_id"]:
                    rid = self._relation(con, obs["entity_id"], target[0], "links_to", "source_observed", "proposed", "URL mentioned in scanner-extracted data; inspect source context.")
                    con.execute("INSERT OR IGNORE INTO evidence VALUES(?,?,?,?,?,?,?)", (uid(), rid, obs["artifact_id"], "supports", obs["selector"], "Extracted URL: " + canonical, now()))

    def attach_evidence(self, case_id, relation_id, artifact_id, role="supports", selector="", note=""):
        if role not in ("supports", "contradicts", "context"):
            raise ValueError("Invalid evidence role.")
        with database(self.db_path(case_id)) as con:
            for table, key in (("relations", relation_id), ("artifacts", artifact_id)):
                if not con.execute(f"SELECT 1 FROM {table} WHERE id=?", (key,)).fetchone():
                    raise ValueError("Claim and evidence must both belong to this case.")
            evidence_id = uid()
            con.execute("INSERT OR IGNORE INTO evidence VALUES(?,?,?,?,?,?,?)", (evidence_id, relation_id, artifact_id, role, str(selector), str(note), now()))
            self.event(con, "attach_evidence", relation_id, after={"artifact_id": artifact_id, "role": role, "selector": selector, "note": note})
        return {"relation_id": relation_id}

    def remove_evidence(self, case_id, evidence_id):
        with database(self.db_path(case_id)) as con:
            old = con.execute("SELECT * FROM evidence WHERE id=?", (evidence_id,)).fetchone()
            if not old:
                raise ValueError("Evidence association not found.")
            con.execute("DELETE FROM evidence WHERE id=?", (evidence_id,))
            self.event(con, "remove_evidence", old["relation_id"], dict(old), None)
        return {"removed": evidence_id}

    def artifact(self, case_id, artifact_id):
        with database(self.db_path(case_id)) as con:
            row = con.execute("SELECT * FROM artifacts WHERE id=?", (artifact_id,)).fetchone()
        if not row:
            raise ValueError("Evidence not found.")
        root = self.case_dir(case_id).resolve()
        path = (root / row["path"]).resolve()
        if not path.is_relative_to(root) or not path.is_file():
            raise ValueError("Evidence file is missing or outside the case.")
        if digest(path.read_bytes()) != row["sha256"]:
            raise ValueError("Evidence integrity check failed.")
        return dict(row), path

    def summary(self, case_id, as_of=None):
        as_of = as_of or date.today().isoformat()
        date.fromisoformat(as_of)
        with database(self.db_path(case_id)) as con:
            for job in rows(con, "SELECT * FROM jobs WHERE state='running'"):
                pid = json.loads(job["plan"]).get("supervisor_pid")
                if pid and not process_alive(pid):
                    con.execute("UPDATE jobs SET state='interrupted',ended=?,message=? WHERE id=?", (now(), "The supervising profiler process exited. Check saved outputs and Docker state before retrying.", job["id"]))
            meta = dict(con.execute("SELECT key,value FROM meta"))
            entities = rows(con, "SELECT * FROM entities ORDER BY added,id")
            relations = rows(con, "SELECT * FROM relations ORDER BY added,id")
            observations = rows(con, "SELECT o.*,COALESCE(r.status,'unreviewed') review_status,COALESCE(r.reason,'') review_reason FROM observations o LEFT JOIN reviews r ON o.fingerprint=r.fingerprint ORDER BY o.added DESC,o.id")
            artifacts = rows(con, "SELECT * FROM artifacts ORDER BY added DESC")
            evidence = rows(con, "SELECT * FROM evidence ORDER BY added")
            notes = rows(con, "SELECT * FROM notes ORDER BY added DESC")
            events = rows(con, "SELECT * FROM events ORDER BY rowid DESC LIMIT 200")
            jobs = rows(con, "SELECT * FROM jobs ORDER BY started DESC LIMIT 100")
        for artifact in artifacts:
            artifact["metadata"] = json.loads(artifact["metadata"])
        unique = {}
        for obs in observations:
            obs["extra"] = json.loads(obs["extra"])
            obs["source"] = {"artifact_id": obs["artifact_id"], "selector": obs["selector"]}
            if obs["fingerprint"] not in unique:
                obs["sources"] = []
                unique[obs["fingerprint"]] = obs
            unique[obs["fingerprint"]]["sources"].append(obs["source"])
        for relation in relations:
            relation["evidence"] = [e for e in evidence if e["relation_id"] == relation["id"]]
            relation["has_contradiction"] = any(e["role"] == "contradicts" for e in relation["evidence"])
            relation["active_at_date"] = (not relation["since"] or relation["since"] <= as_of) and (not relation["until"] or relation["until"] >= as_of)
        parents = {e["id"]: e["id"] for e in entities}
        def find(x):
            while parents[x] != x:
                x = parents[x]
            return x
        for relation in relations:
            if relation["kind"] == "same_entity" and relation["status"] == "accepted" and relation["active_at_date"]:
                parents[find(relation["source"])] = find(relation["target"])
        groups = {}
        for entity in entities:
            groups.setdefault(find(entity["id"]), []).append(entity["id"])
        for event in events:
            event["before"] = json.loads(event.pop("before_json"))
            event["after"] = json.loads(event.pop("after_json"))
        for job in jobs:
            job["plan"] = json.loads(job["plan"])
            job["path"] = self.run_reference(case_id, job["path"])
            if isinstance(job["plan"].get("output"), str):
                job["plan"]["output"] = self.run_reference(case_id, job["plan"]["output"])
        items = list(unique.values())
        return {"case": meta, "as_of": as_of, "entities": entities, "groups": list(groups.values()), "relations": relations,
                "observations": items, "artifacts": artifacts, "notes": notes, "events": events, "jobs": jobs,
                "counts": {"entities": len(entities), "observations": len(items), "raw_observations": len(observations),
                    "artifacts": len(artifacts), "review": sum(r["status"] == "proposed" for r in relations),
                    "contradictions": sum(r["has_contradiction"] for r in relations),
                    "statuses": dict(Counter(o["status"] for o in items)), "excluded": sum(o["review_status"] == "excluded" for o in items)}}

    def discover(self):
        found = []
        for lane in ("maigret", "scanner", "phone"):
            folder = self.root / lane
            if folder.exists():
                for path in sorted(folder.iterdir()):
                    if path.is_file() and path.suffix.lower() in (".json", ".csv", ".md", ".html"):
                        found.append({"path": str(path), "name": path.name, "lane": lane, "bytes": path.stat().st_size})
        return found

    def export(self, case_id):
        from .reports import export_case
        return export_case(self, case_id)
