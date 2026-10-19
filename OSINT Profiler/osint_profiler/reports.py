import html
import json
from .util import now

def export_case(store, case_id):
    data = store.summary(case_id)
    folder = store.case_dir(case_id) / "exports"
    folder.mkdir(exist_ok=True)
    labels = {e["id"]: f"{e['label']} ({e['platform'] or e['kind']})" for e in data["entities"]}
    lines = [f"# {data['case']['title']}", "", data["case"]["question"], "", f"Generated {now()}. Identity group view as of {data['as_of']}.",
             "", "## Findings and notes", ""]
    for n in data["notes"]:
        lines.append(f"- [{n['kind']}; user-declared] {n['text']}")
    lines += ["", "## Connections", ""]
    for r in data["relations"]:
        if r["status"] == "rejected":
            continue
        lines.append(f"- {labels[r['source']]} — {r['kind']} — {labels[r['target']]} [{r['basis']}; {r['status']}; {r['since'] or 'unknown start'} to {r['until'] or 'unknown end'}]")
        lines.append(f"  {r['note']}")
        for e in r["evidence"]:
            lines.append(f"  Evidence {e['artifact_id']} at {e['selector'] or 'whole artifact'} ({e['role']}): {e['note']}")
    lines += ["", "## Collection and evidence", "", "Scanner results are observations; common ownership requires a declared or reviewed connection.", ""]
    for a in data["artifacts"]:
        lines.append(f"- {a['id']}: {a['name']} — SHA256 {a['sha256']} — ../{a['path'].replace(chr(92), '/')}")
    text = "\n".join(lines) + "\n"
    (folder / "profile.md").write_text(text, encoding="utf-8")
    (folder / "profile.json").write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    (folder / "profile.html").write_text('<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'"><title>Case profile</title><style>body{max-width:1000px;margin:40px auto;padding:24px;background:#f3f5f2;color:#18332d;font:16px system-ui}pre{white-space:pre-wrap;overflow-wrap:anywhere;font:inherit}</style><h1>Case profile · read-only snapshot</h1><pre>' + html.escape(text) + '</pre></html>', encoding="utf-8")
    return {"directory": str(folder), "markdown": str(folder / "profile.md"), "json": str(folder / "profile.json"), "html": str(folder / "profile.html")}
