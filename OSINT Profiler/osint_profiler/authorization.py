"""Per-case subject-authorization attestation: an append-only ledger plus a derived sidecar.

An accountability record, not a security boundary: code that bypasses the profiler and
the PowerShell runners is not stopped by it.
"""
from __future__ import annotations
import getpass
import hashlib
import json
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from .util import database, json_text, now, required, uid

ACKNOWLEDGEMENT_PATH = Path(__file__).with_name("ACKNOWLEDGEMENT.txt")
REQUIRED_PHRASE = "I AUTHORIZE THIS CASE AND ACCEPT RESPONSIBILITY FOR LAWFUL USE"
VALIDITY_DAYS = 180
BANNER = "People-focused OSINT. Authorized, lawful use only. See LEGAL-USE.md."
PURPOSES = ("fraud-investigation", "due-diligence", "journalism", "security-research", "legal-process", "missing-person", "self-or-consented-check", "other")
LEGAL_BASES = ("consent", "legitimate-interest", "contract", "legal-obligation", "vital-interest", "public-task", "other")
FAILURE_REASONS = ("missing", "expired", "revoked", "stale-ack")
ACK_FILE_FIELDS = ("subject_label", "purpose", "purpose_note", "legal_basis", "basis_note", "jurisdiction", "acknowledge")

AUTHORIZATIONS_DDL = ("CREATE TABLE IF NOT EXISTS authorizations(id TEXT PRIMARY KEY,case_id TEXT NOT NULL,subject_label TEXT NOT NULL,purpose TEXT NOT NULL,"
                      "purpose_note TEXT NOT NULL,legal_basis TEXT NOT NULL,basis_note TEXT NOT NULL,jurisdiction TEXT NOT NULL,ack_version_hash TEXT NOT NULL,"
                      "ack_phrase_sha256 TEXT NOT NULL,operator TEXT NOT NULL,ts TEXT NOT NULL,expires_ts TEXT NOT NULL,revoked_ts TEXT,revoke_reason TEXT)")

_IDENTIFIER_SHAPES = (re.compile(r"^\+?\d{7,15}$"), re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$"), re.compile(r"^@\w+"))


class AuthorizationRequired(ValueError):
    def __init__(self, case_id, reason):
        self.case_id = case_id
        self.reason = reason
        self.next_step = f"osint-case authorize {case_id}"
        self.detail = {"missing": "No subject-authorization attestation is recorded for this case.",
                       "expired": "The subject-authorization attestation for this case has expired.",
                       "revoked": "The subject-authorization attestation for this case was revoked.",
                       "stale-ack": "The acknowledgement text changed since this case was attested."}[reason]
        super().__init__(f"{self.detail} Run: {self.next_step}")

    def payload(self):
        return {"error": "subject-authorization-required", "case_id": self.case_id, "reason": self.reason, "next": self.next_step, "message": str(self)}


def acknowledgement_text():
    return ACKNOWLEDGEMENT_PATH.read_text(encoding="utf-8").strip()


def acknowledgement_hash():
    return hashlib.sha256(ACKNOWLEDGEMENT_PATH.read_bytes()).hexdigest()


def _utc_now():
    return datetime.now(timezone.utc)


def validate_subject_label(value):
    label = required(value, "Subject label", 80)
    compact = re.sub(r"[\s().-]", "", label)
    if any(shape.match(candidate) for shape in _IDENTIFIER_SHAPES for candidate in (label, compact)):
        raise ValueError("Subject label must be an alias such as 'Subject A', not a phone number, email, or handle. Identifiers are never stored here.")
    return label


def _validated_choice(value, allowed, name, note, note_name):
    if value not in allowed:
        raise ValueError(f"{name} must be one of: {', '.join(allowed)}.")
    note = str(note or "").strip()
    if value == "other" and not note:
        raise ValueError(f"{note_name} is required when {name.lower()} is 'other'.")
    if len(note) > 1000:
        raise ValueError(f"{note_name} is limited to 1000 characters.")
    return note


def _latest_row(con, case_id):
    row = con.execute("SELECT * FROM authorizations WHERE case_id=? ORDER BY ts DESC, rowid DESC LIMIT 1", (case_id,)).fetchone()
    return dict(row) if row else None


def current_authorization(store, case_id):
    with database(store.db_path(case_id)) as con:
        return _latest_row(con, case_id)


def _failure_reason(record):
    if record is None:
        return "missing"
    if record["revoked_ts"]:
        return "revoked"
    if datetime.fromisoformat(record["expires_ts"]) <= _utc_now():
        return "expired"
    if record["ack_version_hash"] != acknowledgement_hash():
        return "stale-ack"
    return None


def authorization_status(store, case_id):
    """Read-only: never writes an event."""
    with database(store.db_path(case_id)) as con:
        record = _latest_row(con, case_id)
        reason = _failure_reason(record)
        first_use = bool(record) and not reason and con.execute(
            "SELECT 1 FROM events WHERE action='authorization_check' AND subject=? AND after_json LIKE '%\"outcome\": \"pass\"%' LIMIT 1", (record["id"],)).fetchone() is None
    return {"status": reason or "valid", "attestation_id": record["id"] if record else None,
            "expires_ts": record["expires_ts"] if record else None, "first_use": first_use}


def write_sidecar(case_dir, record):
    revoked = bool(record.get("revoked_ts"))
    sidecar = {"attestation_id": record["id"], "case_id": record["case_id"], "ack_version_hash": record["ack_version_hash"],
               "expires_ts": record["expires_ts"], "revoked": revoked, "subject_label": record["subject_label"]}
    target = Path(case_dir) / "authorization.json"
    temporary = target.with_suffix(".tmp")
    temporary.write_text(json_text(sidecar), encoding="utf-8")
    os.replace(temporary, target)


def record_authorization(store, case_id, subject_label, purpose, legal_basis, jurisdiction, acknowledgement, purpose_note="", basis_note=""):
    label = validate_subject_label(subject_label)
    purpose_note = _validated_choice(purpose, PURPOSES, "Purpose", purpose_note, "Purpose note")
    basis_note = _validated_choice(legal_basis, LEGAL_BASES, "Legal basis", basis_note, "Basis note")
    jurisdiction = required(jurisdiction, "Jurisdiction", 80)
    if acknowledgement != REQUIRED_PHRASE:
        raise ValueError("The typed acknowledgement phrase did not match exactly. Nothing was recorded.")
    issued = _utc_now().replace(microsecond=0)
    record = {"id": uid(), "case_id": case_id, "subject_label": label, "purpose": purpose, "purpose_note": purpose_note, "legal_basis": legal_basis,
              "basis_note": basis_note, "jurisdiction": jurisdiction, "ack_version_hash": acknowledgement_hash(),
              "ack_phrase_sha256": hashlib.sha256(REQUIRED_PHRASE.encode("utf-8")).hexdigest(), "operator": getpass.getuser(),
              "ts": issued.isoformat(), "expires_ts": (issued + timedelta(days=VALIDITY_DAYS)).isoformat(), "revoked_ts": None, "revoke_reason": None}
    with database(store.db_path(case_id)) as con:
        con.execute("INSERT INTO authorizations VALUES(:id,:case_id,:subject_label,:purpose,:purpose_note,:legal_basis,:basis_note,:jurisdiction,"
                    ":ack_version_hash,:ack_phrase_sha256,:operator,:ts,:expires_ts,:revoked_ts,:revoke_reason)", record)
        store.event(con, "authorization_recorded", record["id"], after={k: record[k] for k in ("subject_label", "purpose", "legal_basis", "jurisdiction", "expires_ts", "operator")})
    write_sidecar(store.case_dir(case_id), record)
    return record


def revoke_authorization(store, case_id, reason=""):
    with database(store.db_path(case_id)) as con:
        record = _latest_row(con, case_id)
        if record is None or record["revoked_ts"]:
            raise ValueError("This case has no active authorization to revoke.")
        record["revoked_ts"], record["revoke_reason"] = now(), str(reason or "").strip()[:1000]
        con.execute("UPDATE authorizations SET revoked_ts=?,revoke_reason=? WHERE id=?", (record["revoked_ts"], record["revoke_reason"], record["id"]))
        store.event(con, "authorization_revoked", record["id"], after={"revoked_ts": record["revoked_ts"], "reason": record["revoke_reason"]})
    write_sidecar(store.case_dir(case_id), record)
    return record


def require_authorization(store, case_id, action):
    with database(store.db_path(case_id)) as con:
        record = _latest_row(con, case_id)
        reason = _failure_reason(record)
        store.event(con, "authorization_check", record["id"] if record else case_id,
                    after={"action": action, "outcome": "pass" if reason is None else reason, "attestation_id": record["id"] if record else None})
    if reason:
        raise AuthorizationRequired(case_id, reason)
    return record


def load_ack_file(path):
    data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(data, dict) or set(data) - set(ACK_FILE_FIELDS):
        raise ValueError("Acknowledgement file must be a JSON object with only: " + ", ".join(ACK_FILE_FIELDS) + ".")
    data = dict(data)
    data["acknowledgement"] = data.pop("acknowledge", "")
    return data
