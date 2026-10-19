"""Terminal flows for recording, showing and revoking a case's subject-authorization attestation."""
from __future__ import annotations
import sys
from .authorization import (BANNER, LEGAL_BASES, PURPOSES, REQUIRED_PHRASE, AuthorizationRequired, acknowledgement_text,
                            authorization_status, current_authorization, load_ack_file, record_authorization, require_authorization, revoke_authorization)
from .terminal import ask, collect, selection, text_field
from .errors import UsageError
from .util import clean


def print_banner():
    print(BANNER, file=sys.stderr)


def interactive_authorize(store, case_id):
    print_banner()
    print("\n" + clean(acknowledgement_text()) + "\n")
    note_step = lambda choice, note, label: (note, lambda v: ask(f"{label} note (required for 'other')") if v[choice] == "other" else "")
    values = collect([
        text_field("subject_label", "Subject alias, e.g. 'Subject A' (never a name, number, email or handle)"),
        selection("purpose", "Purpose", list(PURPOSES)), note_step("purpose", "purpose_note", "Purpose"),
        selection("legal_basis", "Legal basis", list(LEGAL_BASES)), note_step("legal_basis", "basis_note", "Legal basis"),
        text_field("jurisdiction", "Jurisdiction, e.g. US-CA or EU-DE"),
        text_field("acknowledgement", "Type exactly: " + REQUIRED_PHRASE)])
    return record_authorization(store, case_id, **values)


def flag_fields(args):
    fields = {"subject_label": args.subject_label, "purpose": args.purpose, "purpose_note": args.purpose_note or "", "legal_basis": args.legal_basis,
              "basis_note": args.basis_note or "", "jurisdiction": args.jurisdiction, "acknowledgement": args.acknowledge}
    missing = [name for name in ("subject_label", "purpose", "legal_basis", "jurisdiction", "acknowledgement") if fields[name] is None]
    if missing:
        raise UsageError("Missing: " + ", ".join(missing) + ". Provide all flags, or --ack-file, or run interactively without flags.")
    return fields


def show_authorization(store, case_id):
    status = authorization_status(store, case_id)
    record = current_authorization(store, case_id) or {}
    detail = {key: record.get(key) for key in ("subject_label", "purpose", "legal_basis", "jurisdiction", "operator", "ts", "revoked_ts", "revoke_reason")}
    return {"case_id": case_id, "status": status["status"], "attestation_id": status["attestation_id"], "expires_ts": status["expires_ts"], **detail}


def run_authorize(store, args):
    store.db_path(args.case_id)
    if args.show:
        return show_authorization(store, args.case_id)
    if args.revoke:
        record = revoke_authorization(store, args.case_id, args.reason or "")
        return {"case_id": args.case_id, "attestation_id": record["id"], "revoked_ts": record["revoked_ts"]}
    flags_given = any(getattr(args, name) is not None for name in ("subject_label", "purpose", "legal_basis", "jurisdiction", "acknowledge"))
    if args.ack_file or flags_given:
        fields = load_ack_file(args.ack_file) if args.ack_file else flag_fields(args)
        record = record_authorization(store, args.case_id, **fields)
        print_banner()
    else:
        if not getattr(args, "interactive", True):
            raise UsageError("authorize needs --subject-label, --purpose, --legal-basis, --jurisdiction and --acknowledge (or --ack-file) when not interactive.")
        record = interactive_authorize(store, args.case_id)
    return {"case_id": args.case_id, "attestation_id": record["id"], "subject_label": record["subject_label"], "expires_ts": record["expires_ts"]}


def ensure_scan_authorization(store, case_id, interactive=None):
    status = authorization_status(store, case_id)
    if interactive is None:
        interactive = sys.stdin.isatty()
    if status["status"] == "missing" and interactive:
        print("No subject-authorization attestation is recorded for this case yet.", file=sys.stderr)
        interactive_authorize(store, case_id)
        status = authorization_status(store, case_id)
    if status["status"] != "valid":
        require_authorization(store, case_id, "scan")
        raise AuthorizationRequired(case_id, status["status"])
    if status["first_use"]:
        print_banner()
