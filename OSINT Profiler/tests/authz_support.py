import json
from osint_profiler.authorization import REQUIRED_PHRASE, record_authorization

FIXTURE_FIELDS = {
    "subject_label": "Subject A",
    "purpose": "security-research",
    "legal_basis": "legitimate-interest",
    "jurisdiction": "US-CA",
}


def authorize_case(store, case_id, **overrides):
    fields = {**FIXTURE_FIELDS, "acknowledgement": REQUIRED_PHRASE, **overrides}
    return record_authorization(store, case_id, **fields)


def legacy_json(text):
    """The pre-envelope payload of a --json run: data on success or partial results, else the deprecated legacy_error object."""
    envelope = json.loads(text)
    return envelope["data"] if envelope["data"] is not None else envelope["legacy_error"]
