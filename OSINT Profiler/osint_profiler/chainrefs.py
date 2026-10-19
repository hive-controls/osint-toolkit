"""Chain reference syntax: ${<ns>.<path>[<filter>]<terminal><pipe>} parsed by ONE anchored regex, never evaluated."""
from __future__ import annotations
import re
from dataclasses import dataclass

REFERENCE = re.compile(
    r"\$\{(?:steps\.(?P<step>[a-z0-9][a-z0-9_-]{0,62})|(?P<case>case))"
    r"\.(?P<path>entities|inputs|artifacts)"
    r"(?:\[kind=(?P<kind>[a-z][a-z0-9_-]*(?:\.[a-z0-9_]+)?)\])?"
    r"\.(?P<terminal>value|attrs\.(?P<attribute>[A-Za-z0-9_]+))"
    r"(?:\|(?P<pipe>first|only))?\}"
)
NEXT_STEPS = {
    "spec-invalid": "Fix the chain spec; see the Chains section of OSINT Profiler/README.md.",
    "ambiguous-input": "Add |first or |only, or narrow the selection with [kind=...].",
    "empty-reference": "Check the earlier step produced the referenced value, or use a literal input.",
    "derived-input-refused": "Review the derived value, then set derived_ok: true on that step to accept it.",
}


class ChainError(ValueError):
    def __init__(self, code, message, next_step=None):
        super().__init__(message)
        self.code = code
        self.next_step = next_step or NEXT_STEPS.get(code, "Run: osint-case chain show <chain-id> --json")

    def payload(self):
        return {"error": self.code, "message": str(self), "next": self.next_step}


@dataclass(frozen=True)
class Reference:
    text: str
    namespace: str
    step: str | None
    path: str
    kind: str | None
    terminal: str
    attribute: str | None
    pipe: str | None


def parse_input(text):
    """None for a literal; a Reference for a whole-string reference; spec-invalid for anything else containing '${'."""
    if not isinstance(text, str):
        raise ChainError("spec-invalid", "Chain inputs must be strings.")
    if "${" not in text:
        return None
    match = REFERENCE.fullmatch(text)
    if not match:
        raise ChainError("spec-invalid", f"Unsupported reference syntax: {text!r}. Allowed: ${{steps.<id>|case.<entities|inputs|artifacts>[kind=<name>].<value|attrs.<key>>[|first|only]}}.")
    return Reference(text, "case" if match["case"] else "steps", match["step"], match["path"], match["kind"],
                     "attrs" if match["attribute"] else "value", match["attribute"], match["pipe"])


def _terminal_values(reference, candidates):
    items = [item for item in candidates if reference.kind is None or item["kind"] == reference.kind]
    if reference.terminal == "value":
        return items
    selected = []
    for item in items:
        attribute = item["attrs"].get(reference.attribute)
        if attribute not in (None, ""):
            selected.append({**item, "value": str(attribute)})
    return selected


def _listing(items):
    shown = ", ".join(repr(item["value"]) for item in items[:10])
    return shown + (f" (+{len(items) - 10} more)" if len(items) > 10 else "")


def select_one(reference, candidates):
    items = _terminal_values(reference, candidates)
    if not items:
        raise ChainError("empty-reference", f"{reference.text} selected nothing.")
    if reference.pipe == "first" or len(items) == 1:
        return items[0]
    raise ChainError("ambiguous-input", f"{reference.text} selected {len(items)} values; a scalar input needs exactly one. Candidates: {_listing(items)}.")
