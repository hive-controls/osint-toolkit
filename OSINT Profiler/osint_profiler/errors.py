"""One table mapping stable error codes to process exit codes, plus the typed exceptions the library API raises."""
from __future__ import annotations
import re

EXIT_CODES = {
    "usage": 2, "spec-invalid": 2, "ambiguous-input": 2, "empty-reference": 2, "derived-input-refused": 2, "tool-not-chainable": 2,
    "input-kind-mismatch": 2, "input-invalid": 2, "input-changed": 2, "result-changed": 2, "unknown-chain": 2, "ambiguous-chain": 2,
    "chain-exists": 2, "chain-busy": 2, "state-unreadable": 2, "upstream-failed": 2,
    "not-found": 1, "failed": 1, "hop-failed": 1, "timeout": 1,
    "runner-usage": 64, "network-gate": 75, "subject-authorization-required": 77, "config-provider": 78, "interrupted": 130,
}
EXIT_TO_CODE = {1: "failed", 2: "usage", 64: "runner-usage", 75: "network-gate", 77: "subject-authorization-required", 78: "config-provider", 130: "interrupted"}
GATE_MESSAGES = {
    "network-gate": "Network gate refused the run (no allowlisted VPN carrying internet traffic).",
    "subject-authorization-required": "Subject authorization refused the run (record one with: osint-case authorize <case>).",
    "config-provider": "Network gate or provider configuration error.",
    "interrupted": "The run was cancelled; completed outputs were retained.",
}
NOT_FOUND = re.compile(r"not found|not initialized|does not exist|no such", re.IGNORECASE)
DEFAULT_NEXT = {
    "usage": "Run: osint-case --help",
    "not-found": "Run: osint-case list --json",
    "failed": "Check the message, then retry.",
    "network-gate": "Connect an allowlisted VPN, then retry.",
    "config-provider": "Fix the gate or provider configuration, then retry.",
    "interrupted": "Re-run the command; completed outputs were retained.",
}


def exit_code_for(code):
    return EXIT_CODES.get(code, 1)


def code_for_exit(exit_code):
    return EXIT_TO_CODE.get(exit_code, "failed")


class ProfilerError(ValueError):
    code = "failed"

    def __init__(self, message, next_step=None):
        super().__init__(message)
        self.next_step = next_step or DEFAULT_NEXT.get(self.code, DEFAULT_NEXT["failed"])

    def payload(self):
        return {"error": self.code, "message": str(self), "next": self.next_step}


class UsageError(ProfilerError):
    code = "usage"


class NotFoundError(ProfilerError):
    code = "not-found"


class NetworkGateError(ProfilerError):
    code = "network-gate"


class ConfigProviderError(ProfilerError):
    code = "config-provider"


class InterruptedRun(ProfilerError):
    code = "interrupted"


def describe(exc):
    """(code, message, next, details) for any exception the CLI or API can surface."""
    message = str(exc)
    if hasattr(exc, "payload"):
        payload = dict(exc.payload())
        code = payload.pop("error")
        payload.pop("message", None)
        following = payload.pop("next", None) or DEFAULT_NEXT.get(code, DEFAULT_NEXT["failed"])
        return code, message, following, payload
    if isinstance(exc, KeyboardInterrupt):
        return "interrupted", "Cancelled. Saved case data remains available.", DEFAULT_NEXT["interrupted"], {}
    code = "not-found" if NOT_FOUND.search(message) else "failed"
    return code, message, DEFAULT_NEXT[code], {}
