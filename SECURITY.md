# Security Policy

## Reporting a vulnerability

Use GitHub private vulnerability reporting: open the repository's **Security** tab and choose
**Report a vulnerability**. This opens a private advisory visible only to the maintainers.

Do not open a public issue for a vulnerability. Do not include case data, subject identifiers,
credentials, or real API keys in a report; use synthetic values and the smallest reproduction you can.

## Supported versions

Only `main` is supported. Fixes land on `main`; there are no backports.

## Disclosure

Coordinated disclosure with a 90-day window from the first report. We aim to acknowledge a report
promptly, agree a fix timeline in the advisory, and credit the reporter unless asked not to.

## In scope

- Gate bypasses: any path to collection that skips the network probe, the typed `RUN`
  confirmation, or the subject-authorization check (that is, any route that avoids the exit 75, 77
  or 78 refusals).
- Ledger or sidecar tampering that the launchers fail to detect.
- Key and secret leaks: `secrets.json` contents or API keys appearing in logs, transcripts, saved
  reports, or redirects.
- Container hardening regressions: dropped capabilities, read-only root filesystem, egress that
  does not go through the proxy sidecar, or DNS leaving the sidecar in routed mode.
- Supply-chain pin regressions: hash locks, wheel fetching, and source-distribution builds.

## Out of scope

- Provider terms-of-service disputes. Compliance with a provider's terms is the operator's
  responsibility; see [PROVIDERS.md](Phone%20Lookup/PROVIDERS.md).
- Bugs in upstream tools; report those to the upstream project.
- Misuse of the toolkit. See [LEGAL-USE.md](LEGAL-USE.md) for permitted use.
- Findings that require a malicious local administrator. The authorization attestation is an
  accountability record, not a security boundary; see [LEGAL-USE.md](LEGAL-USE.md).
