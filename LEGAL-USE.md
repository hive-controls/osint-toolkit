# Legal use

This toolkit does people-focused OSINT: username, phone, email and onion lookups, organized into per-case workspaces. It is for lawful, authorized use only. This page says what that means and what the toolkit does (and does not do) to hold you to it. It is not legal advice.

## Permitted use

Use the tools only for a lawful purpose that you can state and defend, with a recorded per-case authorization. Examples: security research, fraud or abuse investigation, due diligence on a consenting party, verifying your own exposure.

## Prohibited use

- Stalking, harassment, intimidation or doxxing of any person.
- Surveillance of a current or former intimate partner.
- Employment, credit, insurance or housing decisions without a lawful basis for that decision.
- Any use that violates applicable law, or the terms of a site or data provider you query.

## The three gates

The launchers refuse to run until each applicable gate passes. There is no bypass flag.

| Exit | Gate | What it means |
|---|---|---|
| 75 | Network | The host route to the internet must leave through an allowlisted VPN adapter (or a verified routed proxy). |
| 77 | Subject authorization | The case needs a current attestation. Missing, expired, revoked or stale (acknowledgement text changed) all refuse. |
| 78 | Configuration / provider | A required setting is wrong or missing, for example an enabled provider with no key or a stale terms acknowledgement. |

Phrases the operator types exactly (case-sensitive; a mismatch records nothing):

- Case attestation (`osint-case authorize <case-id>`): `I AUTHORIZE THIS CASE AND ACCEPT RESPONSIBILITY FOR LAWFUL USE`
- Provider opt-in (`--enable <provider> --acknowledge-terms "..."`): `I HAVE READ THE <PROVIDER> TERMS AND ACCEPT RESPONSIBILITY FOR MY QUERIES` (provider id upper-cased, for example `HUDSON_ROCK`)

Third-party data providers are off by default. A key alone never enables one. Read the shipped terms text in `Phone Lookup/PROVIDER-TERMS/` before acknowledging; editing that text makes earlier acknowledgements stale.

## What is recorded, and where

- Case ledger (`case.sqlite` in the case folder): an `authorizations` table plus case events (`authorization_recorded`, `authorization_revoked`, `authorization_check`). It holds a subject alias, purpose, legal basis, jurisdiction, operating-system user, timestamp, and hashes of the acknowledgement text and typed phrase. A derived `authorization.json` sidecar sits beside it.
- `gate-events.jsonl`: network gate decisions, in the gate's per-user config directory on the operator's machine.
- `providers.json`: which providers are enabled and which terms version, operator and time acknowledged each one, beside the local `secrets.json`.

Not recorded: the subject identifier. Phone numbers, emails and `@handles` are refused as subject aliases, and the authorization records never contain them. Scan results and run logs do contain what you searched, so protect the case folder accordingly.

## Third-party disclosure

Searching sends the queried identifier to third parties. Every provider you enable receives the number or username you query, and may log or disclose it. See [Phone Lookup/PROVIDERS.md](Phone%20Lookup/PROVIDERS.md) for what each provider is sent. Retention and vendor terms are the vendor's; see the vendor. Maigret, User-Scanner and TorBot likewise contact the sites and services they check.

## Your responsibility

You decide whether a search is lawful where you are and where the subject is. Data-protection law may apply to what you collect, store or share (for example GDPR, UK GDPR, CCPA/CPRA, and other national or state rules). You are responsible for having a lawful basis, minimizing what you keep, honoring subject rights where they apply, and deleting data when you no longer need it. The toolkit gives no legal advice and makes no determination for you.

## What these controls are, honestly

The gates and attestations are accountability records enforced in the launchers and containers. They document who declared what, and when. They are not a security boundary. A local operator can edit local files, and running the Python packages directly, outside Docker and the launchers, bypasses the launcher gates entirely. Their value is a clear, auditable record of intent and a speed bump against careless use, not protection against a determined misuser.

## Warranty and reporting

The software is provided without warranty; see LICENSE. To report misuse or a security problem, see SECURITY.md.
