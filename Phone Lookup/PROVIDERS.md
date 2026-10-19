# Phone Lookup providers

Repo-derivable facts only. Every provider is **off by default** and needs `enabled: true` plus a current terms acknowledgement in `providers.json` (see [README](README.md#providers-opt-in)). A key never enables a provider. Vendor retention, logging and terms of service are not asserted here: **see vendor**. Permitted use and the operator's wider responsibilities are in [LEGAL-USE.md](../LEGAL-USE.md).

## Data sent and retention

Each enabled provider receives the phone number you look up (format per row below) and sees your IP address and API key. What the vendor logs, retains, shares or sells is the vendor's business and is not stated in this repo: **see vendor**. This toolkit does not delete anything on the vendor's side and does not retry failed requests automatically.

| Provider | What is sent (file:line) | Key | Default | Tier (repo-derivable) | Vendor ToS | Operator obligations |
|---|---|---|---|---|---|---|
| `numverify` | digits only (no `+`) as `number` query param to `api.apilayer.com/number_verification/validate` (`providers/numverify.py:10-12`) | `NUMVERIFY_API_KEY` / `APILAYER_API_KEY` (`secrets.py:16`) | off | key required (`cli.py` via `plan_providers`); plan tier not stated in repo | see vendor | Own account; accept vendor ToS; rate limits are yours; no auto-retry |
| `hudson_rock` | E.164 incl. `+` as `username` query param to `cavalier.hudsonrock.com` (`providers/hudson.py:9,13`); source comment: "They may log the query" (`hudson.py:7-8`) | none | off | free endpoint per `hudson.py:8` comment; keyless, so exempt from the no-key check | see vendor | Accept vendor ToS (no account held); rate limits are yours; no auto-retry |
| `dehashed` | `phone:"<e164>" OR phone:<digits>` in a POST body to `api.dehashed.com/v2/search` (`providers/dehashed.py:9-13`) | `DEHASHED_API_KEY` (`secrets.py:17`) | off | key required; README calls it paid | see vendor | Own paid account; accept vendor ToS; rate limits are yours; no auto-retry |
| `leakcheck` | digits only in the URL path of `leakcheck.io/api/v2/query/<digits>` with `type=phone` (`providers/leakcheck.py:11-12`) | `LEAKCHECK_APIKEY` / `LEAKCHECK_API_KEY` (`secrets.py:18`) | off | key required; README calls it paid. Phone-search support depends on the plan and was not independently confirmed when this was written | see vendor | Own paid account; accept vendor ToS; rate limits are yours; no auto-retry. Confirm with the vendor that phone search is supported before relying on a miss |
| `leakradar` | `username: [e164, digits]` in a POST body to `api.leakradar.io/search/advanced` (`providers/leakradar.py:9,15`); no native phone index | `LEAKRADAR_API_KEY` / `LEAKRADAR_TOKEN` (`secrets.py:19`) | off | key required; plan tier not stated in repo | see vendor | Own account; accept vendor ToS; rate limits are yours; no auto-retry |

Terms text shipped per provider: `PROVIDER-TERMS/<provider>.txt`. The acknowledgement `version` is the SHA-256 of that file with CRLF normalised to LF (`providers_config.terms_version`; PowerShell twin `Get-OsintProviderTermsVersion` in `shared/OsintProviderPolicy.ps1`).

`skipped` reasons in the lookup report: `disabled`, `skipped-flag`. The reasons `no-key` and `terms-ack-stale` appear in the exit-78 `problems` object instead, because a misconfigured enabled provider stops the whole lookup before anything is sent.

User-Scanner's `--hudson` sends the scanned username/email to Hudson Rock and follows the same policy (`hudson_rock` enabled + acknowledged); see `User-Scanner Docker/README.md`.
