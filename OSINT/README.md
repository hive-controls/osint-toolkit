# Case workspace

> People-focused OSINT. Authorized, lawful use only — see [LEGAL-USE.md](../LEGAL-USE.md).

**Legacy location.** New installs keep case data in the data root (`--root`, then `OSINT_ROOT`, then `%LOCALAPPDATA%\OsintToolkit\data`), not in this folder. This folder remains only for older trees: the profiler warns when it finds cases here and the new root is empty, and `osint-case migrate-root --from <repo>\OSINT --to <data root>` copies them across (see the [profiler guide](../OSINT%20Profiler/README.md#data-location)). Nothing is moved or deleted for you.

This folder holds **saved investigation artifacts** for the toolkit. Everything here except this README, `New-OsintCase.ps1` and `cases/_template/` is gitignored case data. It is not an installable scanner by itself.

For new investigations use **`osint-case`**, the installed terminal workbench and optional local HTML editor: per-case SQLite, imports, evidence-backed connection review and scanner launch controls. See the [OSINT Profiler guide](../OSINT%20Profiler/README.md). The folder/index workflow below remains available for legacy cases; the profiler can adopt those folders without replacing `case.md`.

## Layout

```text
OSINT/
  maigret/                    # Legacy hardened Maigret reports (older installs)
  scanner/                    # Legacy User-Scanner JSON/CSV reports (older installs)
  phone/                      # Legacy Phone Lookup JSON reports (older installs)
  cases/
    _template/                # stub copied by New-OsintCase.ps1
    <case-id>/
      case.md                 # metadata, identifiers, artifact index, notes
      scanner/                # User-Scanner copies (optional)
      maigret/                # Maigret copies (optional)
      torbot/                 # TorBot copies (optional)
      phone/                  # Phone lookup JSON (optional)
```

Cases created or adopted with `osint-case` additionally have a database and managed artifact folders.

## Create a case

`<repo>` is your clone directory.

```powershell
Set-Location '<repo>\OSINT'
.\New-OsintCase.ps1 'example-case'
# then edit cases\example-case\case.md
```

Older installs wrote Maigret, User-Scanner and Phone Lookup reports directly into `OSINT\maigret`, `OSINT\scanner` and `OSINT\phone` here; current tools write under the data root (`<data root>\maigret`, `<data root>\scanner`, `<data root>\phone`, `<data root>\torbot`), and each container sees its own folder as `/output`. User-Scanner's Terminal-only mode does not produce a report: choose JSON/CSV or pass CLI export arguments.

To save directly into an existing case, set the corresponding override before launching:

```powershell
$env:MAIGRET_OUTPUT = '<data root>\cases\<id>\maigret'
$env:SCANNER_OUTPUT = '<data root>\cases\<id>\scanner'
$env:PHONE_LOOKUP_OUTPUT = '<data root>\cases\<id>\phone'
$env:TORBOT_OUTPUT = '<data root>\cases\<id>\torbot'
```

Remove an override with `Remove-Item Env:MAIGRET_OUTPUT` (or the corresponding name) to return to the default. With no overrides, the menus and helpers write under the data root; running `docker compose` directly without a launcher falls back to a legacy folder, so prefer the launchers or set the override.

Record the report paths you used in `case.md`.

## Sensitivity rule

Treat everything under `maigret/`, `scanner/`, `phone/` and `cases/` as **sensitive case data**.

- Never sync these trees to cloud storage or a git remote.
- Open untrusted HTML (crawl output, Maigret `combined_graph.html`, saved onion pages) only in an isolated browser profile or disposable VM, never in your daily browser.
- Do not paste crawl HTML, cookies or session dumps into chat or any launcher.

## Which tool when

| Need | Use |
|---|---|
| Email registered where? + username sweep, Docker-isolated | **User-Scanner** |
| Phone: numbering plan + optional opt-in providers | **Phone Lookup** |
| Deep username dossier / recursion / rich reports | **Maigret** (hardened Docker) |
| `.onion` site crawl / link tree | **TorBot** (hardened CLI) |
| Correlate outputs | `<data root>\cases\<id>\case.md` |
