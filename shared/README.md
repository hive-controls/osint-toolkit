# shared/

`OsintTool.Common.ps1` is a dot-sourced helper shared by the launcher/gate scripts
under the tool folders, so each tool resolves its per-machine config directory and
home directory the same way instead of hardcoding Windows-only environment
variables.

- `Get-OsintConfigDir -Tool <name>` — per-machine config/secrets directory.
  Resolution order: `$env:LOCALAPPDATA\<name>`, then `$env:XDG_CONFIG_HOME\<name>`,
  then `$HOME\.config\<name>`.
- `Get-OsintDataRoot [-Root <dir>]` — the OSINT data root (cases, inbox, tool output
  lanes), the twin of the profiler's `util.data_root`. Resolution order: `-Root`,
  `$env:OSINT_ROOT`, `$env:LOCALAPPDATA\OsintToolkit\data`, then
  `$env:XDG_DATA_HOME\osint-toolkit`, then `$HOME\.local\share\osint-toolkit`.
- `Get-OsintHomeDir` — the user's home directory. Resolution order:
  `$env:USERPROFILE`, then `$HOME`.

On Windows the results are byte-identical to the prior hardcoded
`$env:LOCALAPPDATA` / `$env:USERPROFILE` paths. On macOS/Linux, where those
variables are unset, it falls back to XDG/`$HOME` conventions.

## build/

`build/fetch_wheelhouse.py` (stdlib only) fetches and verifies each tool's gitignored
`artifacts/wheelhouse/` from its `requirements.lock`:
`python -I shared/build/fetch_wheelhouse.py --tool "<dir>"` (or `--all`; `--verify-only`, `--force`).
Needs Docker for the download; verification is host-side. Exit 0 ok / 1 verify failure / 2 usage / 3 Docker unavailable.

`build/generate_formic.py` (stdlib only) renders the `.formic/` manifests (`toolkit.yaml`,
`profile.yaml`, `tools/<id>.yaml`) from `catalog/tools.json`: `python -I shared/build/generate_formic.py`
rewrites them, `--check` exits 4 when a committed file differs. `tests/test_formic_drift.py` enforces it.
Private tools are not in the catalog and are never generated.

## catalog/

`catalog/tools.json` is the single tool catalog (ids, versions, runners, input and
option validators, argv templates, gates, exit codes); `catalog/schema/catalog.schema.json`
validates it and `catalog/schema/result.schema.json` defines the per-run
`result.json` envelope. The profiler (`osint_profiler/catalog.py`) loads it and builds
its scan validators and argv from it. See the "Tool catalog" and "Result envelope"
sections of `OSINT Profiler/README.md`.
