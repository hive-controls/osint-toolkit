# Hardened User Scanner interactive launcher

## Outcome

Provide one guided PowerShell experience that is launched either from a
desktop shortcut or by typing `user-scanner` in PowerShell. The launcher owns
Docker readiness, image presence, safe command construction, the existing
Squid-filtered execution path, report placement, and cleanup.

## Information architecture

The main menu has five actions:

1. New guided run
2. Run a favorite
3. Manage favorites
4. Environment status or rebuild
5. Exit and close this project's environment

A new run is configured in four grouped steps:

1. **Target & scope** — username/email, single/bulk input, normal/Hudson mode,
   then full/category/module scope.
2. **Safety & expansion** — standard preset includes NSFW by default; loud and
   cross-scan stay off unless Custom enables them. Minimal opts out of NSFW.
3. **Output & pace** — terminal/JSON/CSV, found/verbose/all display, and a
   gentle/standard/custom performance profile.
4. **Review & run** — human-readable safety summary, generated command,
   optional favorite save, and a mandatory VPN/proxy readiness gate.

## Safety invariants

- Every execution requires the operator to type `RUN` after confirming that
  their VPN is on or their approved proxy path is established.
- The reminder explains that built-in Squid filters LAN access but does not
  rotate or conceal the public IP.
- NSFW modules are on by default (omit `--no-nsfw`). Loud and cross-scan
  behavior remain off by default and cannot be inherited silently from a
  favorite without being shown in review.
- Enabling loud behavior requires an additional `LOUD` acknowledgement.
- Favorites never persist a username, email, input-file path, output filename,
  proxy credential, or other target-specific value.
- Bulk files outside the dedicated output mount are copied only after explicit
  confirmation.
- PDF remains unavailable because the hardened image omits its optional
  dependencies and remote-media fetch path.
- Exit always runs `docker compose down --remove-orphans` for this project.
- Docker Desktop is not stopped automatically because it may serve unrelated
  workloads; the launcher offers an explicit stop action when appropriate.

## Favorites

Four fixed slots are stored in
`%LOCALAPPDATA%\UserScannerLauncher\favorites.json`. Each slot stores only:

- display name;
- scan type and single/bulk input mode;
- normal/Hudson mode;
- scope type and selected modules/categories;
- safety/cross-scan settings;
- output format and display mode;
- pace settings.

Loading a favorite always asks for a fresh target or bulk file and creates a
fresh output filename.

## CLI mapping

The launcher maps to the reviewed 1.5.1.3 flags: `-u`, `-e`, `-uf`, `-ef`,
`-m`, `-c`, `-v`, `--all`, `-s`, `-t`, `-C`, `-d`, `-f`, `-o`,
`--no-nsfw`, `--allow-loud`, `--cross-scan`, `--cross-links`,
`--cross-emails`, `--cross-depth`, `--cross-sweep`, and `--hudson`.

`-U/--update` remains prohibited by container policy. PDF and arbitrary
external proxy lists are not offered in the guided flow; VPN egress plus the
containerized Squid filter is the supported transport boundary.

## Installation

`install-launcher.ps1` creates a user-owned command shim under
`%LOCALAPPDATA%\Programs\UserScannerLauncher`, adds that directory to the user
PATH if needed, and creates `User Scanner (Hardened).lnk` on the current user's
desktop. It refuses to replace an unrelated `user-scanner` command unless
`-Force` is explicitly supplied.

`uninstall-launcher.ps1` removes only those exact launcher artifacts and PATH
entry. It does not remove Docker images or reports.
