# PowerShell tests

Pester 5 tests for the shared network gate (`shared/OsintNetworkGate.psm1`). Pinned: `Install-Module Pester -RequiredVersion 5.7.1 -Scope CurrentUser -Force -SkipPublisherCheck`.
Run from the repo root: `pwsh -NoProfile -Command "Invoke-Pester -Path tests/powershell -Output Detailed"`
