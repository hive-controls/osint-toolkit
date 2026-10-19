[CmdletBinding()]
param([Parameter(Mandatory)][string]$PlanFile)
$ErrorActionPreference = 'Stop'
$plan = Get-Content -LiteralPath $PlanFile -Raw | ConvertFrom-Json
$workspace = Split-Path -Parent $PSScriptRoot
$runners = @{
    maigret = 'Maigret Docker/run-maigret.ps1'
    scanner = 'User-Scanner Docker/run-scanner.ps1'
    phone = 'Phone Lookup/run-phone.ps1'
}
if (-not $runners.ContainsKey([string]$plan.tool)) { throw 'Unsupported tool.' }
# The profiler already presented its RUN review. Every runner (maigret, scanner, phone) applies the shared network gate.
$scanArgs = @($plan.arguments | ForEach-Object { [string]$_ })
& (Join-Path $workspace $runners[[string]$plan.tool]) @scanArgs
exit $LASTEXITCODE
