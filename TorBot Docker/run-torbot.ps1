[CmdletBinding(PositionalBinding = $false)]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $TorBotArguments
)

$ErrorActionPreference = 'Stop'
$torbotExitCode = 1
$projectDirectory = Split-Path -Parent $PSCommandPath

Import-Module (Join-Path (Split-Path -Parent $projectDirectory) 'shared\OsintNetworkGate.psm1') -Force
. (Join-Path $projectDirectory '..\shared\OsintTool.Common.ps1')
. (Join-Path $projectDirectory '..\shared\OsintProxyWiring.ps1')
. (Join-Path $projectDirectory '..\shared\OsintSubjectAuthorization.ps1')

if (-not $env:TORBOT_OUTPUT) {
    $env:TORBOT_OUTPUT = Join-Path (Get-OsintDataRoot) 'torbot'
}
New-Item -ItemType Directory -Path $env:TORBOT_OUTPUT -Force | Out-Null

$gateResult = Invoke-OsintNetworkGate -Tool torbot -Arguments $TorBotArguments
if (-not ($gateResult.Passed -or $gateResult.Skipped)) {
    exit (Get-OsintGateExitCode -Result $gateResult)
}

$authorizationResult = Assert-OsintSubjectAuthorization -Tool torbot -Arguments $TorBotArguments
if (-not ($authorizationResult.Passed -or $authorizationResult.Skipped)) {
    exit $authorizationResult.ExitCode
}

$torbotRouteAction = Resolve-OsintTorBotRouteAction -GateResult $gateResult
if ($torbotRouteAction.Action -eq 'exit') {
    [Console]::Error.WriteLine($torbotRouteAction.Reason)
    exit $torbotRouteAction.Code
}

Push-Location $projectDirectory
try {
    docker compose up --detach --wait tor
    if ($LASTEXITCODE -ne 0) {
        throw 'The Tor sidecar did not become healthy.'
    }

    docker compose run --rm --no-deps torbot @TorBotArguments
    $torbotExitCode = $LASTEXITCODE
}
finally {
    docker compose down --remove-orphans
    Pop-Location
}

exit $torbotExitCode
