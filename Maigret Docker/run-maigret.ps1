[CmdletBinding(PositionalBinding = $false)]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $MaigretArguments
)

$ErrorActionPreference = 'Stop'
$maigretExitCode = 1
$projectDirectory = Split-Path -Parent $PSCommandPath

Import-Module (Join-Path (Split-Path -Parent $projectDirectory) 'shared\OsintNetworkGate.psm1') -Force
. (Join-Path $projectDirectory '..\shared\OsintTool.Common.ps1')
. (Join-Path $projectDirectory '..\shared\OsintProxyWiring.ps1')
. (Join-Path $projectDirectory '..\shared\OsintSubjectAuthorization.ps1')
. (Join-Path $projectDirectory 'image-freshness.ps1')

if (-not $env:MAIGRET_OUTPUT) {
    $env:MAIGRET_OUTPUT = Join-Path (Get-OsintDataRoot) 'maigret'
}
New-Item -ItemType Directory -Path $env:MAIGRET_OUTPUT -Force | Out-Null

$gateResult = Invoke-OsintNetworkGate -Tool maigret -Arguments $MaigretArguments
if (-not ($gateResult.Passed -or $gateResult.Skipped)) {
    exit (Get-OsintGateExitCode -Result $gateResult)
}

$authorizationResult = Assert-OsintSubjectAuthorization -Tool maigret -Arguments $MaigretArguments
if (-not ($authorizationResult.Passed -or $authorizationResult.Skipped)) {
    exit $authorizationResult.ExitCode
}

$proxyAction = Resolve-OsintProxyEnforcementAction -GateResult $gateResult
if ($proxyAction.Action -eq 'exit') {
    [Console]::Error.WriteLine($proxyAction.Reason)
    exit $proxyAction.Code
}

# Runs after the network gate, so a rebuild never happens on a run the gate refused.
Update-MaigretImages -ProjectDirectory $projectDirectory

$routedState = $null
Push-Location $projectDirectory
try {
    $routedState = Enable-OsintRoutedProxy -GateResult $gateResult -ConfigTool 'MaigretLauncher'
    if ($routedState.ExitCode -ne 0) {
        [Console]::Error.WriteLine($routedState.Message)
        exit $routedState.ExitCode
    }

    docker compose up --detach --wait egress-proxy
    if ($LASTEXITCODE -ne 0) {
        throw 'The filtered egress proxy did not become healthy.'
    }

    if ($routedState.Routed) {
        $probe = Invoke-OsintEnforcementProbe -ToolService 'maigret' -Enforcement $gateResult.Enforcement
        if (-not $probe.Ok) {
            [Console]::Error.WriteLine("routed-proxy enforcement probe failed: no PARENT hierarchy code for CONNECT $($probe.Target) in the Squid access log.")
            exit 75
        }
    }

    docker compose run --rm --no-deps maigret @MaigretArguments
    $maigretExitCode = $LASTEXITCODE
}
finally {
    docker compose down --remove-orphans
    Disable-OsintRoutedProxy -State $routedState
    Pop-Location
}

exit $maigretExitCode
