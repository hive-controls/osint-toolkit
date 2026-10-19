[CmdletBinding(PositionalBinding = $false)]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $ScannerArguments
)

$ErrorActionPreference = 'Stop'
$scannerExitCode = 1
$projectDirectory = Split-Path -Parent $PSCommandPath

Import-Module (Join-Path (Split-Path -Parent $projectDirectory) 'shared\OsintNetworkGate.psm1') -Force
. (Join-Path $projectDirectory '..\shared\OsintTool.Common.ps1')
. (Join-Path $projectDirectory '..\shared\OsintProxyWiring.ps1')
. (Join-Path $projectDirectory '..\shared\OsintSubjectAuthorization.ps1')
. (Join-Path $projectDirectory '..\shared\OsintProviderPolicy.ps1')
$gateResult = Invoke-OsintNetworkGate -Tool scanner -Arguments $ScannerArguments
if (-not ($gateResult.Passed -or $gateResult.Skipped)) {
    exit (Get-OsintGateExitCode -Result $gateResult)
}

$authorizationResult = Assert-OsintSubjectAuthorization -Tool scanner -Arguments $ScannerArguments
if (-not ($authorizationResult.Passed -or $authorizationResult.Skipped)) {
    exit $authorizationResult.ExitCode
}

# --hudson sends the subject to Hudson Rock, so it follows the same opt-in policy as Phone Lookup:
# allowed only when the shared providers.json has hudson_rock enabled with a current terms acknowledgement.
$env:SCANNER_HUDSON_ALLOWED = ''
if (Test-OsintHudsonRequested -Arguments $ScannerArguments) {
    $providersPath = Join-Path (Get-OsintConfigDir -Tool 'PhoneLookup') 'providers.json'
    if (-not (Test-OsintHudsonAllowed -Path $providersPath)) {
        [Console]::Error.WriteLine('--hudson is disabled: Hudson Rock is not enabled with a current terms acknowledgement. Run: phone-lookup --enable hudson_rock --acknowledge-terms "<phrase>" (see Phone Lookup\PROVIDERS.md).')
        exit 78
    }
    $env:SCANNER_HUDSON_ALLOWED = '1'
}

$proxyAction = Resolve-OsintProxyEnforcementAction -GateResult $gateResult
if ($proxyAction.Action -eq 'exit') {
    [Console]::Error.WriteLine($proxyAction.Reason)
    exit $proxyAction.Code
}

if (-not $env:SCANNER_OUTPUT) {
    $env:SCANNER_OUTPUT = Join-Path (Get-OsintDataRoot) 'scanner'
}

New-Item -ItemType Directory -Path $env:SCANNER_OUTPUT -Force | Out-Null

$routedState = $null
Push-Location $projectDirectory
try {
    $routedState = Enable-OsintRoutedProxy -GateResult $gateResult -ConfigTool 'ScannerLauncher'
    if ($routedState.ExitCode -ne 0) {
        [Console]::Error.WriteLine($routedState.Message)
        exit $routedState.ExitCode
    }

    docker compose up --detach --wait egress-proxy
    if ($LASTEXITCODE -ne 0) {
        throw "The filtered egress proxy did not become healthy."
    }

    if ($routedState.Routed) {
        $probe = Invoke-OsintEnforcementProbe -ToolService 'scanner' -Enforcement $gateResult.Enforcement
        if (-not $probe.Ok) {
            [Console]::Error.WriteLine("routed-proxy enforcement probe failed: no PARENT hierarchy code for CONNECT $($probe.Target) in the Squid access log.")
            exit 75
        }
    }

    docker compose run --rm --no-deps scanner @ScannerArguments
    $scannerExitCode = $LASTEXITCODE
}
finally {
    docker compose down --remove-orphans
    Disable-OsintRoutedProxy -State $routedState
    Pop-Location
}

exit $scannerExitCode
