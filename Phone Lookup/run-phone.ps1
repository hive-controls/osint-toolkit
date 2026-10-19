[CmdletBinding(PositionalBinding = $false)]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $PhoneArguments
)

$ErrorActionPreference = 'Stop'
$exitCode = 1
$projectDirectory = Split-Path -Parent $PSCommandPath

Import-Module (Join-Path (Split-Path -Parent $projectDirectory) 'shared\OsintNetworkGate.psm1') -Force
. (Join-Path $projectDirectory '..\shared\OsintTool.Common.ps1')
. (Join-Path $projectDirectory '..\shared\OsintProxyWiring.ps1')
. (Join-Path $projectDirectory '..\shared\OsintSubjectAuthorization.ps1')
. (Join-Path $projectDirectory '..\shared\OsintProviderPolicy.ps1')

function Import-PhoneLookupSecrets {
    $path = Join-Path (Get-OsintConfigDir -Tool 'PhoneLookup') 'secrets.json'
    if (-not (Test-Path -LiteralPath $path)) { return }
    $data = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    if ($data.numverify_api_key) { $env:NUMVERIFY_API_KEY = [string]$data.numverify_api_key }
    if ($data.dehashed_api_key) { $env:DEHASHED_API_KEY = [string]$data.dehashed_api_key }
    if ($data.leakcheck_api_key) { $env:LEAKCHECK_APIKEY = [string]$data.leakcheck_api_key }
    if ($data.leakradar_api_key) { $env:LEAKRADAR_API_KEY = [string]$data.leakradar_api_key }
}

Import-PhoneLookupSecrets

if (Test-OsintProviderManagementArguments -Arguments $PhoneArguments) {
    exit (Invoke-OsintProviderManagement -ProjectDirectory $projectDirectory -ManagementArguments $PhoneArguments)
}

if (-not $env:PHONE_LOOKUP_OUTPUT) {
    $env:PHONE_LOOKUP_OUTPUT = Join-Path (Get-OsintDataRoot) 'phone'
}
New-Item -ItemType Directory -Path $env:PHONE_LOOKUP_OUTPUT -Force | Out-Null

$gateResult = Invoke-OsintNetworkGate -Tool phone -Arguments $PhoneArguments
if (-not ($gateResult.Passed -or $gateResult.Skipped)) {
    exit (Get-OsintGateExitCode -Result $gateResult)
}

$authorizationResult = Assert-OsintSubjectAuthorization -Tool phone -Arguments $PhoneArguments
if (-not ($authorizationResult.Passed -or $authorizationResult.Skipped)) {
    exit $authorizationResult.ExitCode
}

# Opt-in providers: the host reads providers.json and hands the container only the enabled list
# ("name@terms-version"); a key alone never enables a provider. A malformed file fails closed (no lookup).
$providersPath = Join-Path (Get-OsintConfigDir -Tool 'PhoneLookup') 'providers.json'
try {
    $env:PHONE_LOOKUP_PROVIDERS = (@(Get-OsintEnabledProviders -Path $providersPath) -join ',')
}
catch {
    [Console]::Error.WriteLine("providers.json is not valid JSON ($providersPath): $($_.Exception.Message)")
    exit 78
}

$proxyAction = Resolve-OsintProxyEnforcementAction -GateResult $gateResult
if ($proxyAction.Action -eq 'exit') {
    [Console]::Error.WriteLine($proxyAction.Reason)
    exit $proxyAction.Code
}

$routedState = $null
Push-Location $projectDirectory
try {
    $routedState = Enable-OsintRoutedProxy -GateResult $gateResult -ConfigTool 'PhoneLookup'
    if ($routedState.ExitCode -ne 0) {
        [Console]::Error.WriteLine($routedState.Message)
        exit $routedState.ExitCode
    }

    docker compose up --detach --wait egress-proxy
    if ($LASTEXITCODE -ne 0) {
        throw 'The filtered egress proxy did not become healthy.'
    }

    if ($routedState.Routed) {
        $probe = Invoke-OsintEnforcementProbe -ToolService 'phone' -Enforcement $gateResult.Enforcement
        if (-not $probe.Ok) {
            [Console]::Error.WriteLine("routed-proxy enforcement probe failed: no PARENT hierarchy code for CONNECT $($probe.Target) in the Squid access log.")
            exit 75
        }
    }

    docker compose run --rm --no-deps phone @PhoneArguments
    $exitCode = $LASTEXITCODE
}
finally {
    docker compose down --remove-orphans
    Disable-OsintRoutedProxy -State $routedState
    Pop-Location
}

exit $exitCode
