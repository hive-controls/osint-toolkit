[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $CommandArgs
)

$ErrorActionPreference = 'Stop'
$projectDirectory = Split-Path -Parent $PSCommandPath
$script:RunnerPath = Join-Path $projectDirectory 'run-phone.ps1'
$script:AppImage = 'phone-lookup-hardened:0.1.0'
$script:ProxyImage = 'phone-lookup-egress-proxy:local'
if ($env:OSINT_CASE_SESSION) {
    . (Join-Path (Split-Path -Parent $projectDirectory) 'OSINT Profiler/Invoke-CaseScan.ps1')
}

Import-Module (Join-Path (Split-Path -Parent $projectDirectory) 'shared\OsintNetworkGate.psm1') -Force
. (Join-Path $projectDirectory '..\shared\OsintTool.Common.ps1')
. (Join-Path $projectDirectory '..\shared\OsintSubjectAuthorization.ps1')

function Show-Help {
    Write-Host @'
phone-lookup - numbering-plan parse + optional Numverify + Hudson/DeHashed/LeakCheck/LeakRadar

  phone-lookup            Open the interactive menu
  phone-lookup --status
  phone-lookup --cleanup
  phone-lookup --selftest
  phone-lookup --help

Lookups require VPN gate PASS + typing RUN (except --help/--version).
Jobs 1 and 4 only. No WhatsApp/Telegram/Ignorant probes.
'@
}

function Read-YesNo {
    param([Parameter(Mandatory)] [string] $Prompt, [bool] $Default = $false)
    $suffix = if ($Default) { '[Y/n]' } else { '[y/N]' }
    while ($true) {
        $answer = (Read-Host "$Prompt $suffix").Trim().ToLowerInvariant()
        if (-not $answer) { return $Default }
        if ($answer -in @('y', 'yes')) { return $true }
        if ($answer -in @('n', 'no')) { return $false }
        Write-Host 'Enter y or n.' -ForegroundColor Yellow
    }
}

function Test-DockerReady {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { return $false }
    & docker info *> $null
    return $LASTEXITCODE -eq 0
}

function Start-DockerIfNeeded {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        throw 'Docker CLI was not found.'
    }
    if (Test-DockerReady) { return }
    if (-not (Read-YesNo 'Docker Desktop is not ready. Start it now?' $true)) {
        throw 'Docker Desktop is required.'
    }
    & docker desktop start
    Write-Host 'Waiting for Docker Desktop' -NoNewline
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        Start-Sleep -Seconds 2
        Write-Host '.' -NoNewline
        if (Test-DockerReady) { Write-Host; return }
    }
    Write-Host
    throw 'Docker Desktop did not become ready within two minutes.'
}

function Test-ImagePresent {
    param([Parameter(Mandatory)] [string] $Image)
    & docker image inspect $Image *> $null
    return $LASTEXITCODE -eq 0
}

function Ensure-Images {
    $missing = @()
    foreach ($image in @($script:AppImage, $script:ProxyImage)) {
        if (-not (Test-ImagePresent $image)) { $missing += $image }
    }
    if ($missing.Count -eq 0) { return }
    Write-Host ("Missing images: {0}" -f ($missing -join ', ')) -ForegroundColor Yellow
    if (-not (Read-YesNo 'Build the pinned images now?' $true)) {
        throw 'Required Docker images are missing.'
    }
    Push-Location $projectDirectory
    try {
        docker compose build
        if ($LASTEXITCODE -ne 0) { throw 'docker compose build failed.' }
    }
    finally { Pop-Location }
}

function Stop-ProjectEnvironment {
    Push-Location $projectDirectory
    try { docker compose down --remove-orphans } finally { Pop-Location }
}

function Confirm-NetworkReady {
    Write-Host
    Write-Host 'NETWORK SAFETY CHECK' -ForegroundColor Black -BackgroundColor Yellow
    Write-Host 'Hudson / Numverify / breach APIs receive the phone number when enabled.' -ForegroundColor Yellow
    $gate = Test-OsintNetworkGate -Tool phone
    if (-not $gate.Passed) { return $false }
    $answer = Read-Host 'Type RUN to confirm and execute (anything else cancels)'
    return $answer -ceq 'RUN'
}

function Show-Status {
    Start-DockerIfNeeded
    Write-Host "Project : $projectDirectory"
    Write-Host "App     : $(if (Test-ImagePresent $script:AppImage) { 'present' } else { 'missing' })"
    Write-Host "Proxy   : $(if (Test-ImagePresent $script:ProxyImage) { 'present' } else { 'missing' })"
    Write-Host "Output  : $(if ($env:PHONE_LOOKUP_OUTPUT) { $env:PHONE_LOOKUP_OUTPUT } else { Join-Path (Get-OsintDataRoot) 'phone' })"
    $gate = Test-OsintNetworkGate -Tool phone -Quiet
    Write-Host ("Gate    : {0} ({1})" -f $(if ($gate.Passed) { 'PASS' } else { 'FAIL' }), $gate.Reason)
    $secrets = Join-Path (Get-OsintConfigDir -Tool 'PhoneLookup') 'secrets.json'
    Write-Host ("Secrets : {0}" -f $(if (Test-Path $secrets) { $secrets } else { 'none (paid APIs need a key AND opt-in)' }))
}

function Start-ProvidersMenu {
    # Every provider is off until enabled here; the Python CLI (in the container) owns the phrase check.
    while ($true) {
        Write-Host
        Write-Host 'Third-party providers (opt-in; a key alone never enables one)' -ForegroundColor Cyan
        Write-Host '1) List state'
        Write-Host '2) Enable a provider (read terms, type acknowledgement phrase)'
        Write-Host '3) Disable a provider'
        Write-Host '4) Back'
        $choice = (Read-Host 'Select').Trim()
        switch ($choice) {
            '1' { Start-DockerIfNeeded; Ensure-Images; & $script:RunnerPath --providers }
            '2' { Enable-ProviderInteractive }
            '3' {
                $provider = (Read-Host 'Provider id to disable').Trim()
                if ($provider) { Start-DockerIfNeeded; Ensure-Images; & $script:RunnerPath --disable $provider }
            }
            '4' { return }
            default { Write-Host 'Choose 1-4.' -ForegroundColor Yellow }
        }
    }
}

function Enable-ProviderInteractive {
    $provider = (Read-Host 'Provider id (numverify, hudson_rock, dehashed, leakcheck, leakradar)').Trim()
    if (-not $provider) { return }
    $termsFile = Join-Path $projectDirectory "PROVIDER-TERMS\$provider.txt"
    if (-not (Test-Path -LiteralPath $termsFile)) { Write-Host "Unknown provider: $provider" -ForegroundColor Yellow; return }
    Write-Host
    Get-Content -LiteralPath $termsFile | Write-Host
    Write-Host
    Start-DockerIfNeeded
    Ensure-Images
    # A deliberately wrong placeholder makes the CLI refuse and print the exact phrase it requires (kept in one place).
    & $script:RunnerPath --enable $provider --acknowledge-terms 'show-required-phrase'
    $phrase = Read-Host 'Type the required phrase exactly to accept (blank cancels)'
    if ($phrase) { & $script:RunnerPath --enable $provider --acknowledge-terms $phrase }
}

function Invoke-SelfTest {
    $gateProbe = Test-OsintNetworkGate -Tool phone -Quiet
    if ($gateProbe.Code -eq 'FAIL_CONFIG') { throw "Gate config invalid: $($gateProbe.Reason)" }
    Write-Host 'Gate config load: OK' -ForegroundColor Green
    if (-not (Test-Path -LiteralPath $script:RunnerPath)) { throw 'run-phone.ps1 missing' }
    Write-Host 'Self-test complete.' -ForegroundColor Green
}

function Start-GuidedLookup {
    if (-not (Test-OsintCaseContext)) { Write-OsintCaseRequired; return }
    $phone = (Read-Host 'Phone (E.164, e.g. +14155552671)').Trim()
    if (-not $phone) { Write-Host 'Cancelled.'; return }
    $region = (Read-Host 'Region if national number [blank]').Trim()
    $arguments = [System.Collections.Generic.List[string]]::new()
    $arguments.Add($phone)
    if ($region) { $arguments.Add('--region'); $arguments.Add($region) }

    Write-Host
    Write-Host ('Command: run-phone.ps1 ' + ($arguments -join ' ')) -ForegroundColor DarkGray
    Write-Host "Output : $(if ($env:PHONE_LOOKUP_OUTPUT) { $env:PHONE_LOOKUP_OUTPUT } else { Join-Path (Get-OsintDataRoot) 'phone' })"
    if (-not (Confirm-NetworkReady)) {
        Write-Host 'Cancelled.' -ForegroundColor Yellow
        return
    }
    Start-DockerIfNeeded
    Ensure-Images
    if (-not $env:PHONE_LOOKUP_OUTPUT) {
        $env:PHONE_LOOKUP_OUTPUT = Join-Path (Get-OsintDataRoot) 'phone'
    }
    New-Item -ItemType Directory -Path $env:PHONE_LOOKUP_OUTPUT -Force | Out-Null
    if ($env:OSINT_CASE_SESSION) {
        Invoke-CaseScan -ScanArguments $arguments.ToArray() -TargetLabel $phone
    } else {
        & $script:RunnerPath @arguments
    }
}

function Show-MainMenu {
    while ($true) {
        Write-Host
        Write-Host 'Phone lookup (Hardened)' -ForegroundColor Cyan
        if ($env:OSINT_CASE_SESSION) { Write-Host "Case: $env:OSINT_CASE_ID | Each scan saves to $env:OSINT_CASE_RUNS\<run-id>\output" -ForegroundColor Cyan }
        Write-Host '1) New lookup'
        Write-Host '2) Environment status / rebuild'
        Write-Host '3) Exit and close project environment'
        Write-Host '4) Providers (opt-in / terms)'
        $choice = (Read-Host 'Select').Trim()
        switch ($choice) {
            '1' { Start-GuidedLookup }
            '2' {
                Show-Status
                if (Read-YesNo 'Rebuild images now?' $false) {
                    Start-DockerIfNeeded
                    Push-Location $projectDirectory
                    try { docker compose build } finally { Pop-Location }
                }
            }
            '3' {
                Stop-ProjectEnvironment
                return
            }
            '4' { Start-ProvidersMenu }
            default { Write-Host 'Choose 1-4.' -ForegroundColor Yellow }
        }
    }
}

if ($CommandArgs -contains '--help' -or $CommandArgs -contains '-h') { Show-Help; exit 0 }
if ($CommandArgs -contains '--status') { Show-Status; exit 0 }
if ($CommandArgs -contains '--cleanup') { Stop-ProjectEnvironment; exit 0 }
if ($CommandArgs -contains '--selftest') { Invoke-SelfTest; exit 0 }

Show-MainMenu
