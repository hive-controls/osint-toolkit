[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $CommandArgs
)

$ErrorActionPreference = 'Stop'
$projectDirectory = Split-Path -Parent $PSCommandPath
$script:RunnerPath = Join-Path $projectDirectory 'run-maigret.ps1'
$script:MaigretImage = 'maigret-hardened:0.6.4'
$script:ProxyImage = 'maigret-egress-proxy:local'
if ($env:OSINT_CASE_SESSION) {
    . (Join-Path (Split-Path -Parent $projectDirectory) 'OSINT Profiler/Invoke-CaseScan.ps1')
}

Import-Module (Join-Path (Split-Path -Parent $projectDirectory) 'shared\OsintNetworkGate.psm1') -Force
. (Join-Path $projectDirectory '..\shared\OsintSubjectAuthorization.ps1')
. (Join-Path $projectDirectory 'image-freshness.ps1')

function Show-Help {
    Write-Host @'
maigret - guided launcher for the hardened Maigret Docker environment

  maigret            Open the interactive menu
  maigret --status   Show environment status
  maigret --cleanup  Close this project's Compose environment
  maigret --selftest Validate launcher wiring without a search
  maigret --help     Show this help

Searches require: VPN gate PASS + typing RUN.
Maigret runs entirely in Docker; reports default to <data root>\maigret (MAIGRET_OUTPUT overrides).
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
        throw 'Docker CLI was not found. Install Docker Desktop before using this launcher.'
    }
    if (Test-DockerReady) { return }
    if (-not (Read-YesNo 'Docker Desktop is not ready. Start it now?' $true)) {
        throw 'Docker Desktop is required.'
    }
    & docker desktop start
    if ($LASTEXITCODE -ne 0) {
        $desktopExe = Join-Path $env:ProgramFiles 'Docker\Docker\Docker Desktop.exe'
        if (-not (Test-Path -LiteralPath $desktopExe)) { throw 'Docker Desktop could not be started.' }
        Start-Process -FilePath $desktopExe | Out-Null
    }
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
    Update-MaigretImages -ProjectDirectory $projectDirectory
}

function Stop-ProjectEnvironment {
    Push-Location $projectDirectory
    try {
        docker compose down --remove-orphans
    }
    finally { Pop-Location }
}

function Confirm-NetworkReady {
    Write-Host
    Write-Host 'NETWORK SAFETY CHECK' -ForegroundColor Black -BackgroundColor Yellow
    Write-Host '1) Automated probe: host route to the internet must leave through an allowlisted VPN adapter.' -ForegroundColor Yellow
    Write-Host '2) Typed RUN: confirm you accept Squid-filtered clearnet egress for this search.' -ForegroundColor Yellow
    Write-Host 'Squid blocks LAN/metadata destinations. It does not hide or rotate your public IP.' -ForegroundColor DarkGray
    Write-Host

    $gate = Test-OsintNetworkGate -Tool maigret
    if (-not $gate.Passed) {
        return $false
    }

    $answer = Read-Host 'Type RUN to confirm and execute (anything else cancels)'
    return $answer -ceq 'RUN'
}

function Show-Status {
    Start-DockerIfNeeded
    Write-Host "Project        : $projectDirectory"
    Write-Host "Maigret image  : $(if (Test-ImagePresent $script:MaigretImage) { 'present' } else { 'missing' }) ($script:MaigretImage)"
    Write-Host "Proxy image    : $(if (Test-ImagePresent $script:ProxyImage) { 'present' } else { 'missing' }) ($script:ProxyImage)"
    $stale = @(Get-StaleMaigretImages -ExpectedHash (Get-MaigretBuildInputsHash -ProjectDirectory $projectDirectory))
    Write-Host "Hardening sync : $(if ($stale.Count -eq 0) { 'images match hardening files' } else { 'rebuild pending on next run: ' + ($stale -join ', ') })"
    Write-Host "Output dir     : $(if ($env:MAIGRET_OUTPUT) { $env:MAIGRET_OUTPUT } else { Join-Path (Get-OsintDataRoot) 'maigret' })"
    $gate = Test-OsintNetworkGate -Tool maigret -Quiet
    Write-Host ("Network gate   : {0} ({1})" -f $(if ($gate.Passed) { 'PASS' } else { 'FAIL' }), $gate.Reason)
}

function Invoke-SelfTest {
    Write-Host 'Self-test (no search, no Docker required for gate module)...' -ForegroundColor Cyan
    $gateProbe = Test-OsintNetworkGate -Tool maigret -Quiet
    if ($gateProbe.Code -eq 'FAIL_CONFIG') { throw "Gate config invalid: $($gateProbe.Reason)" }
    Write-Host 'Gate config load: OK' -ForegroundColor Green
    if (-not (Test-Path -LiteralPath $script:RunnerPath)) { throw 'run-maigret.ps1 missing' }
    Write-Host 'Runner path: OK' -ForegroundColor Green
    Write-Host 'Self-test complete.' -ForegroundColor Green
}

function Start-GuidedSearch {
    if (-not (Test-OsintCaseContext)) { Write-OsintCaseRequired; return }
    Write-Host
    Write-Host 'New Maigret search' -ForegroundColor Cyan
    $user = (Read-Host 'Username (authorized target)').Trim()
    if (-not $user) { Write-Host 'Cancelled.' -ForegroundColor Yellow; return }
    $topText = (Read-Host 'Top sites [500] (0 = --all-sites)').Trim()
    $top = if ($topText) { [int]$topText } else { 500 }
    $html = Read-YesNo 'HTML + Markdown + JSON reports?' $true
    $graph = Read-YesNo 'Also write combined graph HTML (-G)?' $true
    $noRecursion = Read-YesNo 'Disable recursion (--no-recursion)?' $false

    $arguments = [System.Collections.Generic.List[string]]::new()
    $arguments.Add($user)
    if ($top -le 0) {
        $arguments.Add('--all-sites')
    }
    else {
        $arguments.Add('--top-sites'); $arguments.Add([string]$top)
    }
    if ($html) {
        $arguments.Add('-H')
        $arguments.Add('-M')
        $arguments.Add('-J'); $arguments.Add('simple')
    }
    if ($graph) { $arguments.Add('-G') }
    if ($env:OSINT_CASE_SESSION -and -not $html) {
        $arguments.Add('-J'); $arguments.Add('simple')
        Write-Host 'Case mode: a JSON report is also saved for automatic import.' -ForegroundColor Cyan
    }
    if ($noRecursion) { $arguments.Add('--no-recursion') }

    Write-Host
    Write-Host 'Review' -ForegroundColor Cyan
    Write-Host ("User       : {0}" -f $user)
    Write-Host ("Scope      : {0}" -f $(if ($top -le 0) { 'all sites' } else { "top $top" }))
    Write-Host ("Reports    : {0}" -f $(if ($html) { 'html/md/json' } else { 'console' }))
    Write-Host ("Graph      : {0}" -f $(if ($graph) { 'yes' } else { 'no' }))
    Write-Host ('Command    : run-maigret.ps1 ' + ($arguments -join ' ')) -ForegroundColor DarkGray
    Write-Host "Output     : $(if ($env:MAIGRET_OUTPUT) { $env:MAIGRET_OUTPUT } else { Join-Path (Get-OsintDataRoot) 'maigret' })"
    Write-Host 'Open HTML reports only in an isolated browser profile or VM, never your daily browser.' -ForegroundColor Yellow
    Write-Host

    if (-not (Confirm-NetworkReady)) {
        Write-Host 'Run cancelled. Maigret was not started.' -ForegroundColor Yellow
        return
    }

    Start-DockerIfNeeded
    Ensure-Images
    if (-not $env:MAIGRET_OUTPUT) {
        $env:MAIGRET_OUTPUT = Join-Path (Get-OsintDataRoot) 'maigret'
    }
    New-Item -ItemType Directory -Path $env:MAIGRET_OUTPUT -Force | Out-Null
    Write-Host 'Starting Squid sidecar and Maigret...' -ForegroundColor Cyan
    if ($env:OSINT_CASE_SESSION) {
        Invoke-CaseScan -ScanArguments $arguments.ToArray() -TargetLabel $user
    } else {
        & $script:RunnerPath @arguments
    }
}

function Show-MainMenu {
    while ($true) {
        Write-Host
        Write-Host 'Maigret (Hardened)' -ForegroundColor Cyan
        if ($env:OSINT_CASE_SESSION) { Write-Host "Case: $env:OSINT_CASE_ID | Each scan saves to $env:OSINT_CASE_RUNS\<run-id>\output" -ForegroundColor Cyan }
        Write-Host '1) New username search'
        Write-Host '2) Environment status / rebuild'
        Write-Host '3) Exit and close project environment'
        $choice = (Read-Host 'Select').Trim()
        switch ($choice) {
            '1' { Start-GuidedSearch }
            '2' {
                Show-Status
                if (Read-YesNo 'Rebuild images now?' $false) {
                    Start-DockerIfNeeded
                    $env:MAIGRET_BUILD_INPUTS = Get-MaigretBuildInputsHash -ProjectDirectory $projectDirectory
                    Push-Location $projectDirectory
                    try { docker compose build --pull } finally { Pop-Location }
                }
            }
            '3' {
                Stop-ProjectEnvironment
                if (Read-YesNo 'Also stop Docker Desktop?' $false) {
                    & docker desktop stop 2>$null
                }
                return
            }
            default { Write-Host 'Choose 1-3.' -ForegroundColor Yellow }
        }
    }
}

if ($CommandArgs -contains '--help' -or $CommandArgs -contains '-h') { Show-Help; exit 0 }
if ($CommandArgs -contains '--status') { Show-Status; exit 0 }
if ($CommandArgs -contains '--cleanup') { Stop-ProjectEnvironment; exit 0 }
if ($CommandArgs -contains '--selftest') { Invoke-SelfTest; exit 0 }

Show-MainMenu
