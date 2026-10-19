[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $CommandArgs
)

$ErrorActionPreference = 'Stop'
$projectDirectory = Split-Path -Parent $PSCommandPath
$script:RunnerPath = Join-Path $projectDirectory 'run-torbot.ps1'
$script:TorImage = 'torbot-hardened:4.3.0'
$script:TorDaemonImage = 'torbot-tor:local'

Import-Module (Join-Path (Split-Path -Parent $projectDirectory) 'shared\OsintNetworkGate.psm1') -Force
. (Join-Path $projectDirectory '..\shared\OsintTool.Common.ps1')
. (Join-Path $projectDirectory '..\shared\OsintSubjectAuthorization.ps1')

function Show-Help {
    Write-Host @'
torbot - guided launcher for the hardened TorBot Docker environment

  torbot                 Open the interactive menu
  torbot --status        Show environment status
  torbot --cleanup       Close this project's Compose environment
  torbot --selftest      Validate launcher wiring without a crawl
  torbot --help          Show this help

Crawls require: VPN/proxy gate PASS + typing RUN.
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
    $missing = @()
    foreach ($image in @($script:TorImage, $script:TorDaemonImage)) {
        if (-not (Test-ImagePresent $image)) { $missing += $image }
    }
    if ($missing.Count -eq 0) { return }
    Write-Host ("Missing images: {0}" -f ($missing -join ', ')) -ForegroundColor Yellow
    if (-not (Read-YesNo 'Build the pinned images now?' $true)) {
        throw 'Required Docker images are missing.'
    }
    Push-Location $projectDirectory
    try {
        docker compose build --pull
        if ($LASTEXITCODE -ne 0) { throw 'docker compose build failed.' }
    }
    finally { Pop-Location }
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
    Write-Host '2) Typed RUN: confirm you accept Tor SOCKS egress for this crawl.' -ForegroundColor Yellow
    Write-Host 'Tor exit IP != host VPN. The app can only reach the Tor sidecar.' -ForegroundColor DarkGray
    Write-Host

    $gate = Test-OsintNetworkGate -Tool torbot
    if (-not $gate.Passed) {
        return $false
    }

    $answer = Read-Host 'Type RUN to confirm and execute (anything else cancels)'
    return $answer -ceq 'RUN'
}

function Show-Status {
    Start-DockerIfNeeded
    Write-Host "Project       : $projectDirectory"
    Write-Host "TorBot image  : $(if (Test-ImagePresent $script:TorImage) { 'present' } else { 'missing' }) ($script:TorImage)"
    Write-Host "Tor image     : $(if (Test-ImagePresent $script:TorDaemonImage) { 'present' } else { 'missing' }) ($script:TorDaemonImage)"
    Write-Host "Output dir    : $(if ($env:TORBOT_OUTPUT) { $env:TORBOT_OUTPUT } else { Join-Path (Get-OsintDataRoot) 'torbot' })"
    $gate = Test-OsintNetworkGate -Tool torbot -Quiet
    Write-Host ("Network gate  : {0} ({1})" -f $(if ($gate.Passed) { 'PASS' } else { 'FAIL' }), $gate.Reason)
}

function Invoke-SelfTest {
    Write-Host 'Self-test (no crawl, no Docker required for gate module)...' -ForegroundColor Cyan
    $gateProbe = Test-OsintNetworkGate -Tool torbot -Quiet
    if ($gateProbe.Code -eq 'FAIL_CONFIG') { throw "Gate config invalid: $($gateProbe.Reason)" }
    Write-Host 'Gate config load: OK' -ForegroundColor Green
    if (-not (Test-Path -LiteralPath $script:RunnerPath)) { throw 'run-torbot.ps1 missing' }
    Write-Host 'Runner path: OK' -ForegroundColor Green
    Write-Host 'Self-test complete.' -ForegroundColor Green
}

function Start-GuidedCrawl {
    if (-not (Test-OsintCaseContext)) { Write-OsintCaseRequired; return }
    Write-Host
    Write-Host 'New TorBot crawl' -ForegroundColor Cyan
    $url = (Read-Host 'Target URL (.onion or clearnet via Tor)').Trim()
    if (-not $url) { Write-Host 'Cancelled.' -ForegroundColor Yellow; return }
    $depthText = (Read-Host 'Crawl depth [1]').Trim()
    $depth = if ($depthText) { [int]$depthText } else { 1 }
    $save = Read-YesNo 'Save JSON tree to /output?' $true
    $info = Read-YesNo 'Also request --info?' $false

    $arguments = [System.Collections.Generic.List[string]]::new()
    $arguments.Add('-u'); $arguments.Add($url)
    $arguments.Add('--depth'); $arguments.Add([string]$depth)
    if ($save) {
        $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        $arguments.Add('--save'); $arguments.Add('json')
        # TorBot save path is tool-defined; output bind is /output
    }
    if ($info) { $arguments.Add('--info') }

    Write-Host
    Write-Host 'Review' -ForegroundColor Cyan
    Write-Host ("URL    : {0}" -f $url)
    Write-Host ("Depth  : {0}" -f $depth)
    Write-Host ("Save   : {0}" -f $(if ($save) { 'json' } else { 'no' }))
    Write-Host ("Info   : {0}" -f $(if ($info) { 'yes' } else { 'no' }))
    Write-Host ('Command: run-torbot.ps1 ' + ($arguments -join ' ')) -ForegroundColor DarkGray
    Write-Host

    if (-not (Confirm-NetworkReady)) {
        Write-Host 'Run cancelled. TorBot was not started.' -ForegroundColor Yellow
        return
    }

    Start-DockerIfNeeded
    Ensure-Images
    if (-not $env:TORBOT_OUTPUT) {
        $env:TORBOT_OUTPUT = Join-Path (Get-OsintDataRoot) 'torbot'
    }
    New-Item -ItemType Directory -Path $env:TORBOT_OUTPUT -Force | Out-Null
    Write-Host 'Starting Tor sidecar and TorBot...' -ForegroundColor Cyan
    # The runner re-checks the gate at launch, closing the menu-to-launch window.
    & $script:RunnerPath @arguments
}

function Show-MainMenu {
    while ($true) {
        Write-Host
        Write-Host 'TorBot (Hardened)' -ForegroundColor Cyan
        Write-Host '1) New crawl'
        Write-Host '2) Environment status / rebuild'
        Write-Host '3) Exit and close project environment'
        $choice = (Read-Host 'Select').Trim()
        switch ($choice) {
            '1' { Start-GuidedCrawl }
            '2' {
                Show-Status
                if (Read-YesNo 'Rebuild images now?' $false) {
                    Start-DockerIfNeeded
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

# Entry
if ($CommandArgs -contains '--help' -or $CommandArgs -contains '-h') { Show-Help; exit 0 }
if ($CommandArgs -contains '--status') { Show-Status; exit 0 }
if ($CommandArgs -contains '--cleanup') { Stop-ProjectEnvironment; exit 0 }
if ($CommandArgs -contains '--selftest') { Invoke-SelfTest; exit 0 }

Show-MainMenu
