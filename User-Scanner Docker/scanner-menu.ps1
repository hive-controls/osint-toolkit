[CmdletBinding()]
param(
    [switch] $SelfTest,
    [switch] $Status,
    [switch] $Cleanup,
    [Alias('help', 'h')]
    [switch] $ShowHelp
)

$ErrorActionPreference = 'Stop'
$script:ProjectDirectory = Split-Path -Parent $PSCommandPath
$script:RunnerPath = Join-Path $script:ProjectDirectory 'run-scanner.ps1'
. (Join-Path $script:ProjectDirectory '..\shared\OsintTool.Common.ps1')
Import-Module (Join-Path $script:ProjectDirectory '..\shared\OsintNetworkGate.psm1') -Force
. (Join-Path $script:ProjectDirectory '..\shared\OsintSubjectAuthorization.ps1')
$script:FavoriteDirectory = Get-OsintConfigDir -Tool 'UserScannerLauncher'
$script:FavoritePath = Join-Path $script:FavoriteDirectory 'favorites.json'
$script:ScannerImage = 'user-scanner-hardened:1.5.1.3'
$script:ProxyImage = 'user-scanner-egress-proxy:local'
if ($env:OSINT_CASE_SESSION) {
    . (Join-Path (Split-Path -Parent $script:ProjectDirectory) 'OSINT Profiler/Invoke-CaseScan.ps1')
}

function Write-LauncherHeader {
    param([string] $Subtitle = 'Guided Docker launcher')

    if (-not [Console]::IsOutputRedirected) {
        try { Clear-Host } catch { }
    }
    Write-Host ' USER SCANNER ' -ForegroundColor Black -BackgroundColor Cyan
    Write-Host " $Subtitle" -ForegroundColor DarkCyan
    Write-Host ('=' * 72) -ForegroundColor DarkGray
    if ($env:OSINT_CASE_SESSION) { Write-Host "Case: $env:OSINT_CASE_ID | Each scan saves to $env:OSINT_CASE_RUNS\<run-id>\output" -ForegroundColor Cyan }
}

function Write-Step {
    param(
        [int] $Number,
        [string] $Title,
        [string] $Description
    )

    Write-LauncherHeader "Step $Number of 4 - $Title"
    Write-Host $Description -ForegroundColor Gray
    Write-Host
}

function Read-MenuChoice {
    param(
        [Parameter(Mandatory)] [string] $Prompt,
        [Parameter(Mandatory)] [string[]] $Options,
        [int] $Default = 0
    )

    for ($i = 0; $i -lt $Options.Count; $i++) {
        $marker = if ($i -eq $Default) { '*' } else { ' ' }
        Write-Host ("  [{0}] {1} {2}" -f ($i + 1), $marker, $Options[$i])
    }

    while ($true) {
        $answer = Read-Host "$Prompt [$($Default + 1)]"
        if ([string]::IsNullOrWhiteSpace($answer)) {
            return $Default
        }

        $number = 0
        if ([int]::TryParse($answer, [ref] $number) -and $number -ge 1 -and $number -le $Options.Count) {
            return ($number - 1)
        }
        Write-Host "Choose a number from 1 to $($Options.Count)." -ForegroundColor Yellow
    }
}

function Read-YesNo {
    param(
        [Parameter(Mandatory)] [string] $Prompt,
        [bool] $Default = $false
    )

    $suffix = if ($Default) { '[Y/n]' } else { '[y/N]' }
    while ($true) {
        $answer = (Read-Host "$Prompt $suffix").Trim().ToLowerInvariant()
        if (-not $answer) { return $Default }
        if ($answer -in @('y', 'yes')) { return $true }
        if ($answer -in @('n', 'no')) { return $false }
        Write-Host 'Enter Y or N.' -ForegroundColor Yellow
    }
}

function Read-Number {
    param(
        [Parameter(Mandatory)] [string] $Prompt,
        [double] $Default,
        [double] $Minimum,
        [double] $Maximum,
        [switch] $Integer
    )

    while ($true) {
        $answer = Read-Host "$Prompt [$Default]"
        if ([string]::IsNullOrWhiteSpace($answer)) { return $Default }
        $value = 0.0
        if ([double]::TryParse($answer, [Globalization.NumberStyles]::Float,
                [Globalization.CultureInfo]::InvariantCulture, [ref] $value) -and
            $value -ge $Minimum -and $value -le $Maximum -and
            (-not $Integer -or $value -eq [math]::Truncate($value))) {
            return $value
        }
        Write-Host "Enter a value from $Minimum to $Maximum." -ForegroundColor Yellow
    }
}

function Read-MultiChoice {
    param(
        [Parameter(Mandatory)] [string] $Prompt,
        [Parameter(Mandatory)] [string[]] $Options
    )

    for ($i = 0; $i -lt $Options.Count; $i++) {
        Write-Host ("  [{0,2}] {1}" -f ($i + 1), $Options[$i])
    }
    while ($true) {
        $answer = Read-Host "$Prompt (comma-separated numbers, C to cancel)"
        if ($answer.Trim().ToUpperInvariant() -eq 'C') { return $null }
        $selected = [Collections.Generic.List[string]]::new()
        $valid = $true
        foreach ($part in ($answer -split ',')) {
            $number = 0
            if (-not [int]::TryParse($part.Trim(), [ref] $number) -or
                $number -lt 1 -or $number -gt $Options.Count) {
                $valid = $false
                break
            }
            if (-not $selected.Contains($Options[$number - 1])) {
                $selected.Add($Options[$number - 1])
            }
        }
        if ($valid -and $selected.Count -gt 0) { return $selected.ToArray() }
        Write-Host 'Choose one or more valid numbers.' -ForegroundColor Yellow
    }
}

function Get-ModuleCatalog {
    $wheel = Get-ChildItem -LiteralPath (Join-Path $script:ProjectDirectory 'artifacts\wheelhouse') `
        -Filter 'user_scanner-*.whl' | Select-Object -First 1
    if (-not $wheel) { throw 'The reviewed user-scanner wheel was not found.' }

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [IO.Compression.ZipFile]::OpenRead($wheel.FullName)
    try {
        $items = foreach ($entry in $zip.Entries) {
            if ($entry.FullName -match '^user_scanner/(?<kind>user_scan|email_scan)/(?<category>[^/]+)/(?<module>[^/]+)\.py$' -and
                $Matches.module -ne '__init__') {
                [pscustomobject]@{
                    ScanType = if ($Matches.kind -eq 'user_scan') { 'username' } else { 'email' }
                    Category = $Matches.category
                    Module = $Matches.module
                }
            }
        }
        return @($items | Sort-Object ScanType, Category, Module)
    }
    finally {
        $zip.Dispose()
    }
}

function New-DefaultConfiguration {
    return [pscustomobject]@{
        ScanType = 'username'
        InputMode = 'single'
        Hudson = $false
        ScopeType = 'all'
        ScopeValues = @()
        IncludeNsfw = $true
        AllowLoud = $false
        CrossScan = $false
        CrossLinks = 'verified'
        CrossEmails = 'verified'
        CrossDepth = 1
        CrossSweep = 0
        OutputFormat = 'terminal'
        DisplayMode = 'found'
        Pace = 'gentle'
        Stop = 100
        Timeout = 20
        Concurrency = 10
        Delay = 0.25
    }
}

function Copy-Configuration {
    param([Parameter(Mandatory)] $Configuration)

    $copy = New-DefaultConfiguration
    foreach ($property in $copy.PSObject.Properties.Name) {
        if ($Configuration.PSObject.Properties.Name -contains $property) {
            $copy.$property = $Configuration.$property
        }
    }
    $copy.ScopeValues = @($copy.ScopeValues)
    return $copy
}

function Get-OutputDirectory {
    if (-not $env:SCANNER_OUTPUT) {
        $env:SCANNER_OUTPUT = Join-Path (Get-OsintDataRoot) 'scanner'
    }
    return [IO.Path]::GetFullPath($env:SCANNER_OUTPUT)
}

function Resolve-BulkInput {
    param([Parameter(Mandatory)] [string] $Path)

    $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    $outputDirectory = Get-OutputDirectory
    [IO.Directory]::CreateDirectory($outputDirectory) | Out-Null
    $relative = [IO.Path]::GetRelativePath($outputDirectory, $resolved)
    if (-not $relative.StartsWith('..') -and -not [IO.Path]::IsPathRooted($relative)) {
        return "/output/$($relative.Replace('\', '/'))"
    }

    Write-Host
    Write-Host "Docker can only read files inside the output folder: $outputDirectory" -ForegroundColor Yellow
    if (-not (Read-YesNo "Copy '$resolved' into '$outputDirectory'?")) { return $null }
    $destination = Join-Path $outputDirectory ([IO.Path]::GetFileName($resolved))
    if (Test-Path -LiteralPath $destination) {
        $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        $destination = Join-Path $outputDirectory ("{0}-{1}{2}" -f
            [IO.Path]::GetFileNameWithoutExtension($resolved), $stamp, [IO.Path]::GetExtension($resolved))
    }
    Copy-Item -LiteralPath $resolved -Destination $destination
    Write-Host "Copied to $destination" -ForegroundColor Green
    return "/output/$([IO.Path]::GetFileName($destination))"
}

function Read-Target {
    param([Parameter(Mandatory)] $Configuration)

    if ($Configuration.InputMode -eq 'single') {
        while ($true) {
            $value = (Read-Host "Enter the $($Configuration.ScanType) to scan (C to cancel)").Trim()
            if ($value.ToUpperInvariant() -eq 'C') { return $null }
            if ($value) { return $value }
        }
    }

    while ($true) {
        $path = (Read-Host 'Enter the full path to the one-target-per-line file (C to cancel)').Trim('"', "'")
        if ($path.ToUpperInvariant() -eq 'C') { return $null }
        try {
            $containerPath = Resolve-BulkInput $path
            if ($containerPath) { return $containerPath }
        }
        catch {
            Write-Host $_.Exception.Message -ForegroundColor Yellow
        }
    }
}

function Set-TargetAndScope {
    param(
        [Parameter(Mandatory)] $Configuration,
        [Parameter(Mandatory)] [object[]] $Catalog
    )

    Write-Step 1 'Target & scope' 'Choose what kind of identifier to check and how broadly to check it.'
    $Configuration.ScanType = @('username', 'email')[(Read-MenuChoice 'Target type' @(
        'Username', 'Email address'))]
    $Configuration.InputMode = @('single', 'bulk')[(Read-MenuChoice 'Input mode' @(
        'One target', 'Batch file (one target per line)'))]

    $Configuration.Hudson = (Read-MenuChoice 'Scan mode' @(
        'Standard public-site scan',
        'Hudson Rock infostealer intelligence check')) -eq 1

    if ($Configuration.Hudson) {
        $Configuration.ScopeType = 'all'
        $Configuration.ScopeValues = @()
        Write-Host 'Hudson mode does not use normal module/category scope.' -ForegroundColor DarkGray
    }
    else {
        $scopeIndex = Read-MenuChoice 'Scope' @(
            'All available modules',
            'Selected categories',
            'Selected modules')
        $Configuration.ScopeType = @('all', 'categories', 'modules')[$scopeIndex]
        if ($Configuration.ScopeType -eq 'categories') {
            $categories = @($Catalog | Where-Object ScanType -eq $Configuration.ScanType |
                Select-Object -ExpandProperty Category -Unique | Sort-Object)
            $selection = Read-MultiChoice 'Select categories' $categories
            if (-not $selection) { return $null }
            $Configuration.ScopeValues = @($selection)
        }
        elseif ($Configuration.ScopeType -eq 'modules') {
            $needle = (Read-Host 'Optional module-name filter (Enter shows all)').Trim()
            $modules = @($Catalog | Where-Object {
                $_.ScanType -eq $Configuration.ScanType -and
                (-not $needle -or $_.Module -like "*$needle*")
            } | ForEach-Object { "$($_.Module) [$($_.Category)]" } | Sort-Object)
            if ($modules.Count -eq 0) {
                Write-Host 'No reviewed modules matched that filter.' -ForegroundColor Yellow
                return $null
            }
            $selection = Read-MultiChoice 'Select modules' $modules
            if (-not $selection) { return $null }
            $Configuration.ScopeValues = @($selection | ForEach-Object { ($_ -split ' \[')[0] })
        }
        else {
            $Configuration.ScopeValues = @()
        }
    }

    return Read-Target $Configuration
}

function Set-SafetyAndExpansion {
    param([Parameter(Mandatory)] $Configuration)

    Write-Step 2 'Safety & expansion' 'Standard includes adult/NSFW modules and still blocks loud (notification) modules and cross-scan pivots unless you customize.'
    $preset = Read-MenuChoice 'Safety profile' @(
        'Standard — NSFW on; loud/cross-scan off (recommended)',
        'Minimal — no NSFW; loud/cross-scan off',
        'Custom')
    if ($preset -eq 0) {
        $Configuration.IncludeNsfw = $true
        $Configuration.AllowLoud = $false
        $Configuration.CrossScan = $false
        $Configuration.CrossLinks = 'verified'
        $Configuration.CrossEmails = 'verified'
        $Configuration.CrossDepth = 1
        $Configuration.CrossSweep = 0
        return
    }
    if ($preset -eq 1) {
        $Configuration.IncludeNsfw = $false
        $Configuration.AllowLoud = $false
        $Configuration.CrossScan = $false
        $Configuration.CrossLinks = 'verified'
        $Configuration.CrossEmails = 'verified'
        $Configuration.CrossDepth = 1
        $Configuration.CrossSweep = 0
        return
    }

    $Configuration.IncludeNsfw = Read-YesNo 'Include adult/NSFW modules?' $true
    $Configuration.AllowLoud = Read-YesNo 'Allow loud modules that may send email, reset, or verification notifications?'
    if ($Configuration.AllowLoud) {
        Write-Host 'Loud modules may cause a third party to receive a notification.' -ForegroundColor Red
        Write-Host 'A typed LOUD acknowledgement will be required again immediately before execution.' -ForegroundColor Yellow
    }

    if ($Configuration.Hudson) {
        $Configuration.CrossScan = $false
        Write-Host 'Cross-scan is unavailable in Hudson mode.' -ForegroundColor DarkGray
        return
    }

    $Configuration.CrossScan = Read-YesNo 'Follow identifiers and links found by the first scan (cross-scan)?'
    if ($Configuration.CrossScan) {
        $Configuration.CrossLinks = @('verified', 'none', 'all')[(Read-MenuChoice 'Link pivots' @(
            'Verified platform connections only',
            'No link pivots',
            'All discovered links'))]
        $Configuration.CrossEmails = @('verified', 'none', 'all')[(Read-MenuChoice 'Email pivots' @(
            'Verified site-published addresses only',
            'No email pivots',
            'All discovered addresses'))]
        $Configuration.CrossDepth = [int](Read-Number 'Link-following rounds' 1 1 5 -Integer)
        $Configuration.CrossSweep = [int](Read-Number 'Targets allowed a full-module sweep' 0 0 25 -Integer)
    }
}

function Set-OutputAndPace {
    param([Parameter(Mandatory)] $Configuration)

    Write-Step 3 'Output & pace' 'Choose the report, terminal detail, and request pacing together.'
    $Configuration.OutputFormat = @('terminal', 'json', 'csv')[(Read-MenuChoice 'Report' @(
        'Terminal only',
        'JSON report',
        'CSV report'))]
    $Configuration.DisplayMode = @('found', 'foundurls', 'all')[(Read-MenuChoice 'Terminal detail' @(
        'Found results only',
        'Found results with URLs',
        'All results with URLs'))]

    $paceIndex = Read-MenuChoice 'Pace' @(
        'Gentle - 10 concurrent, 20s timeout, 0.25s delay',
        'Standard - scanner defaults',
        'Custom')
    $Configuration.Pace = @('gentle', 'standard', 'custom')[$paceIndex]
    if ($Configuration.Pace -eq 'gentle') {
        $Configuration.Stop = 100
        $Configuration.Timeout = 20
        $Configuration.Concurrency = 10
        $Configuration.Delay = 0.25
    }
    elseif ($Configuration.Pace -eq 'standard') {
        $Configuration.Stop = 100
        $Configuration.Timeout = $null
        $Configuration.Concurrency = $null
        $Configuration.Delay = 0
    }
    else {
        $Configuration.Stop = [int](Read-Number 'Maximum permutations' 100 1 1000 -Integer)
        $Configuration.Timeout = Read-Number 'Request timeout in seconds' 20 1 120
        $Configuration.Concurrency = [int](Read-Number 'Concurrent requests' 10 1 100 -Integer)
        $Configuration.Delay = Read-Number 'Delay between requests in seconds' 0.25 0 10
    }
}

function Get-SafeReportName {
    param(
        [Parameter(Mandatory)] $Configuration,
        [Parameter(Mandatory)] [string] $TargetValue
    )

    if ($Configuration.OutputFormat -eq 'terminal') { return $null }
    $basis = if ($Configuration.InputMode -eq 'bulk') {
        [IO.Path]::GetFileNameWithoutExtension($TargetValue)
    }
    else { $TargetValue }
    $basis = ($basis -replace '[^A-Za-z0-9._-]', '_').Trim('._-')
    if (-not $basis) { $basis = 'scan' }
    if ($basis.Length -gt 40) { $basis = $basis.Substring(0, 40) }
    return '{0}-{1}.{2}' -f $basis, (Get-Date -Format 'yyyyMMdd-HHmmss'), $Configuration.OutputFormat
}

function ConvertTo-ScannerArguments {
    param(
        [Parameter(Mandatory)] $Configuration,
        [Parameter(Mandatory)] [string] $TargetValue,
        [string] $ReportName
    )

    $arguments = [Collections.Generic.List[string]]::new()
    $targetFlag = if ($Configuration.ScanType -eq 'username') {
        if ($Configuration.InputMode -eq 'bulk') { '-uf' } else { '-u' }
    }
    else {
        if ($Configuration.InputMode -eq 'bulk') { '-ef' } else { '-e' }
    }
    $arguments.Add($targetFlag)
    $arguments.Add($TargetValue)

    if ($Configuration.Hudson) {
        $arguments.Add('--hudson')
    }
    elseif ($Configuration.ScopeType -eq 'categories' -and @($Configuration.ScopeValues).Count) {
        $arguments.Add('-c')
        $arguments.Add((@($Configuration.ScopeValues) -join ','))
    }
    elseif ($Configuration.ScopeType -eq 'modules' -and @($Configuration.ScopeValues).Count) {
        $arguments.Add('-m')
        $arguments.Add((@($Configuration.ScopeValues) -join ','))
    }

    if (-not $Configuration.IncludeNsfw) { $arguments.Add('--no-nsfw') }
    if ($Configuration.AllowLoud) { $arguments.Add('--allow-loud') }
    if ($Configuration.CrossScan) {
        $arguments.Add('--cross-scan')
        $arguments.Add('--cross-links'); $arguments.Add([string] $Configuration.CrossLinks)
        $arguments.Add('--cross-emails'); $arguments.Add([string] $Configuration.CrossEmails)
        $arguments.Add('--cross-depth'); $arguments.Add([string] $Configuration.CrossDepth)
        $arguments.Add('--cross-sweep'); $arguments.Add([string] $Configuration.CrossSweep)
    }

    if ($Configuration.DisplayMode -in @('foundurls', 'all')) { $arguments.Add('-v') }
    if ($Configuration.DisplayMode -eq 'all') { $arguments.Add('--all') }
    if ($null -ne $Configuration.Stop) { $arguments.Add('-s'); $arguments.Add([string] $Configuration.Stop) }
    if ($null -ne $Configuration.Timeout) { $arguments.Add('-t'); $arguments.Add([string] $Configuration.Timeout) }
    if ($null -ne $Configuration.Concurrency) { $arguments.Add('-C'); $arguments.Add([string] $Configuration.Concurrency) }
    if ($null -ne $Configuration.Delay -and [double] $Configuration.Delay -gt 0) {
        $arguments.Add('-d'); $arguments.Add([string] $Configuration.Delay)
    }
    if ($Configuration.OutputFormat -ne 'terminal') {
        $arguments.Add('-f'); $arguments.Add([string] $Configuration.OutputFormat)
        $arguments.Add('-o'); $arguments.Add("/output/$ReportName")
    }
    return $arguments.ToArray()
}

function ConvertTo-DisplayCommand {
    param([Parameter(Mandatory)] [string[]] $Arguments)

    $tokens = foreach ($argument in $Arguments) {
        if ($argument -match '[\s''"]') { "'$($argument.Replace("'", "''"))'" } else { $argument }
    }
    return '.\run-scanner.ps1 ' + ($tokens -join ' ')
}

function Get-Favorites {
    $slots = @($null, $null, $null, $null)
    if (-not (Test-Path -LiteralPath $script:FavoritePath)) {
        Write-Output -NoEnumerate $slots
        return
    }
    try {
        $saved = Get-Content -LiteralPath $script:FavoritePath -Raw | ConvertFrom-Json -NoEnumerate
        for ($i = 0; $i -lt [math]::Min(4, $saved.Count); $i++) { $slots[$i] = $saved[$i] }
    }
    catch {
        Write-Host "Favorites could not be read: $($_.Exception.Message)" -ForegroundColor Yellow
    }
    Write-Output -NoEnumerate $slots
}

function Save-Favorites {
    param([Parameter(Mandatory)] [AllowNull()] [object[]] $Slots)

    [IO.Directory]::CreateDirectory($script:FavoriteDirectory) | Out-Null
    ConvertTo-Json -InputObject @($Slots) -Depth 8 |
        Set-Content -LiteralPath $script:FavoritePath -Encoding utf8
}

function New-FavoriteRecord {
    param(
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] $Configuration
    )

    return [pscustomobject]@{
        Name = $Name
        Configuration = Copy-Configuration $Configuration
    }
}

function Save-FavoriteInteractively {
    param([Parameter(Mandatory)] $Configuration)

    if (-not (Read-YesNo 'Save these reusable settings as a favorite?')) { return }
    $slots = Get-Favorites
    $labels = for ($i = 0; $i -lt 4; $i++) {
        if ($null -eq $slots[$i]) { "Slot $($i + 1): Empty" }
        else { "Slot $($i + 1): $($slots[$i].Name)" }
    }
    $slot = Read-MenuChoice 'Favorite slot' $labels
    if ($null -ne $slots[$slot] -and -not (Read-YesNo 'Replace that favorite?')) { return }
    $name = (Read-Host 'Favorite name').Trim()
    if (-not $name) { $name = "Favorite $($slot + 1)" }
    $slots[$slot] = New-FavoriteRecord $name $Configuration
    Save-Favorites $slots
    Write-Host "Saved in slot $($slot + 1). Targets and report names were not saved." -ForegroundColor Green
}

function Show-ConfigurationReview {
    param(
        [Parameter(Mandatory)] $Configuration,
        [Parameter(Mandatory)] [string] $TargetValue,
        [Parameter(Mandatory)] [string[]] $Arguments,
        [string] $ReportName
    )

    Write-Step 4 'Review & run' 'Review the complete run before Docker or the scanner starts.'
    $targetDisplay = if ($Configuration.InputMode -eq 'bulk') { $TargetValue } else { $TargetValue }
    Write-Host ("Target       : {0} ({1}, {2})" -f $targetDisplay, $Configuration.ScanType, $Configuration.InputMode)
    Write-Host ("Mode / scope : {0} / {1} {2}" -f
        $(if ($Configuration.Hudson) { 'Hudson' } else { 'standard' }),
        $Configuration.ScopeType, (@($Configuration.ScopeValues) -join ', '))
    Write-Host ("Safety       : NSFW {0}; loud {1}; cross-scan {2}" -f
        $(if ($Configuration.IncludeNsfw) { 'ON' } else { 'OFF' }),
        $(if ($Configuration.AllowLoud) { 'ON' } else { 'OFF' }),
        $(if ($Configuration.CrossScan) { 'ON' } else { 'OFF' }))
    Write-Host ("Output       : {0}{1}; detail {2}; pace {3}" -f
        $Configuration.OutputFormat,
        $(if ($ReportName) { " ($ReportName)" } else { '' }),
        $Configuration.DisplayMode, $Configuration.Pace)
    Write-Host
    Write-Host 'Command:' -ForegroundColor DarkCyan
    Write-Host (ConvertTo-DisplayCommand $Arguments) -ForegroundColor Gray
}

function Confirm-NetworkReady {
    Write-Host
    Write-Host 'NETWORK SAFETY CHECK' -ForegroundColor Black -BackgroundColor Yellow
    Write-Host 'The built-in Squid service blocks LAN/metadata destinations.'
    Write-Host 'It does NOT hide or rotate your public IP; a host VPN is needed for that.'
    Write-Host
    $gate = Test-OsintNetworkGate -Tool scanner
    if (-not $gate.Passed) { return $false }
    $answer = Read-Host 'Type RUN to confirm network readiness and execute (anything else cancels)'
    return $answer -ceq 'RUN'
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
    if (-not (Test-ImagePresent $script:ScannerImage)) { $missing += $script:ScannerImage }
    if (-not (Test-ImagePresent $script:ProxyImage)) { $missing += $script:ProxyImage }
    if ($missing.Count -eq 0) { return }
    Write-Host "Missing image(s): $($missing -join ', ')" -ForegroundColor Yellow
    if (-not (Read-YesNo 'Build the pinned images now?' $true)) { throw 'Required Docker images are missing.' }
    Push-Location $script:ProjectDirectory
    try {
        & docker compose build
        if ($LASTEXITCODE -ne 0) { throw 'Docker image build failed.' }
    }
    finally { Pop-Location }
}

function Stop-ProjectEnvironment {
    param([switch] $OfferDockerStop)

    if (Test-DockerReady) {
        Push-Location $script:ProjectDirectory
        try { & docker compose down --remove-orphans }
        finally { Pop-Location }
        if ($OfferDockerStop -and (Read-YesNo 'Also stop Docker Desktop? This can affect other containers.')) {
            & docker desktop stop
        }
    }
    else {
        Write-Host 'Docker is not running; this project has no active environment to close.' -ForegroundColor DarkGray
    }
}

function Invoke-ReviewedRun {
    param(
        [Parameter(Mandatory)] $Configuration,
        [Parameter(Mandatory)] [string] $TargetValue
    )

    if ($env:OSINT_CASE_SESSION -and $Configuration.OutputFormat -eq 'terminal') {
        $Configuration = Copy-Configuration $Configuration
        $Configuration.OutputFormat = 'json'
    }
    $reportName = Get-SafeReportName $Configuration $TargetValue
    $arguments = ConvertTo-ScannerArguments $Configuration $TargetValue $reportName
    Show-ConfigurationReview $Configuration $TargetValue $arguments $reportName
    if ($env:OSINT_CASE_SESSION) { Write-Host 'Case mode: JSON/CSV is retained for automatic import; terminal detail is unchanged.' -ForegroundColor Cyan }
    Save-FavoriteInteractively $Configuration
    if ($Configuration.AllowLoud) {
        Write-Host
        Write-Host 'This run enables modules that may trigger third-party notifications.' -ForegroundColor Red
        if ((Read-Host 'Type LOUD to confirm this specific run') -cne 'LOUD') {
            Write-Host 'Run cancelled. The scanner was not started.' -ForegroundColor Yellow
            return
        }
    }
    if (-not (Confirm-NetworkReady)) {
        Write-Host 'Run cancelled. The scanner was not started.' -ForegroundColor Yellow
        return
    }

    Start-DockerIfNeeded
    Ensure-Images
    Write-Host 'Starting the filtered proxy and scanner...' -ForegroundColor Cyan
    if ($env:OSINT_CASE_SESSION) {
        Invoke-CaseScan -ScanArguments $arguments -TargetLabel $TargetValue
    } else {
        & $script:RunnerPath @arguments
    }
    $exitCode = $LASTEXITCODE
    if ($exitCode -eq 0) {
        Write-Host 'Run completed and this project environment was closed.' -ForegroundColor Green
        if ($reportName) {
            $reportDirectory = if ($env:OSINT_CASE_SESSION) { $global:OsintCaseLastOutput } else { Get-OutputDirectory }
            if ($reportDirectory) { Write-Host "Report: $(Join-Path $reportDirectory $reportName)" }
        }
    }
    else {
        Write-Host "Scanner exited with code $exitCode. Compose cleanup was still requested." -ForegroundColor Yellow
    }
    Read-Host 'Press Enter to return to the menu' | Out-Null
}

function Start-NewGuidedRun {
    param([Parameter(Mandatory)] [object[]] $Catalog)

    if (-not (Test-OsintCaseContext)) { Write-OsintCaseRequired; return }
    $configuration = New-DefaultConfiguration
    $targetValue = Set-TargetAndScope $configuration $Catalog
    if (-not $targetValue) { return }
    Set-SafetyAndExpansion $configuration
    Set-OutputAndPace $configuration
    Invoke-ReviewedRun $configuration $targetValue
}

function Start-FavoriteRun {
    if (-not (Test-OsintCaseContext)) { Write-OsintCaseRequired; return }
    $slots = Get-Favorites
    $available = @($slots | Where-Object { $null -ne $_ })
    if ($available.Count -eq 0) {
        Write-Host 'No favorites have been saved yet.' -ForegroundColor Yellow
        Read-Host 'Press Enter to continue' | Out-Null
        return
    }
    $labels = for ($i = 0; $i -lt 4; $i++) {
        if ($null -eq $slots[$i]) { "Slot $($i + 1): Empty" } else { "Slot $($i + 1): $($slots[$i].Name)" }
    }
    $slot = Read-MenuChoice 'Favorite' $labels
    if ($null -eq $slots[$slot]) { return }
    $configuration = Copy-Configuration $slots[$slot].Configuration
    $targetValue = Read-Target $configuration
    if (-not $targetValue) { return }
    Invoke-ReviewedRun $configuration $targetValue
}

function Manage-Favorites {
    while ($true) {
        Write-LauncherHeader 'Manage four target-free favorite configurations'
        $slots = Get-Favorites
        $labels = for ($i = 0; $i -lt 4; $i++) {
            if ($null -eq $slots[$i]) { "Slot $($i + 1): Empty" }
            else { "Slot $($i + 1): $($slots[$i].Name)" }
        }
        $choice = Read-MenuChoice 'Choose a slot to rename/delete, or go back' @(
            $labels[0], $labels[1], $labels[2], $labels[3], 'Back') 4
        if ($choice -eq 4) { return }
        if ($null -eq $slots[$choice]) {
            Write-Host 'That slot is empty; save it during a guided run.' -ForegroundColor Yellow
            Read-Host 'Press Enter to continue' | Out-Null
            continue
        }
        $action = Read-MenuChoice 'Action' @('Rename', 'Delete', 'Cancel') 2
        if ($action -eq 0) {
            $name = (Read-Host 'New favorite name').Trim()
            if ($name) { $slots[$choice].Name = $name; Save-Favorites $slots }
        }
        elseif ($action -eq 1 -and (Read-YesNo 'Delete this favorite?')) {
            $slots[$choice] = $null
            Save-Favorites $slots
        }
    }
}

function Show-EnvironmentMenu {
    param([switch] $NoPrompt)

    Write-LauncherHeader 'Environment status and maintenance'
    $dockerInstalled = $null -ne (Get-Command docker -ErrorAction SilentlyContinue)
    $dockerReady = $dockerInstalled -and (Test-DockerReady)
    Write-Host "Docker CLI    : $(if ($dockerInstalled) { 'found' } else { 'not found' })"
    Write-Host "Docker engine : $(if ($dockerReady) { 'ready' } else { 'not ready' })"
    if ($dockerReady) {
        Write-Host "Scanner image : $(if (Test-ImagePresent $script:ScannerImage) { 'present' } else { 'missing' })"
        Write-Host "Proxy image   : $(if (Test-ImagePresent $script:ProxyImage) { 'present' } else { 'missing' })"
    }
    Write-Host "Reports       : $(Get-OutputDirectory)"
    Write-Host "Favorites     : $script:FavoritePath"
    if ($NoPrompt) { return }
    Write-Host
    $action = Read-MenuChoice 'Maintenance' @(
        'Back',
        'Start/check Docker and ensure images',
        'Rebuild pinned images',
        'Close this project environment')
    switch ($action) {
        1 { Start-DockerIfNeeded; Ensure-Images }
        2 {
            Start-DockerIfNeeded
            Push-Location $script:ProjectDirectory
            try { & docker compose build --no-cache; if ($LASTEXITCODE -ne 0) { throw 'Rebuild failed.' } }
            finally { Pop-Location }
        }
        3 { Stop-ProjectEnvironment }
    }
    if ($action -ne 0) { Read-Host 'Press Enter to continue' | Out-Null }
}

function Invoke-SelfTest {
    $catalog = @(Get-ModuleCatalog)
    if ($catalog.Count -lt 10) { throw 'Catalog self-test failed.' }
    if (-not ($catalog | Where-Object { $_.ScanType -eq 'username' -and $_.Module -eq 'github' })) {
        throw 'Reviewed GitHub module was not found in the wheel catalog.'
    }
    $configuration = New-DefaultConfiguration
    $configuration.ScopeType = 'modules'
    $configuration.ScopeValues = @('github')
    $configuration.OutputFormat = 'json'
    $configuration.IncludeNsfw = $false
    $arguments = ConvertTo-ScannerArguments $configuration 'synthetic-test-target' 'self-test.json'
    foreach ($required in @('-u', 'synthetic-test-target', '-m', 'github', '--no-nsfw', '-f', 'json', '-o', '/output/self-test.json')) {
        if ($arguments -notcontains $required) { throw "Argument self-test failed: $required" }
    }
    $favorite = New-FavoriteRecord 'Self test' $configuration
    if ($favorite.PSObject.Properties.Name -contains 'TargetValue' -or
        $favorite.Configuration.PSObject.Properties.Name -contains 'TargetValue') {
        throw 'Favorite privacy self-test failed.'
    }
    $slotTest = @($null, $favorite, $null, $null)
    $restored = ConvertTo-Json -InputObject $slotTest -Depth 8 | ConvertFrom-Json -NoEnumerate
    if ($restored.Count -ne 4 -or $null -ne $restored[0] -or $restored[1].Name -ne 'Self test') {
        throw 'Four-slot favorite serialization self-test failed.'
    }
    Write-Host "PASS: catalog ($($catalog.Count) modules), argument mapping, four-slot serialization, and target-free favorite schema."
}

if ($ShowHelp) {
    @'
user-scanner - guided launcher for the hardened Docker environment

  user-scanner              Open the interactive menu
  user-scanner --status     Show environment status
  user-scanner --cleanup    Close this project's Compose environment
  user-scanner --selftest   Validate the launcher without Docker or a scan

No real scan starts until the final VPN/proxy reminder is confirmed by typing RUN.
'@ | Write-Host
    exit 0
}
if ($SelfTest) { Invoke-SelfTest; exit 0 }
if ($Cleanup) { Stop-ProjectEnvironment; exit 0 }
if ($Status) {
    Show-EnvironmentMenu -NoPrompt
    exit 0
}

$catalog = @(Get-ModuleCatalog)
while ($true) {
    Write-LauncherHeader
    $choice = Read-MenuChoice 'Main menu' @(
        'New guided run',
        'Run a favorite',
        'Manage favorites',
        'Environment status / rebuild',
        'Exit and close this project environment')
    try {
        switch ($choice) {
            0 { Start-NewGuidedRun $catalog }
            1 { Start-FavoriteRun }
            2 { Manage-Favorites }
            3 { Show-EnvironmentMenu }
            4 { Stop-ProjectEnvironment -OfferDockerStop; exit 0 }
        }
    }
    catch {
        Write-Host
        Write-Host "Launcher error: $($_.Exception.Message)" -ForegroundColor Red
        Read-Host 'Press Enter to return to the menu' | Out-Null
    }
}
