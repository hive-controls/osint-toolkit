[CmdletBinding(SupportsShouldProcess)]
param(
    [switch] $Force
)

$ErrorActionPreference = 'Stop'
$projectDirectory = Split-Path -Parent $PSCommandPath
$launcherPath = Join-Path $projectDirectory 'phone-menu.ps1'
$installDirectory = Join-Path $env:LOCALAPPDATA 'Programs\PhoneLookup'
$shimPath = Join-Path $installDirectory 'phone-lookup.cmd'
$desktopPath = Join-Path ([Environment]::GetFolderPath('Desktop')) 'Phone Lookup (Hardened).lnk'
$gateExample = Join-Path $projectDirectory 'gate\phone-gate.example.json'
$gateDest = Join-Path $env:LOCALAPPDATA 'PhoneLookup\phone-gate.json'
$secretsExample = Join-Path $projectDirectory 'secrets.example.json'
$secretsDest = Join-Path $env:LOCALAPPDATA 'PhoneLookup\secrets.json'

if (-not (Test-Path -LiteralPath $launcherPath)) { throw "Launcher not found: $launcherPath" }
$pwsh = Get-Command pwsh.exe -ErrorAction SilentlyContinue
if (-not $pwsh) { throw 'PowerShell 7 (pwsh.exe) is required.' }

$conflicts = @(Get-Command phone-lookup -All -ErrorAction SilentlyContinue | Where-Object {
        $_.Source -and [IO.Path]::GetFullPath($_.Source) -ne [IO.Path]::GetFullPath($shimPath)
    })
if ($conflicts.Count -gt 0 -and -not $Force) {
    throw "An unrelated phone-lookup command already exists. Re-run with -Force to take precedence."
}

if ($PSCmdlet.ShouldProcess($installDirectory, 'Install phone-lookup command')) {
    [IO.Directory]::CreateDirectory($installDirectory) | Out-Null
    [IO.Directory]::CreateDirectory((Split-Path $gateDest)) | Out-Null
    $escapedLauncher = $launcherPath.Replace('"', '""')
    $shim = "@echo off`r`npwsh.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File `"$escapedLauncher`" %*`r`n"
    [IO.File]::WriteAllText($shimPath, $shim, [Text.UTF8Encoding]::new($false))
    if (-not (Test-Path -LiteralPath $gateDest)) {
        Copy-Item -LiteralPath $gateExample -Destination $gateDest
    }
    if (-not (Test-Path -LiteralPath $secretsDest)) {
        Copy-Item -LiteralPath $secretsExample -Destination $secretsDest
    }
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $parts = @($userPath -split ';' | Where-Object { $_ })
    if (-not ($parts | Where-Object { $_.TrimEnd('\') -ieq $installDirectory.TrimEnd('\') })) {
        [Environment]::SetEnvironmentVariable('Path', ((@($installDirectory) + $parts) -join ';'), 'User')
    }
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($desktopPath)
    $shortcut.TargetPath = $pwsh.Source
    $shortcut.Arguments = "-NoLogo -NoProfile -ExecutionPolicy Bypass -File `"$launcherPath`""
    $shortcut.WorkingDirectory = $projectDirectory
    $shortcut.Description = 'Hardened Docker phone lookup (jobs 1 and 4)'
    $shortcut.Save()
}

Write-Host 'Phone lookup launcher installed.' -ForegroundColor Green
Write-Host "Command : $shimPath"
Write-Host "Secrets : $secretsDest"
Write-Host 'Open a new PowerShell window, then type: phone-lookup'
