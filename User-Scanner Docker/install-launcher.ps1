[CmdletBinding(SupportsShouldProcess)]
param(
    [switch] $Force
)

$ErrorActionPreference = 'Stop'
$projectDirectory = Split-Path -Parent $PSCommandPath
$launcherPath = Join-Path $projectDirectory 'scanner-menu.ps1'
$installDirectory = Join-Path $env:LOCALAPPDATA 'Programs\UserScannerLauncher'
$shimPath = Join-Path $installDirectory 'user-scanner.cmd'
$desktopPath = Join-Path ([Environment]::GetFolderPath('Desktop')) 'User Scanner (Hardened).lnk'

if (-not (Test-Path -LiteralPath $launcherPath)) {
    throw "Launcher not found: $launcherPath"
}
$pwsh = Get-Command pwsh.exe -ErrorAction SilentlyContinue
if (-not $pwsh) { throw 'PowerShell 7 (pwsh.exe) is required.' }

$conflicts = @(Get-Command user-scanner -All -ErrorAction SilentlyContinue | Where-Object {
    $_.Source -and [IO.Path]::GetFullPath($_.Source) -ne [IO.Path]::GetFullPath($shimPath)
})
if ($conflicts.Count -gt 0 -and -not $Force) {
    $locations = $conflicts | ForEach-Object Source | Sort-Object -Unique
    throw "An unrelated user-scanner command already exists at: $($locations -join ', '). Re-run with -Force only if you intend this launcher to take precedence."
}

if ($PSCmdlet.ShouldProcess($installDirectory, 'Install user-scanner command and desktop shortcut')) {
    [IO.Directory]::CreateDirectory($installDirectory) | Out-Null

    $escapedLauncher = $launcherPath.Replace('"', '""')
    $shim = "@echo off`r`npwsh.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File `"$escapedLauncher`" %*`r`n"
    [IO.File]::WriteAllText($shimPath, $shim, [Text.UTF8Encoding]::new($false))

    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $parts = @($userPath -split ';' | Where-Object { $_ })
    if (-not ($parts | Where-Object { $_.TrimEnd('\') -ieq $installDirectory.TrimEnd('\') })) {
        $newPath = (@($installDirectory) + $parts) -join ';'
        [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
    }
    if (-not (($env:Path -split ';') | Where-Object { $_.TrimEnd('\') -ieq $installDirectory.TrimEnd('\') })) {
        $env:Path = "$installDirectory;$env:Path"
    }

    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($desktopPath)
    $shortcut.TargetPath = $pwsh.Source
    $shortcut.Arguments = "-NoLogo -NoProfile -ExecutionPolicy Bypass -File `"$launcherPath`""
    $shortcut.WorkingDirectory = $projectDirectory
    $shortcut.Description = 'Hardened Docker launcher for User Scanner'
    $shortcut.IconLocation = "$($pwsh.Source),0"
    $shortcut.Save()
}

Write-Host 'User Scanner launcher installed.' -ForegroundColor Green
Write-Host "Command shim : $shimPath"
Write-Host "Desktop link : $desktopPath"
Write-Host "Project      : $projectDirectory"
Write-Host
Write-Host 'Open a new PowerShell window, then type: user-scanner' -ForegroundColor Cyan
Write-Host 'To close only this project environment: user-scanner --cleanup'

