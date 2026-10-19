[CmdletBinding(SupportsShouldProcess)]
param(
    [switch] $RemoveFavorites
)

$ErrorActionPreference = 'Stop'
$installDirectory = Join-Path $env:LOCALAPPDATA 'Programs\UserScannerLauncher'
$shimPath = Join-Path $installDirectory 'user-scanner.cmd'
$desktopPath = Join-Path ([Environment]::GetFolderPath('Desktop')) 'User Scanner (Hardened).lnk'
$favoriteDirectory = Join-Path $env:LOCALAPPDATA 'UserScannerLauncher'

if ($PSCmdlet.ShouldProcess('User Scanner launcher artifacts', 'Uninstall')) {
    if (Test-Path -LiteralPath $shimPath) { Remove-Item -LiteralPath $shimPath -Force }
    if (Test-Path -LiteralPath $desktopPath) { Remove-Item -LiteralPath $desktopPath -Force }
    if (Test-Path -LiteralPath $installDirectory) {
        $remaining = @(Get-ChildItem -LiteralPath $installDirectory -Force)
        if ($remaining.Count -eq 0) { Remove-Item -LiteralPath $installDirectory -Force }
    }

    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $kept = @($userPath -split ';' | Where-Object {
        $_ -and $_.TrimEnd('\') -ine $installDirectory.TrimEnd('\')
    })
    [Environment]::SetEnvironmentVariable('Path', ($kept -join ';'), 'User')

    if ($RemoveFavorites -and (Test-Path -LiteralPath $favoriteDirectory)) {
        Remove-Item -LiteralPath $favoriteDirectory -Recurse -Force
    }
}

Write-Host 'User Scanner launcher removed.' -ForegroundColor Green
if (-not $RemoveFavorites -and (Test-Path -LiteralPath $favoriteDirectory)) {
    Write-Host "Favorites preserved at: $favoriteDirectory"
}
Write-Host 'Docker images and scan reports were not removed.'

