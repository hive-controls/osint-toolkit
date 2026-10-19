[CmdletBinding(SupportsShouldProcess)]
param()

$ErrorActionPreference = 'Stop'
$installDirectory = Join-Path $env:LOCALAPPDATA 'Programs\MaigretLauncher'
$shimPath = Join-Path $installDirectory 'maigret.cmd'
$desktopPath = Join-Path ([Environment]::GetFolderPath('Desktop')) 'Maigret (Hardened).lnk'

if ($PSCmdlet.ShouldProcess($installDirectory, 'Remove Maigret launcher artifacts')) {
    if (Test-Path -LiteralPath $shimPath) { Remove-Item -LiteralPath $shimPath -Force }
    if (Test-Path -LiteralPath $desktopPath) { Remove-Item -LiteralPath $desktopPath -Force }

    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if ($userPath) {
        $parts = @($userPath -split ';' | Where-Object {
                $_ -and ($_.TrimEnd('\') -ine $installDirectory.TrimEnd('\'))
            })
        [Environment]::SetEnvironmentVariable('Path', ($parts -join ';'), 'User')
    }

    if (Test-Path -LiteralPath $installDirectory) {
        $remaining = Get-ChildItem -LiteralPath $installDirectory -Force -ErrorAction SilentlyContinue
        if ($remaining.Count -eq 0) {
            Remove-Item -LiteralPath $installDirectory -Recurse -Force
        }
    }
}

Write-Host 'Maigret launcher removed.' -ForegroundColor Green
Write-Host 'Docker images, gate JSON, and reports were not removed.'
