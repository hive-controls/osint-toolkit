[CmdletBinding(SupportsShouldProcess)]
param()

$ErrorActionPreference = 'Stop'
$installDirectory = Join-Path $env:LOCALAPPDATA 'Programs\TorBotLauncher'
$shimPath = Join-Path $installDirectory 'torbot.cmd'
$desktopPath = Join-Path ([Environment]::GetFolderPath('Desktop')) 'TorBot (Hardened).lnk'

if ($PSCmdlet.ShouldProcess($installDirectory, 'Remove TorBot launcher artifacts')) {
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
        # Keep gate config unless directory is otherwise empty of important files
        $remaining = Get-ChildItem -LiteralPath $installDirectory -Force -ErrorAction SilentlyContinue
        $onlyGate = @($remaining | Where-Object { $_.Name -ne 'torbot-gate.json' }).Count -eq 0
        if ($remaining.Count -eq 0 -or $onlyGate) {
            Remove-Item -LiteralPath $installDirectory -Recurse -Force
        }
    }
}

Write-Host 'TorBot launcher removed.' -ForegroundColor Green
Write-Host 'Docker images and crawl reports were not removed.'
