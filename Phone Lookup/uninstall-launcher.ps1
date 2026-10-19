[CmdletBinding(SupportsShouldProcess)]
param()

$ErrorActionPreference = 'Stop'
$installDirectory = Join-Path $env:LOCALAPPDATA 'Programs\PhoneLookup'
$shimPath = Join-Path $installDirectory 'phone-lookup.cmd'
$desktopPath = Join-Path ([Environment]::GetFolderPath('Desktop')) 'Phone Lookup (Hardened).lnk'

if ($PSCmdlet.ShouldProcess($installDirectory, 'Remove phone-lookup launcher')) {
    if (Test-Path -LiteralPath $shimPath) { Remove-Item -LiteralPath $shimPath -Force }
    if (Test-Path -LiteralPath $desktopPath) { Remove-Item -LiteralPath $desktopPath -Force }
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if ($userPath) {
        $parts = @($userPath -split ';' | Where-Object {
                $_ -and ($_.TrimEnd('\') -ine $installDirectory.TrimEnd('\'))
            })
        [Environment]::SetEnvironmentVariable('Path', ($parts -join ';'), 'User')
    }
}

Write-Host 'Phone lookup launcher removed. secrets.json and reports were not deleted.'
