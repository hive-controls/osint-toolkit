[CmdletBinding()]
param([string]$Python = 'python')
$ErrorActionPreference = 'Stop'
$pwsh = Get-Command pwsh.exe -ErrorAction Stop
$resolved = & $Python -c 'import sys,sqlite3; assert sys.version_info >= (3,11); print(sys.executable)'
if ($LASTEXITCODE -ne 0 -or -not $resolved) { throw 'Python 3.11+ with sqlite3 is required.' }
$runtime = @{ python = [string]$resolved }
$runtimeFile = if ($env:OSINT_PROFILER_RUNTIME_FILE) { $env:OSINT_PROFILER_RUNTIME_FILE } else { Join-Path $PSScriptRoot 'runtime.json' }
$runtime | ConvertTo-Json | Set-Content -LiteralPath $runtimeFile -Encoding utf8
$installDir = Join-Path $env:LOCALAPPDATA 'Programs\OsintProfiler'
$shimPath = Join-Path $installDir 'osint-case.cmd'
$conflicts = @(Get-Command osint-case -All -ErrorAction SilentlyContinue | Where-Object { $_.Source -and $_.Source -ine $shimPath })
if ($conflicts.Count) { throw "An unrelated osint-case command already exists: $($conflicts.Source -join ', ')" }
[IO.Directory]::CreateDirectory($installDir) | Out-Null
$launcher = Join-Path $PSScriptRoot 'osint-case.ps1'
$shim = "@echo off`r`n`"$($pwsh.Source)`" -NoLogo -NoProfile -ExecutionPolicy Bypass -File `"$launcher`" %*`r`n"
[IO.File]::WriteAllText($shimPath, $shim, [Text.UTF8Encoding]::new($false))
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
$parts = @($userPath -split ';' | Where-Object { $_ })
if (-not ($parts | Where-Object { $_.TrimEnd('\') -ieq $installDir.TrimEnd('\') })) {
    [Environment]::SetEnvironmentVariable('Path', ((@($installDir) + $parts) -join ';'), 'User')
}
Write-Host "Installed: $shimPath"
Write-Host "Python: $resolved"
Write-Host 'In a new terminal, run: osint-case'
& $launcher doctor --offline
exit $LASTEXITCODE
