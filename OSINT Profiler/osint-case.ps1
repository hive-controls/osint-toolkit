$ErrorActionPreference = 'Stop'
$env:PYTHONUTF8 = '1'
$runtimeFile = Join-Path $PSScriptRoot 'runtime.json'
if (-not (Test-Path -LiteralPath $runtimeFile)) { throw 'Run install.ps1 to select the Python runtime.' }
$runtime = Get-Content -LiteralPath $runtimeFile -Raw | ConvertFrom-Json
Push-Location $PSScriptRoot
try {
    & $runtime.python -m osint_profiler @args
    $result = $LASTEXITCODE
} finally { Pop-Location }
exit $result
