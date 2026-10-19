[CmdletBinding()]
param([Parameter(Mandatory)][string]$SessionFile)
$ErrorActionPreference = 'Stop'
$env:PYTHONUTF8 = '1'
$runtime = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'runtime.json') -Raw | ConvertFrom-Json
Push-Location $PSScriptRoot
try { & $runtime.python -m osint_profiler.native session $SessionFile; $code = $LASTEXITCODE }
finally { Pop-Location }
exit $code
