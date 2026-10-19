[CmdletBinding()]
param([Parameter(Mandatory)][string]$PlanFile)
$ErrorActionPreference = 'Stop'
$logPath = Join-Path (Split-Path -Parent $PlanFile) 'console.log'
Start-Transcript -LiteralPath $logPath -Force | Out-Null
$code = 1
try {
    & (Join-Path $PSScriptRoot 'run-reviewed-scan.ps1') -PlanFile $PlanFile
    $code = $LASTEXITCODE
} finally { Stop-Transcript | Out-Null }
exit $code
