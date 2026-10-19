function Invoke-CaseScan {
    param([Parameter(Mandatory)][string[]]$ScanArguments, [string]$TargetLabel = '')
    if (-not $env:OSINT_CASE_SESSION) { throw 'No profiler case session is attached.' }
    $app = $PSScriptRoot
    $sessionDirectory = Split-Path -Parent $env:OSINT_CASE_SESSION
    $requests = Join-Path $sessionDirectory 'requests'
    [IO.Directory]::CreateDirectory($requests) | Out-Null
    $requestPath = Join-Path $requests (([guid]::NewGuid().ToString('N')) + '.json')
    @{ session_file = $env:OSINT_CASE_SESSION; arguments = @($ScanArguments); target = $TargetLabel } |
        ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $requestPath -Encoding utf8
    $runtimeFile = if ($env:OSINT_PROFILER_RUNTIME_FILE) { $env:OSINT_PROFILER_RUNTIME_FILE } else { Join-Path $app 'runtime.json' }
    $runtime = Get-Content -LiteralPath $runtimeFile -Raw | ConvertFrom-Json
    Push-Location $app
    try {
        & $runtime.python -m osint_profiler.native run $requestPath
        $code = $LASTEXITCODE
    } finally { Pop-Location }
    $resultPath = [IO.Path]::ChangeExtension($requestPath, '.result.json')
    if (Test-Path -LiteralPath $resultPath) {
        $result = Get-Content -LiteralPath $resultPath -Raw | ConvertFrom-Json
        $global:OsintCaseLastOutput = $result.output
    }
    $global:LASTEXITCODE = $code
}
