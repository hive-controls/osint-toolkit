<#
    OsintSubjectAuthorization.ps1

    Requires OsintNetworkGate.psm1 to be imported first (Test-OsintInformationalArguments).
    Dot-source after the gate module, like OsintProxyWiring.ps1:

        . (Join-Path $projectDirectory '..\shared\OsintSubjectAuthorization.ps1')

    Verifies the per-case subject-authorization sidecar written by `osint-case authorize`:
    cases/<id>/authorization.json under the OSINT data root. This is an accountability check,
    not a security boundary: the sidecar is derived from the case ledger and a local operator can
    edit it. Nothing here calls `exit`; the runner exits with the result's ExitCode (77 = refused).
#>

if (-not (Get-Command Get-OsintDataRoot -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'OsintTool.Common.ps1') }

$script:AuthorizationExitCode = 77
$script:AcknowledgementPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'OSINT Profiler\osint_profiler\ACKNOWLEDGEMENT.txt'
$script:CaseIdPattern = '^[a-z0-9][a-z0-9_-]{0,62}$'

function Test-OsintCaseContext {
    return [bool] ($env:OSINT_CASE_SESSION -or $env:OSINT_CASE_ID)
}

function Write-OsintCaseRequired {
    Write-Host 'Open a case first: osint-case new <id> --question "<question>" && osint-case authorize <id>' -ForegroundColor Yellow
}

function New-OsintAuthorizationResult {
    param(
        [Parameter(Mandatory)] [string] $Code,
        [string] $Reason = '',
        [bool] $Passed = $false,
        [bool] $Skipped = $false,
        [string] $CaseId = ''
    )

    $exitCode = if ($Passed -or $Skipped) { 0 } else { $script:AuthorizationExitCode }
    return [pscustomobject]@{ Passed = $Passed; Skipped = $Skipped; Code = $Code; Reason = $Reason; ExitCode = $exitCode; CaseId = $CaseId }
}

function Read-OsintSessionContext {
    $sessionFile = $env:OSINT_CASE_SESSION
    if (-not $sessionFile -or -not (Test-Path -LiteralPath $sessionFile)) { return $null }
    try { return Get-Content -LiteralPath $sessionFile -Raw | ConvertFrom-Json } catch { return $null }
}

function Resolve-OsintCaseLocation {
    $session = Read-OsintSessionContext
    $caseId = $env:OSINT_CASE_ID
    if (-not $caseId -and $session) { $caseId = [string] $session.case_id }
    $root = $env:OSINT_ROOT
    if (-not $root -and $session) { $root = [string] $session.root }
    if (-not $root) { $root = Get-OsintDataRoot }
    return [pscustomobject]@{ CaseId = $caseId; Root = $root }
}

function Read-OsintAuthorizationSidecar {
    param([Parameter(Mandatory)] [string] $Path)

    $fields = @{}
    $document = [System.Text.Json.JsonDocument]::Parse([IO.File]::ReadAllText($Path))
    try {
        if ($document.RootElement.ValueKind -ne 'Object') { throw 'Sidecar is not a JSON object.' }
        foreach ($property in $document.RootElement.EnumerateObject()) {
            $kind = $property.Value.ValueKind
            $fields[$property.Name] = if ($kind -eq 'String') { $property.Value.GetString() } elseif ($kind -eq 'True') { $true } elseif ($kind -eq 'False') { $false } else { $null }
        }
    }
    finally { $document.Dispose() }
    return $fields
}

function Get-OsintSidecarFailure {
    param([Parameter(Mandatory)] $Sidecar, [Parameter(Mandatory)] [string] $CaseId, [Parameter(Mandatory)] [string] $ShippedHash)

    foreach ($required in 'attestation_id', 'case_id', 'ack_version_hash', 'expires_ts') {
        if (-not ($Sidecar[$required] -is [string]) -or [string]::IsNullOrWhiteSpace($Sidecar[$required])) { return @{ Code = 'FAIL_UNREADABLE'; Reason = "Authorization sidecar is missing '$required'." } }
    }
    if ($Sidecar['revoked'] -isnot [bool]) { return @{ Code = 'FAIL_UNREADABLE'; Reason = "Authorization sidecar has no boolean 'revoked'." } }
    if ($Sidecar['case_id'] -ne $CaseId) { return @{ Code = 'FAIL_UNREADABLE'; Reason = 'Authorization sidecar belongs to a different case.' } }
    $expires = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParse($Sidecar['expires_ts'], [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal, [ref] $expires)) {
        return @{ Code = 'FAIL_UNREADABLE'; Reason = 'Authorization sidecar has an unreadable expiry.' }
    }
    if ($Sidecar['revoked']) { return @{ Code = 'FAIL_REVOKED'; Reason = 'The subject authorization for this case was revoked.' } }
    if ($expires -le [DateTimeOffset]::UtcNow) { return @{ Code = 'FAIL_EXPIRED'; Reason = 'The subject authorization for this case has expired.' } }
    if ($Sidecar['ack_version_hash'] -ne $ShippedHash) { return @{ Code = 'FAIL_STALE_ACK'; Reason = 'The acknowledgement text changed since this case was authorized.' } }
    return $null
}

function Assert-OsintSubjectAuthorization {
    param(
        [Parameter(Mandatory)] [ValidateSet('maigret', 'phone', 'torbot', 'scanner')] [string] $Tool,
        [AllowNull()] [AllowEmptyCollection()] [string[]] $Arguments
    )

    if (Test-OsintInformationalArguments -Tool $Tool -Arguments $Arguments) {
        return New-OsintAuthorizationResult -Code 'SKIP_INFORMATIONAL' -Skipped $true -Reason 'Informational invocation: no subject data sent.'
    }
    $location = Resolve-OsintCaseLocation
    if (-not $location.CaseId -or $location.CaseId -cnotmatch $script:CaseIdPattern) {
        return Write-OsintAuthorizationRefusal (New-OsintAuthorizationResult -Code 'FAIL_NO_CASE' -Reason 'No case is attached to this run.')
    }
    $caseId = $location.CaseId
    $path = Join-Path $location.Root "cases\$caseId\authorization.json"
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        return Write-OsintAuthorizationRefusal (New-OsintAuthorizationResult -Code 'FAIL_MISSING' -CaseId $caseId -Reason 'No subject authorization is recorded for this case.')
    }
    try {
        $sidecar = Read-OsintAuthorizationSidecar -Path $path
        $shippedHash = (Get-FileHash -LiteralPath $script:AcknowledgementPath -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    catch {
        return Write-OsintAuthorizationRefusal (New-OsintAuthorizationResult -Code 'FAIL_UNREADABLE' -CaseId $caseId -Reason "Authorization record could not be read: $($_.Exception.Message)")
    }
    $failure = Get-OsintSidecarFailure -Sidecar $sidecar -CaseId $caseId -ShippedHash $shippedHash
    if ($failure) {
        return Write-OsintAuthorizationRefusal (New-OsintAuthorizationResult -Code $failure.Code -CaseId $caseId -Reason $failure.Reason)
    }
    $env:OSINT_SUBJECT_AUTH = '{0}:{1}:{2}' -f $caseId, $sidecar['attestation_id'], $sidecar['ack_version_hash']
    return New-OsintAuthorizationResult -Code 'PASS' -Passed $true -CaseId $caseId -Reason 'Subject authorization verified.'
}

function Write-OsintAuthorizationRefusal {
    param([Parameter(Mandatory)] $Result)

    Write-Host 'SUBJECT AUTHORIZATION REQUIRED' -ForegroundColor Black -BackgroundColor Red
    Write-Host $Result.Reason -ForegroundColor Yellow
    $target = if ($Result.CaseId) { $Result.CaseId } else { '<case>' }
    Write-Host "Run: osint-case authorize $target" -ForegroundColor Yellow
    return $Result
}
