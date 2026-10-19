BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..\..\shared\OsintNetworkGate.psm1') -Force
    . (Join-Path $PSScriptRoot '..\..\shared\OsintTool.Common.ps1')
    . (Join-Path $PSScriptRoot '..\..\shared\OsintSubjectAuthorization.ps1')
    $script:Sandbox = Join-Path ([IO.Path]::GetTempPath()) ("osint-authz-tests-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:Sandbox | Out-Null
    $script:ShippedHash = (Get-FileHash -LiteralPath (Join-Path $PSScriptRoot '..\..\OSINT Profiler\osint_profiler\ACKNOWLEDGEMENT.txt') -Algorithm SHA256).Hash.ToLowerInvariant()
    $script:SavedEnvironment = @{}
    foreach ($name in 'OSINT_CASE_ID', 'OSINT_CASE_SESSION', 'OSINT_ROOT', 'OSINT_SUBJECT_AUTH') { $script:SavedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name) }

    function script:Reset-AuthorizationEnvironment {
        $env:OSINT_ROOT = $script:Sandbox
        $env:OSINT_CASE_ID = 'case-a'
        Remove-Item Env:\OSINT_CASE_SESSION, Env:\OSINT_SUBJECT_AUTH -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath (Join-Path $script:Sandbox 'cases') -Recurse -Force -ErrorAction SilentlyContinue
    }

    function script:Write-Sidecar {
        param([string] $CaseId = 'case-a', [bool] $Revoked = $false, [string] $Expires = $null, [string] $Hash = $script:ShippedHash, [string] $Raw = $null)
        if (-not $Expires) { $Expires = [DateTimeOffset]::UtcNow.AddDays(30).ToString('yyyy-MM-ddTHH:mm:sszzz') }
        $folder = Join-Path $script:Sandbox "cases\$CaseId"
        New-Item -ItemType Directory -Path $folder -Force | Out-Null
        $text = if ($Raw) { $Raw } else {
            ([ordered]@{ attestation_id = 'att123'; case_id = $CaseId; ack_version_hash = $Hash; expires_ts = $Expires; revoked = $Revoked; subject_label = 'Subject A' } | ConvertTo-Json -Compress)
        }
        [IO.File]::WriteAllText((Join-Path $folder 'authorization.json'), $text, (New-Object System.Text.UTF8Encoding($false)))
    }
}

AfterAll {
    foreach ($name in $script:SavedEnvironment.Keys) { [Environment]::SetEnvironmentVariable($name, $script:SavedEnvironment[$name]) }
    Remove-Module OsintNetworkGate -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $script:Sandbox -Recurse -Force -ErrorAction SilentlyContinue
}

Describe 'Assert-OsintSubjectAuthorization' {
    BeforeEach { Reset-AuthorizationEnvironment }
    It 'passes a valid sidecar and exports the container attestation env' {
        Write-Sidecar
        $result = Assert-OsintSubjectAuthorization -Tool maigret -Arguments @('someone')
        $result.Passed | Should -BeTrue
        $result.Code | Should -Be 'PASS'
        $result.ExitCode | Should -Be 0
        $env:OSINT_SUBJECT_AUTH | Should -Be "case-a:att123:$script:ShippedHash"
    }
    It 'refuses with 77 when the sidecar is missing' {
        $result = Assert-OsintSubjectAuthorization -Tool maigret -Arguments @('someone')
        ($result.Passed -or $result.Skipped) | Should -BeFalse
        $result.Code | Should -Be 'FAIL_MISSING'
        $result.ExitCode | Should -Be 77
        $env:OSINT_SUBJECT_AUTH | Should -BeNullOrEmpty
    }
    It 'refuses when no case is attached' {
        Remove-Item Env:\OSINT_CASE_ID
        $result = Assert-OsintSubjectAuthorization -Tool scanner -Arguments @('-u', 'someone')
        $result.Code | Should -Be 'FAIL_NO_CASE'
        $result.ExitCode | Should -Be 77
    }
    It 'refuses an expired sidecar' {
        Write-Sidecar -Expires ([DateTimeOffset]::UtcNow.AddDays(-1).ToString('yyyy-MM-ddTHH:mm:sszzz'))
        $result = Assert-OsintSubjectAuthorization -Tool phone -Arguments @('+15555550100')
        $result.Code | Should -Be 'FAIL_EXPIRED'
        $result.ExitCode | Should -Be 77
    }
    It 'refuses a revoked sidecar' {
        Write-Sidecar -Revoked $true
        $result = Assert-OsintSubjectAuthorization -Tool torbot -Arguments @('http://example.onion')
        $result.Code | Should -Be 'FAIL_REVOKED'
        $result.ExitCode | Should -Be 77
    }
    It 'refuses a sidecar carrying a stale acknowledgement hash' {
        Write-Sidecar -Hash ('0' * 64)
        $result = Assert-OsintSubjectAuthorization -Tool maigret -Arguments @('someone')
        $result.Code | Should -Be 'FAIL_STALE_ACK'
        $result.ExitCode | Should -Be 77
    }
    It 'refuses an unparseable sidecar' {
        Write-Sidecar -Raw '{not json'
        (Assert-OsintSubjectAuthorization -Tool maigret -Arguments @('someone')).Code | Should -Be 'FAIL_UNREADABLE'
    }
    It 'refuses a sidecar that belongs to a different case' {
        Write-Sidecar -CaseId 'case-a'
        Write-Sidecar -CaseId 'case-b' -Raw (Get-Content -LiteralPath (Join-Path $script:Sandbox 'cases\case-a\authorization.json') -Raw)
        $env:OSINT_CASE_ID = 'case-b'
        (Assert-OsintSubjectAuthorization -Tool maigret -Arguments @('someone')).Code | Should -Be 'FAIL_UNREADABLE'
    }
    It 'refuses a case id that tries to leave the cases folder' {
        $env:OSINT_CASE_ID = '..\..\evil'
        (Assert-OsintSubjectAuthorization -Tool maigret -Arguments @('someone')).Code | Should -Be 'FAIL_NO_CASE'
    }
    It 'skips informational invocations without a case' {
        Remove-Item Env:\OSINT_CASE_ID
        $result = Assert-OsintSubjectAuthorization -Tool maigret -Arguments @('--help')
        $result.Skipped | Should -BeTrue
        $result.ExitCode | Should -Be 0
        (Assert-OsintSubjectAuthorization -Tool phone -Arguments @()).Skipped | Should -BeTrue
    }
    It 'derives the case from the session file when OSINT_CASE_ID is unset' {
        Remove-Item Env:\OSINT_CASE_ID
        Remove-Item Env:\OSINT_ROOT
        Write-Sidecar
        $session = Join-Path $script:Sandbox 'session.json'
        ([ordered]@{ case_id = 'case-a'; root = $script:Sandbox; tool = 'scanner'; id = 's1' } | ConvertTo-Json -Compress) | Set-Content -LiteralPath $session -Encoding utf8
        $env:OSINT_CASE_SESSION = $session
        (Assert-OsintSubjectAuthorization -Tool scanner -Arguments @('-u', 'someone')).Code | Should -Be 'PASS'
    }
}

Describe 'Test-OsintCaseContext' {
    BeforeEach { Reset-AuthorizationEnvironment }
    It 'is false with neither session nor case id' {
        Remove-Item Env:\OSINT_CASE_ID
        Test-OsintCaseContext | Should -BeFalse
    }
    It 'is true with a case id or a session' {
        Test-OsintCaseContext | Should -BeTrue
        Remove-Item Env:\OSINT_CASE_ID
        $env:OSINT_CASE_SESSION = 'C:\x\session.json'
        Test-OsintCaseContext | Should -BeTrue
    }
}
