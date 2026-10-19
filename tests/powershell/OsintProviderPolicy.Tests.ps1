BeforeAll {
    $script:RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '..\..')
    . (Join-Path $script:RepoRoot 'shared\OsintProviderPolicy.ps1')
    $script:Sandbox = Join-Path ([IO.Path]::GetTempPath()) ("osint-provider-policy-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:Sandbox | Out-Null
    $script:TermsDirectory = Join-Path $script:Sandbox 'terms'
    New-Item -ItemType Directory -Path $script:TermsDirectory | Out-Null
    foreach ($provider in 'hudson_rock', 'dehashed') {
        [IO.File]::WriteAllText((Join-Path $script:TermsDirectory "$provider.txt"), "terms for $provider`n")
    }

    function script:Get-ExpectedVersion([string] $Provider) {
        $bytes = [Text.Encoding]::UTF8.GetBytes("terms for $Provider`n")
        ([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($bytes)) -replace '-', '').ToLowerInvariant()
    }
    function script:Write-ProvidersJson([hashtable] $Config) {
        $path = Join-Path $script:Sandbox ("providers-" + [guid]::NewGuid().ToString('N') + '.json')
        [IO.File]::WriteAllText($path, ($Config | ConvertTo-Json -Depth 5))
        return $path
    }
    function script:New-Entry([bool] $Enabled, [string] $Version) {
        $entry = @{ enabled = $Enabled }
        if ($Version) { $entry.terms_ack = @{ version = $Version; operator = 'tester'; ts = '2026-10-18T00:00:00Z' } }
        return $entry
    }
}

AfterAll {
    Remove-Item -LiteralPath $script:Sandbox -Recurse -Force -ErrorAction SilentlyContinue
}

Describe 'Get-OsintProviderTermsVersion' {
    It 'hashes LF-normalised bytes so CRLF checkouts match the Python side' {
        $crlf = Join-Path $script:Sandbox 'crlf.txt'
        [IO.File]::WriteAllText($crlf, "terms for hudson_rock`r`n")
        Get-OsintProviderTermsVersion -TermsFile $crlf | Should -BeExactly (Get-ExpectedVersion 'hudson_rock')
    }
}

Describe 'Get-OsintEnabledProviders' {
    It 'returns nothing when the file is missing' {
        @(Get-OsintEnabledProviders -Path (Join-Path $script:Sandbox 'absent.json') -TermsDirectory $script:TermsDirectory).Count | Should -Be 0
    }
    It 'omits disabled providers' {
        $path = Write-ProvidersJson @{ hudson_rock = (New-Entry $false (Get-ExpectedVersion 'hudson_rock')) }
        @(Get-OsintEnabledProviders -Path $path -TermsDirectory $script:TermsDirectory).Count | Should -Be 0
    }
    It 'emits name@version for enabled providers' {
        $path = Write-ProvidersJson @{
            hudson_rock = (New-Entry $true 'abc123')
            dehashed    = (New-Entry $false 'def456')
        }
        @(Get-OsintEnabledProviders -Path $path -TermsDirectory $script:TermsDirectory) | Should -Be @('hudson_rock@abc123')
    }
    It 'emits the bare name when no acknowledgement is recorded (the container rejects it as stale)' {
        $path = Write-ProvidersJson @{ dehashed = (New-Entry $true '') }
        @(Get-OsintEnabledProviders -Path $path -TermsDirectory $script:TermsDirectory) | Should -Be @('dehashed')
    }
    It 'ignores unknown provider names' {
        $path = Write-ProvidersJson @{ evilcorp = (New-Entry $true 'abc') }
        @(Get-OsintEnabledProviders -Path $path -TermsDirectory $script:TermsDirectory).Count | Should -Be 0
    }
    It 'fails closed on malformed JSON' {
        $path = Join-Path $script:Sandbox 'bad.json'
        [IO.File]::WriteAllText($path, '{not json')
        { Get-OsintEnabledProviders -Path $path -TermsDirectory $script:TermsDirectory } | Should -Throw
    }
}

Describe 'Test-OsintHudsonAllowed' {
    It 'is true only when hudson_rock is enabled with the current terms version' {
        $path = Write-ProvidersJson @{ hudson_rock = (New-Entry $true (Get-ExpectedVersion 'hudson_rock')) }
        Test-OsintHudsonAllowed -Path $path -TermsDirectory $script:TermsDirectory | Should -BeTrue
    }
    It 'is false for a stale acknowledgement' {
        $path = Write-ProvidersJson @{ hudson_rock = (New-Entry $true ('0' * 64)) }
        Test-OsintHudsonAllowed -Path $path -TermsDirectory $script:TermsDirectory | Should -BeFalse
    }
    It 'is false when disabled, absent, or only another provider is enabled' {
        $disabled = Write-ProvidersJson @{ hudson_rock = (New-Entry $false (Get-ExpectedVersion 'hudson_rock')) }
        $other = Write-ProvidersJson @{ dehashed = (New-Entry $true (Get-ExpectedVersion 'dehashed')) }
        Test-OsintHudsonAllowed -Path $disabled -TermsDirectory $script:TermsDirectory | Should -BeFalse
        Test-OsintHudsonAllowed -Path $other -TermsDirectory $script:TermsDirectory | Should -BeFalse
        Test-OsintHudsonAllowed -Path (Join-Path $script:Sandbox 'absent.json') -TermsDirectory $script:TermsDirectory | Should -BeFalse
    }
    It 'is false (not an exception) on malformed JSON' {
        $path = Join-Path $script:Sandbox 'bad2.json'
        [IO.File]::WriteAllText($path, '{not json')
        Test-OsintHudsonAllowed -Path $path -TermsDirectory $script:TermsDirectory | Should -BeFalse
    }
}

Describe 'argument classifiers' {
    It 'detects --hudson and unambiguous abbreviations' {
        Test-OsintHudsonRequested -Arguments @('-u', 'bob', '--hudson') | Should -BeTrue
        Test-OsintHudsonRequested -Arguments @('-u', 'bob', '--hud') | Should -BeTrue
        Test-OsintHudsonRequested -Arguments @('-u', 'bob', '--help') | Should -BeFalse
        Test-OsintHudsonRequested -Arguments @() | Should -BeFalse
    }
    It 'detects provider management arguments' {
        Test-OsintProviderManagementArguments -Arguments @('--providers', '--json') | Should -BeTrue
        Test-OsintProviderManagementArguments -Arguments @('--enable', 'hudson_rock', '--acknowledge-terms', 'x') | Should -BeTrue
        Test-OsintProviderManagementArguments -Arguments @('--disable', 'hudson_rock') | Should -BeTrue
        Test-OsintProviderManagementArguments -Arguments @('+14155552671', '--skip-hudson') | Should -BeFalse
    }
}

Describe 'launcher wiring' {
    BeforeAll {
        $script:Phone = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Phone Lookup\run-phone.ps1') -Raw
        $script:PhoneCompose = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Phone Lookup\compose.yaml') -Raw
        $script:Scanner = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'User-Scanner Docker\run-scanner.ps1') -Raw
        $script:ScannerCompose = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'User-Scanner Docker\compose.yaml') -Raw
        $script:Entrypoint = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'User-Scanner Docker\hardening\entrypoint.sh') -Raw
    }
    It 'run-phone.ps1 computes the provider list on the host and plumbs it through compose' {
        $script:Phone | Should -Match 'Get-OsintEnabledProviders'
        $script:Phone | Should -Match 'PHONE_LOOKUP_PROVIDERS'
        $script:Phone | Should -Match 'Invoke-OsintProviderManagement'
        $script:PhoneCompose | Should -Match 'PHONE_LOOKUP_PROVIDERS: \$\{PHONE_LOOKUP_PROVIDERS:-\}'
        $script:PhoneCompose | Should -Match 'PHONE_LOOKUP_REQUIRE_CASE: "1"'
    }
    It 'run-scanner.ps1 refuses --hudson with exit 78 unless the policy allows it' {
        $script:Scanner | Should -Match 'Test-OsintHudsonRequested'
        $script:Scanner | Should -Match 'Test-OsintHudsonAllowed'
        $script:Scanner | Should -Match 'exit 78'
        $script:Scanner | Should -Match 'phone-lookup --enable hudson_rock'
        $script:Scanner | Should -Match 'SCANNER_HUDSON_ALLOWED'
    }
    It 'the scanner container blocks --hudson unless SCANNER_HUDSON_ALLOWED=1' {
        $script:ScannerCompose | Should -Match 'SCANNER_HUDSON_ALLOWED: \$\{SCANNER_HUDSON_ALLOWED:-\}'
        $script:Entrypoint | Should -Match '--hu\*\)'
        $script:Entrypoint | Should -Match 'SCANNER_HUDSON_ALLOWED:-\}" != "1"'
        $script:Entrypoint | Should -Match 'exit 64'
    }
}
