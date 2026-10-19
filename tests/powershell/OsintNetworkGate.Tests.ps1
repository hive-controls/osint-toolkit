BeforeAll {
    $script:ModulePath = Join-Path $PSScriptRoot '..\..\shared\OsintNetworkGate.psm1'
    Import-Module $script:ModulePath -Force
    $script:Sandbox = Join-Path ([IO.Path]::GetTempPath()) ("osint-gate-tests-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:Sandbox | Out-Null
    $script:ExampleConfig = Join-Path $script:ModulePath '..\gate\osint-gate.example.json' | Resolve-Path | Select-Object -ExpandProperty Path

    function script:New-GateConfig {
        param([string] $Name, [string] $Json)
        $path = Join-Path $script:Sandbox $Name
        Set-Content -LiteralPath $path -Value $Json -Encoding utf8
        return $path
    }
}

AfterAll {
    Remove-Module OsintNetworkGate -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $script:Sandbox -Recurse -Force -ErrorAction SilentlyContinue
}

Describe 'Invoke-OsintGateCore decisions' {
    BeforeAll {
        $script:Config = New-GateConfig -Name 'good.json' -Json '{"schemaVersion":1,"vpnNamePatterns":["WireGuard","Mullvad"],"proxyUrls":[]}'
        $script:AdapterSample = @(
            @{ Index = 62; Name = 'peer'; Description = 'WireGuard Tunnel' },
            @{ Index = 9; Name = 'Ethernet'; Description = 'Realtek PCIe 5GbE Family Controller' },
            @{ Index = 44; Name = 'Tailscale'; Description = 'Tailscale Tunnel' }
        )
    }

    BeforeEach {
        $script:Ledger = Join-Path $script:Sandbox ([guid]::NewGuid().ToString('N') + '.jsonl')
    }

    function script:New-FakeProvider {
        param($RouteIndex, $Adapters, [string] $Platform = 'Windows', [switch] $NullRoute, [switch] $ThrowOnRoute)
        $routeValue = if ($NullRoute) { $null } else { @{ Index = $RouteIndex; Alias = 'fake-alias' } }
        $adapterValue = $Adapters
        $throwing = [bool] $ThrowOnRoute
        $platformName = $Platform
        return @{
            GetPlatformName          = { $platformName }.GetNewClosure()
            GetDefaultRouteInterface = { if ($throwing) { throw 'route table unavailable' }; $routeValue }.GetNewClosure()
            GetUpAdapters            = { $adapterValue }.GetNewClosure()
        }
    }

    function script:Invoke-Core {
        [CmdletBinding()]
        param($Provider, [string] $Tool = 'phone', [string[]] $Candidates, [string] $LedgerFile)
        $captured = @{ Provider = $Provider; Tool = $Tool; Candidates = $Candidates; Ledger = $LedgerFile }
        InModuleScope OsintNetworkGate -Parameters @{ Captured = $captured } {
            Invoke-OsintGateCore -Tool $Captured.Tool -Provider $Captured.Provider -ConfigCandidates $Captured.Candidates -LedgerPath $Captured.Ledger
        }
    }

    It 'passes when a matching adapter owns the default route' {
        $provider = New-FakeProvider -RouteIndex 62 -Adapters $script:AdapterSample
        $result = Invoke-Core -Provider $provider -Candidates @($script:Config) -LedgerFile $script:Ledger
        $result.Passed | Should -BeTrue
        $result.Code | Should -Be 'PASS_VPN_ROUTE'
        $result.Route.InterfaceIndex | Should -Be 62
        $result.Route.AdapterDescription | Should -Be 'WireGuard Tunnel'
        $result.Evidence.Count | Should -Be 3
        $result.PSObject.TypeNames[0] | Should -Be 'Osint.GateResult'
        $result.SchemaVersion | Should -Be 1
    }

    It 'fails FAIL_ADAPTER_NOT_ROUTING when the matching adapter is up but another interface owns the route' {
        $provider = New-FakeProvider -RouteIndex 9 -Adapters $script:AdapterSample
        $result = Invoke-Core -Provider $provider -Candidates @($script:Config) -LedgerFile $script:Ledger
        $result.Passed | Should -BeFalse
        $result.Code | Should -Be 'FAIL_ADAPTER_NOT_ROUTING'
    }

    It 'fails FAIL_NO_MATCHING_ADAPTER when no up adapter matches the allowlist' {
        $nonVpn = @($script:AdapterSample[1], $script:AdapterSample[2])
        $provider = New-FakeProvider -RouteIndex 9 -Adapters $nonVpn
        $result = Invoke-Core -Provider $provider -Candidates @($script:Config) -LedgerFile $script:Ledger
        $result.Code | Should -Be 'FAIL_NO_MATCHING_ADAPTER'
        $result.Passed | Should -BeFalse
    }

    It 'fails FAIL_ROUTE_UNREADABLE when the provider returns no route' {
        $provider = New-FakeProvider -Adapters $script:AdapterSample -NullRoute
        $result = Invoke-Core -Provider $provider -Candidates @($script:Config) -LedgerFile $script:Ledger
        $result.Code | Should -Be 'FAIL_ROUTE_UNREADABLE'
        $result.Passed | Should -BeFalse
    }

    It 'fails FAIL_ROUTE_UNREADABLE when the provider throws' {
        $provider = New-FakeProvider -RouteIndex 62 -Adapters $script:AdapterSample -ThrowOnRoute
        $result = Invoke-Core -Provider $provider -Candidates @($script:Config) -LedgerFile $script:Ledger
        $result.Code | Should -Be 'FAIL_ROUTE_UNREADABLE'
        $result.Passed | Should -BeFalse
    }

    It 'matches patterns case-insensitively' {
        $lower = New-GateConfig -Name 'lower.json' -Json '{"vpnNamePatterns":["wireguard"]}'
        $provider = New-FakeProvider -RouteIndex 62 -Adapters $script:AdapterSample
        (Invoke-Core -Provider $provider -Candidates @($lower) -LedgerFile $script:Ledger).Code | Should -Be 'PASS_VPN_ROUTE'
    }

    It 'rejects wildcard-only or too-short patterns as FAIL_CONFIG' -ForEach @(
        @{ Json = '{"vpnNamePatterns":["*"]}' },
        @{ Json = '{"vpnNamePatterns":["***"]}' },
        @{ Json = '{"vpnNamePatterns":["ab"]}' },
        @{ Json = '{"vpnNamePatterns":["WireGuard","*"]}' },
        @{ Json = '{"vpnNamePatterns":[]}' },
        @{ Json = '{"notes":"no patterns"}' }
    ) {
        $path = New-GateConfig -Name ('bad-' + [guid]::NewGuid().ToString('N') + '.json') -Json $Json
        $provider = New-FakeProvider -RouteIndex 62 -Adapters $script:AdapterSample
        $result = Invoke-Core -Provider $provider -Candidates @($path) -LedgerFile $script:Ledger
        $result.Code | Should -Be 'FAIL_CONFIG'
        $result.Passed | Should -BeFalse
    }

    It 'fails FAIL_CONFIG with exit code 78 when no config file exists' {
        $provider = New-FakeProvider -RouteIndex 62 -Adapters $script:AdapterSample
        $missing = Join-Path $script:Sandbox 'does-not-exist.json'
        $result = Invoke-Core -Provider $provider -Candidates @($missing) -LedgerFile $script:Ledger
        $result.Code | Should -Be 'FAIL_CONFIG'
        Get-OsintGateExitCode -Result $result | Should -Be 78
    }

    It 'fails FAIL_CONFIG on invalid JSON' {
        $path = New-GateConfig -Name 'broken.json' -Json '{ not json'
        $provider = New-FakeProvider -RouteIndex 62 -Adapters $script:AdapterSample
        (Invoke-Core -Provider $provider -Candidates @($path) -LedgerFile $script:Ledger).Code | Should -Be 'FAIL_CONFIG'
    }

    It 'rejects a non-empty proxyUrls as FAIL_CONFIG / exit 78 even when the VPN would pass' {
        $withProxy = New-GateConfig -Name 'proxy.json' -Json '{"vpnNamePatterns":["WireGuard"],"proxyUrls":["http://127.0.0.1:8080"]}'
        $provider = New-FakeProvider -RouteIndex 62 -Adapters $script:AdapterSample
        $result = Invoke-Core -Provider $provider -Candidates @($withProxy) -LedgerFile $script:Ledger
        $result.Passed | Should -BeFalse
        $result.Code | Should -Be 'FAIL_CONFIG'
        $result.Reason | Should -Match 'proxyUrls is retired'
        Get-OsintGateExitCode -Result $result | Should -Be 78
    }

    It 'accepts an empty proxyUrls array' {
        $emptyProxy = New-GateConfig -Name 'proxy-empty.json' -Json '{"vpnNamePatterns":["WireGuard"],"proxyUrls":[]}'
        $provider = New-FakeProvider -RouteIndex 62 -Adapters $script:AdapterSample
        (Invoke-Core -Provider $provider -Candidates @($emptyProxy) -LedgerFile $script:Ledger).Code | Should -Be 'PASS_VPN_ROUTE'
    }

    It 'handles schemaVersion <Label>: <Expected>' -ForEach @(
        @{ Label = '1'; Json = '{"schemaVersion":1,"vpnNamePatterns":["WireGuard"]}'; Expected = 'PASS_VPN_ROUTE' },
        @{ Label = 'absent'; Json = '{"vpnNamePatterns":["WireGuard"]}'; Expected = 'PASS_VPN_ROUTE' },
        @{ Label = '2'; Json = '{"schemaVersion":2,"vpnNamePatterns":["WireGuard"]}'; Expected = 'FAIL_CONFIG' },
        @{ Label = '"x"'; Json = '{"schemaVersion":"x","vpnNamePatterns":["WireGuard"]}'; Expected = 'FAIL_CONFIG' }
    ) {
        $path = New-GateConfig -Name ('schema-' + [guid]::NewGuid().ToString('N') + '.json') -Json $Json
        $provider = New-FakeProvider -RouteIndex 62 -Adapters $script:AdapterSample
        $result = Invoke-Core -Provider $provider -Candidates @($path) -LedgerFile $script:Ledger
        $result.Code | Should -Be $Expected
        if ($Expected -eq 'FAIL_CONFIG') { $result.Reason | Should -Match 'Unsupported gate config schemaVersion' }
    }

    It 'fails closed with FAIL_PROVIDER_UNSUPPORTED on a non-Windows platform provider' {
        $provider = New-FakeProvider -RouteIndex 62 -Adapters $script:AdapterSample -Platform 'Linux'
        $result = Invoke-Core -Provider $provider -Candidates @($script:Config) -LedgerFile $script:Ledger
        $result.Code | Should -Be 'FAIL_PROVIDER_UNSUPPORTED'
        $result.Passed | Should -BeFalse
        Get-OsintGateExitCode -Result $result | Should -Be 75
    }

    It 'selects the unsupported provider for a non-Windows platform name' {
        $selected = InModuleScope OsintNetworkGate { Get-OsintGateProvider -PlatformName 'macOS' }
        & $selected.GetPlatformName | Should -Be 'macOS'
        $selected.ContainsKey('GetDefaultRouteInterface') | Should -BeFalse
        $result = Invoke-Core -Provider $selected -Candidates @($script:Config) -LedgerFile $script:Ledger
        $result.Code | Should -Be 'FAIL_PROVIDER_UNSUPPORTED'
    }

    It 'ships a valid example config that the loader accepts' {
        $provider = New-FakeProvider -RouteIndex 62 -Adapters $script:AdapterSample
        $result = Invoke-Core -Provider $provider -Candidates @($script:ExampleConfig) -LedgerFile $script:Ledger
        $result.Code | Should -Be 'PASS_VPN_ROUTE'
    }
}

Describe 'Test-OsintInformationalArguments skip rule' {
    It 'treats <Label> as <Expected> for <Tool>' -ForEach @(
        @{ Label = 'empty argv'; Tool = 'maigret'; Arguments = @(); Expected = $true },
        @{ Label = '--help'; Tool = 'maigret'; Arguments = @('--help'); Expected = $true },
        @{ Label = '-h'; Tool = 'torbot'; Arguments = @('-h'); Expected = $true },
        @{ Label = '--version'; Tool = 'scanner'; Arguments = @('--version'); Expected = $true },
        @{ Label = 'x --help'; Tool = 'maigret'; Arguments = @('x', '--help'); Expected = $false },
        @{ Label = '--HELP'; Tool = 'maigret'; Arguments = @('--HELP'); Expected = $false },
        @{ Label = '"--help "'; Tool = 'maigret'; Arguments = @('--help '); Expected = $false },
        @{ Label = '--helpme'; Tool = 'maigret'; Arguments = @('--helpme'); Expected = $false },
        @{ Label = '-h x'; Tool = 'maigret'; Arguments = @('-h', 'x'); Expected = $false },
        @{ Label = '--init-secrets'; Tool = 'phone'; Arguments = @('--init-secrets'); Expected = $true },
        @{ Label = '--init-secrets'; Tool = 'maigret'; Arguments = @('--init-secrets'); Expected = $false },
        @{ Label = 'a username'; Tool = 'maigret'; Arguments = @('someuser'); Expected = $false }
    ) {
        Test-OsintInformationalArguments -Tool $Tool -Arguments $Arguments | Should -Be $Expected
    }

    It 'treats null argv as informational' {
        Test-OsintInformationalArguments -Tool 'phone' -Arguments $null | Should -BeTrue
    }
}

Describe 'Ledger' {
    BeforeAll {
        $script:Config = New-GateConfig -Name 'ledger.json' -Json '{"vpnNamePatterns":["WireGuard"]}'
        $script:Adapters = @(@{ Index = 62; Name = 'peer'; Description = 'WireGuard Tunnel' })
        $script:Provider = @{
            GetPlatformName          = { 'Windows' }
            GetDefaultRouteInterface = { @{ Index = 62; Alias = 'peer' } }
            GetUpAdapters            = { @(@{ Index = 62; Name = 'peer'; Description = 'WireGuard Tunnel' }) }
        }
    }

    It 'writes one JSON line with the expected fields and never the argv' {
        $ledger = Join-Path $script:Sandbox 'ledger-ok.jsonl'
        $sentinel = 'SENTINEL-TARGET-john.doe@example.com'
        InModuleScope OsintNetworkGate -Parameters @{ P = $script:Provider; C = $script:Config; L = $ledger; S = $sentinel } {
            Invoke-OsintGateCore -Tool 'maigret' -ApplySkipRule -Arguments @($S, 'extra') -Entrypoint 'menu' -Provider $P -ConfigCandidates @($C) -LedgerPath $L | Out-Null
        }
        $lines = @(Get-Content -LiteralPath $ledger)
        $lines.Count | Should -Be 1
        $entry = $lines[0] | ConvertFrom-Json
        $entry.schema | Should -Be 1
        $entry.tool | Should -Be 'maigret'
        $entry.entrypoint | Should -Be 'menu'
        $entry.outcome | Should -Be 'pass'
        $entry.code | Should -Be 'PASS_VPN_ROUTE'
        $entry.ifIndex | Should -Be 62
        $entry.adapter | Should -Be 'peer'
        $entry.provider | Should -Be 'Windows'
        $lines[0] | Should -Match '"ts":"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z"'
        (Get-Content -LiteralPath $ledger -Raw) | Should -Not -Match 'SENTINEL'
        (Get-Content -LiteralPath $ledger -Raw) | Should -Not -Match 'example\.com'
    }

    It 'records skip outcomes' {
        $ledger = Join-Path $script:Sandbox 'ledger-skip.jsonl'
        InModuleScope OsintNetworkGate -Parameters @{ L = $ledger } {
            Invoke-OsintGateCore -Tool 'phone' -ApplySkipRule -Arguments @('--help') -LedgerPath $L | Out-Null
        }
        $entry = (Get-Content -LiteralPath $ledger | Select-Object -First 1) | ConvertFrom-Json
        $entry.outcome | Should -Be 'skip'
        $entry.code | Should -Be 'SKIP_INFORMATIONAL'
    }

    It 'keeps the decision and only warns when the ledger path is unwritable' {
        $blocker = Join-Path $script:Sandbox 'blocker-file'
        Set-Content -LiteralPath $blocker -Value 'x'
        $unwritable = Join-Path $blocker 'sub\gate-events.jsonl'
        $result = InModuleScope OsintNetworkGate -Parameters @{ P = $script:Provider; C = $script:Config; L = $unwritable } {
            Invoke-OsintGateCore -Tool 'phone' -Provider $P -ConfigCandidates @($C) -LedgerPath $L
        } 3>&1
        $warnings = @($result | Where-Object { $_ -is [System.Management.Automation.WarningRecord] })
        $decision = @($result | Where-Object { $_.PSObject.TypeNames -contains 'Osint.GateResult' })[0]
        $decision.Passed | Should -BeTrue
        $decision.Code | Should -Be 'PASS_VPN_ROUTE'
        $warnings.Count | Should -BeGreaterThan 0
        ($warnings[0].Message) | Should -Match 'ledger'
    }
}

Describe 'Assert-OsintNetworkGate and exit codes' {
    It 'returns true and skips the gate for informational argv' {
        Mock -ModuleName OsintNetworkGate Write-OsintGateLedger {}
        Assert-OsintNetworkGate -Tool 'phone' -Arguments @('--help') 6>$null | Should -BeTrue
    }

    It 'returns false when the gate fails (gated argv, mocked failing result)' {
        Mock -ModuleName OsintNetworkGate Write-OsintGateLedger {}
        Mock -ModuleName OsintNetworkGate Get-OsintGateConfigCandidates { @('Z:\nope\missing.json') }
        Assert-OsintNetworkGate -Tool 'maigret' -Arguments @('someuser') 6>$null | Should -BeFalse
    }

    It 'returns true when the gate passes' {
        Mock -ModuleName OsintNetworkGate Write-OsintGateLedger {}
        Mock -ModuleName OsintNetworkGate Get-OsintGateProvider {
            @{
                GetPlatformName          = { 'Windows' }
                GetDefaultRouteInterface = { @{ Index = 1; Alias = 'vpn' } }
                GetUpAdapters            = { @(@{ Index = 1; Name = 'vpn'; Description = 'WireGuard Tunnel' }) }
            }
        }
        Assert-OsintNetworkGate -Tool 'phone' -Arguments @('someuser') 6>$null | Should -BeTrue
    }

    It 'Invoke-OsintNetworkGate returns the SKIP result object for informational argv' {
        Mock -ModuleName OsintNetworkGate Write-OsintGateLedger {}
        $result = Invoke-OsintNetworkGate -Tool 'phone' -Arguments @('--help') 6>$null
        $result.Code | Should -Be 'SKIP_INFORMATIONAL'
        $result.Skipped | Should -BeTrue
    }

    It 'Invoke-OsintNetworkGate returns the FAIL result object with its code' {
        Mock -ModuleName OsintNetworkGate Write-OsintGateLedger {}
        Mock -ModuleName OsintNetworkGate Get-OsintGateConfigCandidates { @('Z:\nope\missing.json') }
        $result = Invoke-OsintNetworkGate -Tool 'maigret' -Arguments @('someuser') 6>$null
        $result.Code | Should -Be 'FAIL_CONFIG'
        Get-OsintGateExitCode -Result $result | Should -Be 78
    }

    It 'Invoke-OsintNetworkGate returns the PASS result object' {
        Mock -ModuleName OsintNetworkGate Write-OsintGateLedger {}
        Mock -ModuleName OsintNetworkGate Get-OsintGateProvider {
            @{
                GetPlatformName          = { 'Windows' }
                GetDefaultRouteInterface = { @{ Index = 1; Alias = 'vpn' } }
                GetUpAdapters            = { @(@{ Index = 1; Name = 'vpn'; Description = 'WireGuard Tunnel' }) }
            }
        }
        $result = Invoke-OsintNetworkGate -Tool 'phone' -Arguments @('someuser') 6>$null
        $result.Code | Should -Be 'PASS_VPN_ROUTE'
        $result.Passed | Should -BeTrue
    }

    It 'maps results to exit codes 0 / 75 / 78' -ForEach @(
        @{ Code = 'PASS_VPN_ROUTE'; Passed = $true; Skipped = $false; Expected = 0 },
        @{ Code = 'SKIP_INFORMATIONAL'; Passed = $false; Skipped = $true; Expected = 0 },
        @{ Code = 'FAIL_CONFIG'; Passed = $false; Skipped = $false; Expected = 78 },
        @{ Code = 'FAIL_NO_MATCHING_ADAPTER'; Passed = $false; Skipped = $false; Expected = 75 },
        @{ Code = 'FAIL_ADAPTER_NOT_ROUTING'; Passed = $false; Skipped = $false; Expected = 75 },
        @{ Code = 'FAIL_ROUTE_UNREADABLE'; Passed = $false; Skipped = $false; Expected = 75 },
        @{ Code = 'FAIL_PROVIDER_UNSUPPORTED'; Passed = $false; Skipped = $false; Expected = 75 }
    ) {
        $fake = [pscustomobject]@{ Code = $Code; Passed = $Passed; Skipped = $Skipped }
        Get-OsintGateExitCode -Result $fake | Should -Be $Expected
    }
}
