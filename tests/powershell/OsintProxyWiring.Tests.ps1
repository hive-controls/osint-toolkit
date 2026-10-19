BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..\..\shared\OsintNetworkGate.psm1') -Force
    . (Join-Path $PSScriptRoot '..\..\shared\OsintTool.Common.ps1')
    . (Join-Path $PSScriptRoot '..\..\shared\OsintProxyWiring.ps1')
    $script:Sandbox = Join-Path ([IO.Path]::GetTempPath()) ("osint-proxywire-tests-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:Sandbox | Out-Null
    $script:SavedLocalAppData = $env:LOCALAPPDATA

    function script:New-Enforcement {
        param([string] $PeerIp = '203.0.113.9', [int] $PeerPort = 8080, [bool] $Tls = $false, [string] $VerifyHost = 'verify.test')
        [pscustomobject]@{ Mode = 'routed-proxy'; PeerIp = $PeerIp; PeerPort = $PeerPort; Tls = $Tls; VerifyHost = $VerifyHost }
    }
    function script:New-GateResultFake {
        param([string] $Code, $Enforcement = $null, [bool] $Passed = $true, [bool] $Skipped = $false)
        [pscustomobject]@{ Passed = $Passed; Skipped = $Skipped; Code = $Code; Enforcement = $Enforcement; Route = $null }
    }
}

AfterAll {
    Remove-Module OsintNetworkGate -ErrorAction SilentlyContinue
    $env:LOCALAPPDATA = $script:SavedLocalAppData
    Remove-Item -LiteralPath $script:Sandbox -Recurse -Force -ErrorAction SilentlyContinue
}

Describe 'Upstream file render and cleanup' {
    It 'writes the snippet under the state directory and removes it' {
        $path = New-OsintSquidUpstreamFile -StateDirectory $script:Sandbox -Enforcement (New-Enforcement)
        $path | Should -Exist
        (Split-Path -Parent $path) | Should -Be (Join-Path $script:Sandbox 'proxy-run')
        (Get-Content -LiteralPath $path -Raw) | Should -BeExactly (ConvertTo-OsintSquidUpstreamConfig -Enforcement (New-Enforcement))
        (Get-Content -LiteralPath $path -Raw) | Should -Match 'never_direct allow all'
        Remove-OsintSquidUpstreamFile -Path $path
        $path | Should -Not -Exist
    }
    It 'tolerates cleanup of a missing file' {
        { Remove-OsintSquidUpstreamFile -Path (Join-Path $script:Sandbox 'nope.conf') } | Should -Not -Throw
        { Remove-OsintSquidUpstreamFile -Path $null } | Should -Not -Throw
    }
}

Describe 'Resolve-OsintProxyEnforcementAction' {
    It 'runs vpn mode with no enforcement' {
        $action = Resolve-OsintProxyEnforcementAction -GateResult (New-GateResultFake -Code 'PASS_VPN_ROUTE')
        $action.Action | Should -Be 'run'
        $action.Routed | Should -BeFalse
    }
    It 'runs a skipped gate as vpn mode' {
        $action = Resolve-OsintProxyEnforcementAction -GateResult (New-GateResultFake -Code 'SKIPPED' -Passed $false -Skipped $true)
        $action.Action | Should -Be 'run'
        $action.Routed | Should -BeFalse
    }
    It 'runs routed mode when enforcement is present' {
        $action = Resolve-OsintProxyEnforcementAction -GateResult (New-GateResultFake -Code 'PASS_ROUTED_PROXY' -Enforcement (New-Enforcement))
        $action.Action | Should -Be 'run'
        $action.Routed | Should -BeTrue
    }
    It 'exits 78 when a routed pass has no enforcement' {
        $action = Resolve-OsintProxyEnforcementAction -GateResult (New-GateResultFake -Code 'PASS_ROUTED_PROXY')
        $action.Action | Should -Be 'exit'
        $action.Code | Should -Be 78
    }
    It 'exits 78 when routed enforcement lacks or empties VerifyHost' {
        $noHost = [pscustomobject]@{ Mode = 'routed-proxy'; PeerIp = '203.0.113.9'; PeerPort = 8080; Tls = $false }
        (Resolve-OsintProxyEnforcementAction -GateResult (New-GateResultFake -Code 'PASS_ROUTED_PROXY' -Enforcement $noHost)).Code | Should -Be 78
        (Resolve-OsintProxyEnforcementAction -GateResult (New-GateResultFake -Code 'PASS_ROUTED_PROXY' -Enforcement (New-Enforcement -VerifyHost ' '))).Action | Should -Be 'exit'
    }
    It 'exits 78 when enforcement names an unknown mode' {
        $odd = [pscustomobject]@{ Mode = 'mystery'; PeerIp = '203.0.113.9'; PeerPort = 1; Tls = $false }
        (Resolve-OsintProxyEnforcementAction -GateResult (New-GateResultFake -Code 'PASS_ROUTED_PROXY' -Enforcement $odd)).Code | Should -Be 78
    }
}

Describe 'Resolve-OsintTorBotRouteAction' {
    It 'refuses routed-proxy mode with 78' {
        $result = [pscustomobject]@{ Route = [pscustomobject]@{ Mode = 'routed-proxy' }; Code = 'PASS_ROUTED_PROXY' }
        $action = Resolve-OsintTorBotRouteAction -GateResult $result
        $action.Action | Should -Be 'exit'
        $action.Code | Should -Be 78
        $action.Reason | Should -Be 'routed-proxy mode is not available for TorBot'
    }
    It 'allows vpn mode' {
        (Resolve-OsintTorBotRouteAction -GateResult ([pscustomobject]@{ Route = [pscustomobject]@{ Mode = 'vpn' }; Code = 'PASS_VPN_ROUTE' })).Action | Should -Be 'run'
        (Resolve-OsintTorBotRouteAction -GateResult ([pscustomobject]@{ Route = $null; Code = 'SKIPPED' })).Action | Should -Be 'run'
    }
}

Describe 'Test-OsintSquidHierarchyLine' {
    BeforeAll {
        $script:Target = 'probe.example:443'
        function script:New-AccessLine {
            param([string] $Hier, [string] $Target = 'probe.example:443', [string] $Code = 'TCP_TUNNEL/200')
            "1760000000.123 45 172.34.0.3 $Code 4000 CONNECT $Target - $Hier -"
        }
    }
    It 'accepts FIRSTUP_PARENT' {
        Test-OsintSquidHierarchyLine -Lines @(New-AccessLine -Hier 'FIRSTUP_PARENT/203.0.113.9') -Target $script:Target | Should -BeTrue
    }
    It 'accepts DEFAULT_PARENT' {
        Test-OsintSquidHierarchyLine -Lines @(New-AccessLine -Hier 'DEFAULT_PARENT/203.0.113.9') -Target $script:Target | Should -BeTrue
    }
    It 'rejects HIER_DIRECT' {
        Test-OsintSquidHierarchyLine -Lines @(New-AccessLine -Hier 'HIER_DIRECT/198.51.100.7') -Target $script:Target | Should -BeFalse
    }
    It 'rejects HIER_DIRECT even when a parent line is also present' {
        $lines = @((New-AccessLine -Hier 'FIRSTUP_PARENT/203.0.113.9'), (New-AccessLine -Hier 'HIER_DIRECT/198.51.100.7'))
        Test-OsintSquidHierarchyLine -Lines $lines -Target $script:Target | Should -BeFalse
    }
    It 'rejects a denied request (HIER_NONE)' {
        Test-OsintSquidHierarchyLine -Lines @(New-AccessLine -Hier 'HIER_NONE/-' -Code 'TCP_DENIED/403') -Target $script:Target | Should -BeFalse
    }
    It 'rejects a missing log line and empty input' {
        Test-OsintSquidHierarchyLine -Lines @(New-AccessLine -Hier 'FIRSTUP_PARENT/203.0.113.9' -Target 'other.example:443') -Target $script:Target | Should -BeFalse
        Test-OsintSquidHierarchyLine -Lines @() -Target $script:Target | Should -BeFalse
        Test-OsintSquidHierarchyLine -Lines $null -Target $script:Target | Should -BeFalse
    }
}

Describe 'Enable-OsintRoutedProxy' {
    BeforeEach {
        $env:LOCALAPPDATA = $script:Sandbox
        Remove-Item Env:OSINT_SQUID_CONF, Env:OSINT_SQUID_UPSTREAM -ErrorAction SilentlyContinue
    }
    AfterEach {
        Remove-Item Env:OSINT_SQUID_CONF, Env:OSINT_SQUID_UPSTREAM -ErrorAction SilentlyContinue
    }
    It 'leaves vpn mode untouched and never calls docker' {
        Mock Invoke-OsintDocker { throw 'docker must not run in vpn mode' }
        $state = Enable-OsintRoutedProxy -GateResult (New-GateResultFake -Code 'PASS_VPN_ROUTE') -ConfigTool 'ProxyWireTest'
        $state.Routed | Should -BeFalse
        $state.ExitCode | Should -Be 0
        $env:OSINT_SQUID_CONF | Should -BeNullOrEmpty
        $env:OSINT_SQUID_UPSTREAM | Should -BeNullOrEmpty
    }
    It 'renders the file, selects the routed conf and preflights in routed mode' {
        Mock Invoke-OsintDocker { [pscustomobject]@{ ExitCode = 0; Output = @('ok') } }
        $state = Enable-OsintRoutedProxy -GateResult (New-GateResultFake -Code 'PASS_ROUTED_PROXY' -Enforcement (New-Enforcement)) -ConfigTool 'ProxyWireTest'
        $state.Routed | Should -BeTrue
        $state.ExitCode | Should -Be 0
        $env:OSINT_SQUID_CONF | Should -Be 'squid-routed.conf'
        $env:OSINT_SQUID_UPSTREAM | Should -Be $state.UpstreamFile
        $state.UpstreamFile | Should -Exist
        Should -Invoke Invoke-OsintDocker -Times 1 -ParameterFilter { $Arguments -contains 'parse' -and $Arguments -contains '/etc/squid/squid-routed.conf' }
        Disable-OsintRoutedProxy -State $state
        $state.UpstreamFile | Should -Not -Exist
        $env:OSINT_SQUID_CONF | Should -BeNullOrEmpty
    }
    It 'returns 78 with the parse output when squid -k parse fails' {
        Mock Invoke-OsintDocker { [pscustomobject]@{ ExitCode = 1; Output = @('FATAL: bad directive') } }
        $state = Enable-OsintRoutedProxy -GateResult (New-GateResultFake -Code 'PASS_ROUTED_PROXY' -Enforcement (New-Enforcement)) -ConfigTool 'ProxyWireTest'
        $state.ExitCode | Should -Be 78
        $state.Message | Should -Match 'FATAL: bad directive'
        Disable-OsintRoutedProxy -State $state
    }
    It 'returns 78 for a non-IP peer without touching docker' {
        Mock Invoke-OsintDocker { throw 'docker must not run' }
        $bad = New-Enforcement -PeerIp 'proxy.example'
        (Enable-OsintRoutedProxy -GateResult (New-GateResultFake -Code 'PASS_ROUTED_PROXY' -Enforcement $bad) -ConfigTool 'ProxyWireTest').ExitCode | Should -Be 78
    }
}

Describe 'Invoke-OsintEnforcementProbe' {
    BeforeAll {
        function script:New-DockerFake {
            param([string[]] $LogLines)
            $captured = $LogLines
            { param($Arguments) [pscustomobject]@{ ExitCode = 0; Output = $(if ($Arguments -contains 'logs') { $captured } else { @() }) } }.GetNewClosure()
        }
    }
    BeforeEach { Mock Start-Sleep { } }
    It 'passes when the log shows a parent hierarchy code' {
        Mock Invoke-OsintDocker (New-DockerFake -LogLines @('1.1 5 172.34.0.3 TCP_TUNNEL/200 39 CONNECT verify.test:443 - FIRSTUP_PARENT/203.0.113.9 -'))
        (Invoke-OsintEnforcementProbe -ToolService 'maigret' -Enforcement (New-Enforcement) -WaitSeconds 2).Ok | Should -BeTrue
    }
    It 'fails on HIER_DIRECT' {
        Mock Invoke-OsintDocker (New-DockerFake -LogLines @('1.1 5 172.34.0.3 TCP_TUNNEL/200 39 CONNECT verify.test:443 - HIER_DIRECT/93.184.216.34 -'))
        (Invoke-OsintEnforcementProbe -ToolService 'maigret' -Enforcement (New-Enforcement) -WaitSeconds 2).Ok | Should -BeFalse
    }
    It 'fails when the log never shows the CONNECT' {
        Mock Invoke-OsintDocker (New-DockerFake -LogLines @())
        (Invoke-OsintEnforcementProbe -ToolService 'maigret' -Enforcement (New-Enforcement) -WaitSeconds 2).Ok | Should -BeFalse
    }
    It 'throws without a VerifyHost and never contacts docker' {
        Mock Invoke-OsintDocker { [pscustomobject]@{ ExitCode = 0; Output = @() } }
        $noHost = [pscustomobject]@{ Mode = 'routed-proxy'; PeerIp = '203.0.113.9'; PeerPort = 8080; Tls = $false }
        { Invoke-OsintEnforcementProbe -ToolService 'maigret' -Enforcement $noHost -WaitSeconds 1 } | Should -Throw -ExpectedMessage '*VerifyHost*'
        Should -Invoke Invoke-OsintDocker -Times 0
    }
    It 'probes the VerifyHost when the enforcement carries one' {
        $withHost = New-Enforcement
        Mock Invoke-OsintDocker (New-DockerFake -LogLines @('1.1 5 172.34.0.3 TCP_TUNNEL/200 39 CONNECT verify.test:443 - DEFAULT_PARENT/203.0.113.9 -'))
        $probe = Invoke-OsintEnforcementProbe -ToolService 'maigret' -Enforcement $withHost -WaitSeconds 2
        $probe.Ok | Should -BeTrue
        $probe.Target | Should -Be 'verify.test:443'
    }
}
