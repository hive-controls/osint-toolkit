BeforeAll {
    $script:ModulePath = Join-Path $PSScriptRoot '..\..\shared\OsintNetworkGate.psm1'
    Import-Module $script:ModulePath -Force
    $script:SharedDir = Split-Path -Parent (Resolve-Path $script:ModulePath).Path
    $script:Sandbox = Join-Path ([IO.Path]::GetTempPath()) ("osint-gate-proxy-tests-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:Sandbox | Out-Null

    function script:New-ConfigFile {
        param([string] $Json)
        $path = Join-Path $script:Sandbox ([guid]::NewGuid().ToString('N') + '.json')
        Set-Content -LiteralPath $path -Value $Json -Encoding utf8
        return $path
    }

    function script:New-RoutedConfigJson {
        param([string] $Url = 'http://proxy.test:3128', [hashtable] $Overrides = @{}, [bool] $WithPatterns = $false)
        $block = [ordered]@{ url = $Url; verifyHost = 'example.com'; allowPrivate = $false; tlsToProxy = $false; connectTimeoutSeconds = 5 }
        foreach ($key in $Overrides.Keys) {
            if ($null -eq $Overrides[$key]) { $block.Remove($key) } else { $block[$key] = $Overrides[$key] }
        }
        $document = [ordered]@{ schemaVersion = 1; mode = 'routed-proxy'; routedProxy = $block }
        if ($WithPatterns) { $document['vpnNamePatterns'] = @('WireGuard') }
        return ($document | ConvertTo-Json -Depth 5)
    }

    function script:Invoke-RoutedCore {
        param([string] $ConfigPath, [hashtable] $Seams = @{}, $Provider = $null, [string] $Ledger = $null)
        if (-not $Ledger) { $Ledger = Join-Path $script:Sandbox ([guid]::NewGuid().ToString('N') + '.jsonl') }
        $arguments = @{ Captured = @{ Config = $ConfigPath; Seams = $Seams; Provider = $Provider; Ledger = $Ledger } }
        InModuleScope OsintNetworkGate -Parameters $arguments {
            $splat = @{ Tool = 'phone'; ConfigCandidates = @($Captured.Config); LedgerPath = $Captured.Ledger }
            if ($Captured.Provider) { $splat['Provider'] = $Captured.Provider }
            foreach ($seam in $Captured.Seams.Keys) { $splat[$seam] = $Captured.Seams[$seam] }
            Invoke-OsintGateCore @splat
        }
    }

    function script:New-CountingProbe {
        param([int] $Status = 200, [string] $Protocol = 'Tls13', [string] $Subject = 'CN=example.com')
        $state = @{ Calls = 0; Last = $null }
        $probe = {
            param($Ip, $Port, $VerifyHost, $TimeoutSeconds, $Tls, $ProxyHost)
            $state.Calls++
            $state.Last = @{ Ip = $Ip; Port = $Port; VerifyHost = $VerifyHost; Tls = $Tls }
            @{ Status = $Status; TlsProtocol = $Protocol; CertSubject = $Subject; ElapsedMs = 12 }
        }.GetNewClosure()
        return @{ Probe = $probe; State = $state }
    }

    function script:Get-AddressClass {
        param([string] $Ip, [bool] $AllowPrivate = $false, [string[]] $HostAddresses = @())
        InModuleScope OsintNetworkGate -Parameters @{ Ip = $Ip; Allow = $AllowPrivate; Owned = $HostAddresses } {
            Test-OsintProxyAddressClass -IPAddress $Ip -AllowPrivate:$Allow -HostAddresses $Owned
        }
    }

    function script:Start-FakeConnectServer {
        param([string] $Behavior)
        $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
        $listener.Start()
        $shared = [hashtable]::Synchronized(@{ Request = ''; Stop = $false })
        $shell = [powershell]::Create()
        [void]$shell.AddScript({
                param($Listener, $Behavior, $Shared)
                function Wait-ForStop { for ($i = 0; $i -lt 200 -and -not $Shared.Stop; $i++) { Start-Sleep -Milliseconds 100 } }
                try {
                    $client = $Listener.AcceptTcpClient()
                    if ($Behavior -eq 'close') { $client.Close(); return }
                    $stream = $client.GetStream()
                    $buffer = [byte[]]::new(4096)
                    $text = ''
                    while (-not $text.Contains("`r`n`r`n")) {
                        $count = $stream.Read($buffer, 0, 4096)
                        if ($count -le 0) { break }
                        $text += [Text.Encoding]::ASCII.GetString($buffer, 0, $count)
                    }
                    $Shared.Request = $text
                    $reply = switch ($Behavior) {
                        '403' { "HTTP/1.1 403 Forbidden`r`nContent-Length: 0`r`n`r`n" }
                        '407' { "HTTP/1.1 407 Proxy Authentication Required`r`nProxy-Authenticate: Basic`r`n`r`n" }
                        '200-garbage' { "HTTP/1.1 200 Connection established`r`n`r`n" }
                        '200-hang' { "HTTP/1.1 200 Connection established`r`n`r`n" }
                        default { '' }
                    }
                    if ($reply) { $bytes = [Text.Encoding]::ASCII.GetBytes($reply); $stream.Write($bytes, 0, $bytes.Length); $stream.Flush() }
                    if ($Behavior -eq '200-garbage') {
                        [void]$stream.Read($buffer, 0, 4096)
                        $junk = [Text.Encoding]::ASCII.GetBytes('this is definitely not a tls server hello')
                        $stream.Write($junk, 0, $junk.Length); $stream.Flush()
                    }
                    Wait-ForStop
                }
                catch { $Shared.Error = $_.Exception.Message }
            }).AddArgument($listener).AddArgument($Behavior).AddArgument($shared)
        $handle = $shell.BeginInvoke()
        return @{ Port = ([Net.IPEndPoint] $listener.LocalEndpoint).Port; Shared = $shared; Listener = $listener; Shell = $shell; Handle = $handle }
    }

    function script:Stop-FakeConnectServer {
        param($Server)
        $Server.Shared.Stop = $true
        try { $Server.Listener.Stop() } catch { $null = $_ }
        [void]$Server.Shell.BeginStop($null, $null)
    }

    function script:Get-ClosedPort {
        $probeListener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
        $probeListener.Start()
        $port = ([Net.IPEndPoint] $probeListener.LocalEndpoint).Port
        $probeListener.Stop()
        return $port
    }

    $script:PublicResolver = { '203.0.113.10' }
}

AfterAll {
    Remove-Module OsintNetworkGate -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $script:Sandbox -Recurse -Force -ErrorAction SilentlyContinue
}

Describe 'Test-OsintProxyAddressClass' {
    It '<Ip> (allowPrivate=<AllowPrivate>, owned=<Owned>) is <Class>, allowed=<Allowed>' -ForEach @(
        @{ Ip = '127.0.0.1'; AllowPrivate = $true; Owned = @(); Class = 'loopback'; Allowed = $false },
        @{ Ip = '::1'; AllowPrivate = $true; Owned = @(); Class = 'loopback'; Allowed = $false },
        @{ Ip = '::ffff:127.0.0.1'; AllowPrivate = $true; Owned = @(); Class = 'loopback'; Allowed = $false },
        @{ Ip = '0.0.0.0'; AllowPrivate = $true; Owned = @(); Class = 'unspecified'; Allowed = $false },
        @{ Ip = '::'; AllowPrivate = $true; Owned = @(); Class = 'unspecified'; Allowed = $false },
        @{ Ip = '169.254.10.1'; AllowPrivate = $true; Owned = @(); Class = 'link-local'; Allowed = $false },
        @{ Ip = 'fe80::1'; AllowPrivate = $true; Owned = @(); Class = 'link-local'; Allowed = $false },
        @{ Ip = '224.0.0.1'; AllowPrivate = $true; Owned = @(); Class = 'multicast'; Allowed = $false },
        @{ Ip = 'ff02::1'; AllowPrivate = $true; Owned = @(); Class = 'multicast'; Allowed = $false },
        @{ Ip = '203.0.113.9'; AllowPrivate = $true; Owned = @('203.0.113.9'); Class = 'host-owned'; Allowed = $false },
        @{ Ip = '10.0.0.5'; AllowPrivate = $true; Owned = @('10.0.0.5'); Class = 'host-owned'; Allowed = $false },
        @{ Ip = '10.1.2.3'; AllowPrivate = $false; Owned = @(); Class = 'private'; Allowed = $false },
        @{ Ip = '10.1.2.3'; AllowPrivate = $true; Owned = @(); Class = 'private'; Allowed = $true },
        @{ Ip = '172.16.0.1'; AllowPrivate = $false; Owned = @(); Class = 'private'; Allowed = $false },
        @{ Ip = '192.168.1.1'; AllowPrivate = $true; Owned = @(); Class = 'private'; Allowed = $true },
        @{ Ip = '100.64.0.1'; AllowPrivate = $false; Owned = @(); Class = 'private'; Allowed = $false },
        @{ Ip = '100.127.255.254'; AllowPrivate = $true; Owned = @(); Class = 'private'; Allowed = $true },
        @{ Ip = '100.128.0.1'; AllowPrivate = $false; Owned = @(); Class = 'public'; Allowed = $true },
        @{ Ip = 'fc00::1'; AllowPrivate = $false; Owned = @(); Class = 'private'; Allowed = $false },
        @{ Ip = 'fd12:3456::1'; AllowPrivate = $true; Owned = @(); Class = 'private'; Allowed = $true },
        @{ Ip = '8.8.8.8'; AllowPrivate = $false; Owned = @(); Class = 'public'; Allowed = $true },
        @{ Ip = '2606:4700::1111'; AllowPrivate = $false; Owned = @(); Class = 'public'; Allowed = $true }
    ) {
        $result = Get-AddressClass -Ip $Ip -AllowPrivate $AllowPrivate -HostAddresses $Owned
        $result.Class | Should -Be $Class
        $result.Allowed | Should -Be $Allowed
    }
}

Describe 'routed-proxy config validation' {
    It 'rejects <Label> as FAIL_CONFIG (78) without probing' -ForEach @(
        @{ Label = 'mode "tunnel"'; Json = '{"mode":"tunnel","vpnNamePatterns":["WireGuard"]}'; Match = 'mode must be' },
        @{ Label = 'numeric mode'; Json = '{"mode":5,"vpnNamePatterns":["WireGuard"]}'; Match = 'mode must be' },
        @{ Label = 'mode case variance'; Json = '{"mode":"VPN","vpnNamePatterns":["WireGuard"]}'; Match = 'mode must be' },
        @{ Label = 'routed-proxy without a block'; Json = '{"mode":"routed-proxy"}'; Match = 'requires a routedProxy' },
        @{ Label = 'missing url'; Json = '{"mode":"routed-proxy","routedProxy":{"verifyHost":"example.com"}}'; Match = 'url is required' },
        @{ Label = 'socks5 scheme'; Json = '{"mode":"routed-proxy","routedProxy":{"url":"socks5://proxy.test:1080","verifyHost":"example.com"}}'; Match = 'SOCKS' },
        @{ Label = 'socks5h scheme'; Json = '{"mode":"routed-proxy","routedProxy":{"url":"socks5h://proxy.test:1080","verifyHost":"example.com"}}'; Match = 'SOCKS' },
        @{ Label = 'ftp scheme'; Json = '{"mode":"routed-proxy","routedProxy":{"url":"ftp://proxy.test:21","verifyHost":"example.com"}}'; Match = 'not supported' },
        @{ Label = 'https without tlsToProxy'; Json = '{"mode":"routed-proxy","routedProxy":{"url":"https://proxy.test:3129","verifyHost":"example.com"}}'; Match = 'tlsToProxy=true' },
        @{ Label = 'tlsToProxy with an http url'; Json = '{"mode":"routed-proxy","routedProxy":{"url":"http://proxy.test:3128","verifyHost":"example.com","tlsToProxy":true}}'; Match = 'https' },
        @{ Label = 'empty verifyHost'; Json = '{"mode":"routed-proxy","routedProxy":{"url":"http://proxy.test:3128","verifyHost":""}}'; Match = 'verifyHost' },
        @{ Label = 'missing verifyHost'; Json = '{"mode":"routed-proxy","routedProxy":{"url":"http://proxy.test:3128"}}'; Match = 'verifyHost' },
        @{ Label = 'IP verifyHost'; Json = '{"mode":"routed-proxy","routedProxy":{"url":"http://proxy.test:3128","verifyHost":"93.184.216.34"}}'; Match = 'verifyHost' },
        @{ Label = 'verifyHost with a space'; Json = '{"mode":"routed-proxy","routedProxy":{"url":"http://proxy.test:3128","verifyHost":"bad host"}}'; Match = 'verifyHost' },
        @{ Label = 'timeout 0'; Json = '{"mode":"routed-proxy","routedProxy":{"url":"http://proxy.test:3128","verifyHost":"example.com","connectTimeoutSeconds":0}}'; Match = 'connectTimeoutSeconds' },
        @{ Label = 'timeout 31'; Json = '{"mode":"routed-proxy","routedProxy":{"url":"http://proxy.test:3128","verifyHost":"example.com","connectTimeoutSeconds":31}}'; Match = 'connectTimeoutSeconds' },
        @{ Label = 'string timeout'; Json = '{"mode":"routed-proxy","routedProxy":{"url":"http://proxy.test:3128","verifyHost":"example.com","connectTimeoutSeconds":"5"}}'; Match = 'connectTimeoutSeconds' },
        @{ Label = 'fractional timeout'; Json = '{"mode":"routed-proxy","routedProxy":{"url":"http://proxy.test:3128","verifyHost":"example.com","connectTimeoutSeconds":1.5}}'; Match = 'connectTimeoutSeconds' },
        @{ Label = 'string allowPrivate'; Json = '{"mode":"routed-proxy","routedProxy":{"url":"http://proxy.test:3128","verifyHost":"example.com","allowPrivate":"yes"}}'; Match = 'allowPrivate' }
    ) {
        $counter = New-CountingProbe
        $result = Invoke-RoutedCore -ConfigPath (New-ConfigFile -Json $Json) -Seams @{ ProxyProbe = $counter.Probe; Resolver = $script:PublicResolver; HostAddresses = @() }
        $result.Code | Should -Be 'FAIL_CONFIG'
        $result.Reason | Should -Match $Match
        Get-OsintGateExitCode -Result $result | Should -Be 78
        $counter.State.Calls | Should -Be 0
    }

    It 'accepts scheme-default ports and timeout bounds' -ForEach @(
        @{ Url = 'http://proxy.test'; Tls = $false; Timeout = 1; Port = 80 },
        @{ Url = 'https://proxy.test'; Tls = $true; Timeout = 30; Port = 443 },
        @{ Url = 'http://proxy.test:3128'; Tls = $false; Timeout = 5; Port = 3128 }
    ) {
        $json = New-RoutedConfigJson -Url $Url -Overrides @{ tlsToProxy = $Tls; connectTimeoutSeconds = $Timeout }
        $counter = New-CountingProbe
        $result = Invoke-RoutedCore -ConfigPath (New-ConfigFile -Json $json) -Seams @{ ProxyProbe = $counter.Probe; Resolver = $script:PublicResolver; HostAddresses = @() }
        $result.Code | Should -Be 'PASS_ROUTED_PROXY'
        $result.Enforcement.PeerPort | Should -Be $Port
        $result.Enforcement.Tls | Should -Be $Tls
    }

    It 'defaults the timeout to 5 seconds when absent' {
        $json = New-RoutedConfigJson -Overrides @{ connectTimeoutSeconds = $null }
        $captured = @{ Timeout = $null }
        $probe = { param($Ip, $Port, $VerifyHost, $TimeoutSeconds, $Tls, $ProxyHost) $captured.Timeout = $TimeoutSeconds; @{ Status = 200; TlsProtocol = 'Tls12'; CertSubject = 'CN=x'; ElapsedMs = 1 } }.GetNewClosure()
        (Invoke-RoutedCore -ConfigPath (New-ConfigFile -Json $json) -Seams @{ ProxyProbe = $probe; Resolver = $script:PublicResolver; HostAddresses = @() }).Passed | Should -BeTrue
        $captured.Timeout | Should -Be 5
    }

    It 'never reads ambient proxy environment variables' {
        $text = Get-Content -LiteralPath (Join-Path $script:SharedDir 'OsintRoutedProxy.ps1') -Raw
        $text | Should -Not -Match '\$env:|GetEnvironmentVariable|Get-ChildItem\s+Env:'
    }
}

Describe 'routed-proxy decisions (probe seam)' {
    It 'passes with the full Enforcement contract and evidence' {
        $counter = New-CountingProbe -Subject 'CN=example.com'
        $result = Invoke-RoutedCore -ConfigPath (New-ConfigFile -Json (New-RoutedConfigJson)) -Seams @{ ProxyProbe = $counter.Probe; Resolver = $script:PublicResolver; HostAddresses = @() }
        $result.Passed | Should -BeTrue
        $result.Code | Should -Be 'PASS_ROUTED_PROXY'
        $result.PSObject.TypeNames[0] | Should -Be 'Osint.GateResult'
        $result.Enforcement.Mode | Should -Be 'routed-proxy'
        $result.Enforcement.PeerIp | Should -Be '203.0.113.10'
        $result.Enforcement.PeerPort | Should -Be 3128
        $result.Enforcement.PeerPort | Should -BeOfType [int]
        $result.Enforcement.Tls | Should -BeFalse
        ($result.Enforcement.PSObject.Properties.Name | Sort-Object) -join ',' | Should -Be 'Mode,PeerIp,PeerPort,Tls,VerifyHost'
        $result.Enforcement.VerifyHost | Should -Be 'example.com'
        $result.Route.Mode | Should -Be 'routed-proxy'
        $result.Route.ProxyHost | Should -Be 'proxy.test'
        $result.Route.ProxyIp | Should -Be '203.0.113.10'
        $result.Route.ProxyPort | Should -Be 3128
        $result.Route.Scheme | Should -Be 'http'
        $joined = $result.Evidence -join "`n"
        $joined | Should -Match 'address class: public'
        $joined | Should -Match 'connect status: HTTP 200'
        $joined | Should -Match 'tls protocol: Tls13'
        $joined | Should -Match 'tls certificate subject: CN=example\.com'
        $joined | Should -Match 'elapsed ms: 12'
        $joined | Should -Match 'enforcement: sidecar peer must be pinned to 203\.0\.113\.10:3128'
        $counter.State.Last.Ip | Should -Be '203.0.113.10'
        $counter.State.Last.VerifyHost | Should -Be 'example.com'
        Get-OsintGateExitCode -Result $result | Should -Be 0
    }

    It 'carries Enforcement Tls=true for an https peer' {
        $json = New-RoutedConfigJson -Url 'https://proxy.test:3129' -Overrides @{ tlsToProxy = $true }
        $counter = New-CountingProbe
        $result = Invoke-RoutedCore -ConfigPath (New-ConfigFile -Json $json) -Seams @{ ProxyProbe = $counter.Probe; Resolver = $script:PublicResolver; HostAddresses = @() }
        $result.Enforcement.Tls | Should -BeTrue
        $counter.State.Last.Tls | Should -BeTrue
    }

    It 'gives <Label> a null Enforcement and exit 75' -ForEach @(
        @{ Label = 'CONNECT denied'; Probe = { @{ Status = 403; TlsProtocol = $null; CertSubject = $null; ElapsedMs = 3 } }; Code = 'FAIL_PROXY_CONNECT_DENIED' },
        @{ Label = '407'; Probe = { @{ Status = 407; TlsProtocol = $null; CertSubject = $null; ElapsedMs = 3 } }; Code = 'FAIL_PROXY_CONNECT_DENIED' },
        @{ Label = 'no TLS session'; Probe = { @{ Status = 200; TlsProtocol = $null; CertSubject = $null; ElapsedMs = 3 } }; Code = 'FAIL_PROXY_TLS' },
        @{ Label = 'unreachable'; Probe = { throw 'PROXYFAIL:FAIL_PROXY_UNREACHABLE:refused' }; Code = 'FAIL_PROXY_UNREACHABLE' },
        @{ Label = 'timeout'; Probe = { throw 'PROXYFAIL:FAIL_PROXY_TIMEOUT:slow' }; Code = 'FAIL_PROXY_TIMEOUT' },
        @{ Label = 'tls failure'; Probe = { throw 'PROXYFAIL:FAIL_PROXY_TLS:bad cert' }; Code = 'FAIL_PROXY_TLS' },
        @{ Label = 'an untyped probe exception'; Probe = { throw 'boom' }; Code = 'FAIL_PROXY_UNREACHABLE' }
    ) {
        $result = Invoke-RoutedCore -ConfigPath (New-ConfigFile -Json (New-RoutedConfigJson)) -Seams @{ ProxyProbe = $Probe; Resolver = $script:PublicResolver; HostAddresses = @() }
        $result.Passed | Should -BeFalse
        $result.Code | Should -Be $Code
        $result.Enforcement | Should -BeNullOrEmpty
        Get-OsintGateExitCode -Result $result | Should -Be 75
    }

    It 'rejects a <Label> proxy address without probing (FAIL_PROXY_ADDRESS_REJECTED, 75, null Enforcement)' -ForEach @(
        @{ Label = 'loopback'; Ip = '127.0.0.1'; Owned = @() },
        @{ Label = 'unspecified'; Ip = '0.0.0.0'; Owned = @() },
        @{ Label = 'link-local'; Ip = '169.254.1.1'; Owned = @() },
        @{ Label = 'multicast'; Ip = '224.0.0.5'; Owned = @() },
        @{ Label = 'host-owned'; Ip = '203.0.113.10'; Owned = @('203.0.113.10') },
        @{ Label = 'private (allowPrivate off)'; Ip = '10.9.8.7'; Owned = @() }
    ) {
        $counter = New-CountingProbe
        $address = $Ip
        $resolver = { $address }.GetNewClosure()
        $result = Invoke-RoutedCore -ConfigPath (New-ConfigFile -Json (New-RoutedConfigJson)) -Seams @{ ProxyProbe = $counter.Probe; Resolver = $resolver; HostAddresses = $Owned }
        $result.Code | Should -Be 'FAIL_PROXY_ADDRESS_REJECTED'
        $result.Enforcement | Should -BeNullOrEmpty
        $counter.State.Calls | Should -Be 0
        Get-OsintGateExitCode -Result $result | Should -Be 75
    }

    It 'allows a private proxy address only with allowPrivate=true' {
        $resolver = { '10.9.8.7' }
        $json = New-RoutedConfigJson -Overrides @{ allowPrivate = $true }
        $result = Invoke-RoutedCore -ConfigPath (New-ConfigFile -Json $json) -Seams @{ ProxyProbe = (New-CountingProbe).Probe; Resolver = $resolver; HostAddresses = @() }
        $result.Code | Should -Be 'PASS_ROUTED_PROXY'
    }

    It 'ignores AllowLoopbackForTests unless a probe or resolver seam is supplied' {
        $result = InModuleScope OsintNetworkGate -Parameters @{ Config = (New-ConfigFile -Json (New-RoutedConfigJson -Url 'http://127.0.0.1:3128')); Ledger = (Join-Path $script:Sandbox 'noseam.jsonl') } {
            Invoke-OsintGateCore -Tool 'phone' -ConfigCandidates @($Config) -LedgerPath $Ledger -AllowLoopbackForTests -HostAddresses @()
        }
        $result.Code | Should -Be 'FAIL_PROXY_ADDRESS_REJECTED'
    }

    It 'fails FAIL_PROXY_UNREACHABLE when the proxy host does not resolve' {
        $resolver = { throw 'no such host' }
        $result = Invoke-RoutedCore -ConfigPath (New-ConfigFile -Json (New-RoutedConfigJson)) -Seams @{ ProxyProbe = (New-CountingProbe).Probe; Resolver = $resolver; HostAddresses = @() }
        $result.Code | Should -Be 'FAIL_PROXY_UNREACHABLE'
        $result.Enforcement | Should -BeNullOrEmpty
    }
}

Describe 'mode exclusivity' {
    BeforeAll {
        $script:FailingVpnProvider = @{
            GetPlatformName          = { 'Windows' }
            GetDefaultRouteInterface = { $null }
            GetUpAdapters            = { @() }
        }
        $script:PassingVpnProvider = @{
            GetPlatformName          = { 'Windows' }
            GetDefaultRouteInterface = { @{ Index = 62; Alias = 'peer' } }
            GetUpAdapters            = { @(@{ Index = 62; Name = 'peer'; Description = 'WireGuard Tunnel' }) }
        }
    }

    It 'routed-proxy PASSES even when the VPN provider would fail' {
        $counter = New-CountingProbe
        $result = Invoke-RoutedCore -ConfigPath (New-ConfigFile -Json (New-RoutedConfigJson -WithPatterns $true)) -Provider $script:FailingVpnProvider -Seams @{ ProxyProbe = $counter.Probe; Resolver = $script:PublicResolver; HostAddresses = @() }
        $result.Code | Should -Be 'PASS_ROUTED_PROXY'
        $counter.State.Calls | Should -Be 1
    }

    It 'routed-proxy FAILS when the proxy check fails even though the VPN provider would pass' {
        $probe = { @{ Status = 403; TlsProtocol = $null; CertSubject = $null; ElapsedMs = 1 } }
        $result = Invoke-RoutedCore -ConfigPath (New-ConfigFile -Json (New-RoutedConfigJson -WithPatterns $true)) -Provider $script:PassingVpnProvider -Seams @{ ProxyProbe = $probe; Resolver = $script:PublicResolver; HostAddresses = @() }
        $result.Passed | Should -BeFalse
        $result.Code | Should -Be 'FAIL_PROXY_CONNECT_DENIED'
    }

    It 'vpn mode (<Label>) never runs the proxy probe, passing or failing' -ForEach @(
        @{ Label = 'explicit, VPN up'; Mode = '"mode":"vpn",'; Provider = 'Pass'; Expected = 'PASS_VPN_ROUTE' },
        @{ Label = 'default, VPN up'; Mode = ''; Provider = 'Pass'; Expected = 'PASS_VPN_ROUTE' },
        @{ Label = 'explicit, VPN down'; Mode = '"mode":"vpn",'; Provider = 'Fail'; Expected = 'FAIL_ROUTE_UNREADABLE' }
    ) {
        $json = '{' + $Mode + '"vpnNamePatterns":["WireGuard"],"routedProxy":{"url":"http://proxy.test:3128","verifyHost":"example.com"}}'
        $provider = if ($Provider -eq 'Pass') { $script:PassingVpnProvider } else { $script:FailingVpnProvider }
        $counter = New-CountingProbe
        $result = Invoke-RoutedCore -ConfigPath (New-ConfigFile -Json $json) -Provider $provider -Seams @{ ProxyProbe = $counter.Probe; Resolver = $script:PublicResolver; HostAddresses = @() }
        $result.Code | Should -Be $Expected
        $result.Enforcement | Should -BeNullOrEmpty
        $counter.State.Calls | Should -Be 0
    }

    It 'keeps the informational skip rule in routed-proxy mode' {
        $counter = New-CountingProbe
        $config = New-ConfigFile -Json (New-RoutedConfigJson)
        $result = InModuleScope OsintNetworkGate -Parameters @{ Config = $config; Ledger = (Join-Path $script:Sandbox 'skip.jsonl'); Probe = $counter.Probe } {
            Invoke-OsintGateCore -Tool 'phone' -ApplySkipRule -Arguments @('--help') -ConfigCandidates @($Config) -LedgerPath $Ledger -ProxyProbe $Probe
        }
        $result.Code | Should -Be 'SKIP_INFORMATIONAL'
        $result.Enforcement | Should -BeNullOrEmpty
        $counter.State.Calls | Should -Be 0
    }
}

Describe 'real CONNECT probe against a fake proxy' {
    BeforeEach { $script:Server = $null }
    AfterEach { if ($script:Server) { Stop-FakeConnectServer -Server $script:Server } }

    function script:Invoke-AgainstFake {
        param([int] $Port, [int] $TimeoutSeconds = 2)
        $json = New-RoutedConfigJson -Url "http://proxy.test:$Port" -Overrides @{ connectTimeoutSeconds = $TimeoutSeconds }
        $seams = @{ Resolver = { '127.0.0.1' }; HostAddresses = @(); AllowLoopbackForTests = $true }
        Invoke-RoutedCore -ConfigPath (New-ConfigFile -Json $json) -Seams $seams
    }

    It 'maps a <Behavior> reply to <Code>' -ForEach @(
        @{ Behavior = '403'; Code = 'FAIL_PROXY_CONNECT_DENIED' },
        @{ Behavior = '407'; Code = 'FAIL_PROXY_CONNECT_DENIED' },
        @{ Behavior = 'close'; Code = 'FAIL_PROXY_UNREACHABLE' },
        @{ Behavior = '200-garbage'; Code = 'FAIL_PROXY_TLS' }
    ) {
        $script:Server = Start-FakeConnectServer -Behavior $Behavior
        $result = Invoke-AgainstFake -Port $script:Server.Port
        $result.Code | Should -Be $Code
        $result.Passed | Should -BeFalse
        $result.Enforcement | Should -BeNullOrEmpty
    }

    It 'sends a well-formed CONNECT request to verifyHost:443' {
        $script:Server = Start-FakeConnectServer -Behavior '403'
        Invoke-AgainstFake -Port $script:Server.Port | Out-Null
        $script:Server.Shared.Request | Should -Be "CONNECT example.com:443 HTTP/1.1`r`nHost: example.com:443`r`n`r`n"
    }

    It 'reports FAIL_PROXY_UNREACHABLE when nothing is listening' {
        $result = Invoke-AgainstFake -Port (Get-ClosedPort) -TimeoutSeconds 8
        $result.Code | Should -Be 'FAIL_PROXY_UNREACHABLE'
    }

    It 'enforces a total deadline when the proxy never answers CONNECT' {
        $script:Server = Start-FakeConnectServer -Behavior 'hang'
        $clock = [Diagnostics.Stopwatch]::StartNew()
        $result = Invoke-AgainstFake -Port $script:Server.Port -TimeoutSeconds 1
        $clock.Stop()
        $result.Code | Should -Be 'FAIL_PROXY_TIMEOUT'
        $clock.Elapsed.TotalSeconds | Should -BeLessThan 5
    }

    It 'enforces the deadline during the TLS handshake after a 200' {
        $script:Server = Start-FakeConnectServer -Behavior '200-hang'
        $clock = [Diagnostics.Stopwatch]::StartNew()
        $result = Invoke-AgainstFake -Port $script:Server.Port -TimeoutSeconds 1
        $clock.Stop()
        $result.Code | Should -Be 'FAIL_PROXY_TIMEOUT'
        $clock.Elapsed.TotalSeconds | Should -BeLessThan 5
    }
}

Describe 'ConvertTo-OsintSquidUpstreamConfig' {
    It 'returns the single comment line for a null Enforcement' {
        ConvertTo-OsintSquidUpstreamConfig -Enforcement $null | Should -BeExactly "# vpn mode: no upstream peer`n"
    }

    It 'renders the exact snippet without tls' {
        $enforcement = [pscustomobject]@{ Mode = 'routed-proxy'; PeerIp = '203.0.113.10'; PeerPort = 3128; Tls = $false }
        $expected = "cache_peer 203.0.113.10 parent 3128 0 no-query no-digest default name=routed`n" +
        "cache_peer_access routed allow all`nnever_direct allow all`nnonhierarchical_direct off`nprefer_direct off`n"
        ConvertTo-OsintSquidUpstreamConfig -Enforcement $enforcement | Should -BeExactly $expected
    }

    It 'appends tls to the cache_peer line' {
        $enforcement = [pscustomobject]@{ Mode = 'routed-proxy'; PeerIp = '2606:4700::1111'; PeerPort = 3129; Tls = $true }
        $expected = "cache_peer 2606:4700::1111 parent 3129 0 no-query no-digest default name=routed tls`n" +
        "cache_peer_access routed allow all`nnever_direct allow all`nnonhierarchical_direct off`nprefer_direct off`n"
        ConvertTo-OsintSquidUpstreamConfig -Enforcement $enforcement | Should -BeExactly $expected
    }

    It 'uses LF line endings only and refuses a malformed peer' {
        $enforcement = [pscustomobject]@{ Mode = 'routed-proxy'; PeerIp = '203.0.113.10'; PeerPort = 3128; Tls = $false }
        (ConvertTo-OsintSquidUpstreamConfig -Enforcement $enforcement) | Should -Not -Match "`r"
        { ConvertTo-OsintSquidUpstreamConfig -Enforcement ([pscustomobject]@{ PeerIp = "1.2.3.4`nnever_direct deny all"; PeerPort = 1; Tls = $false }) } | Should -Throw
        { ConvertTo-OsintSquidUpstreamConfig -Enforcement ([pscustomobject]@{ PeerIp = '1.2.3.4'; PeerPort = 70000; Tls = $false }) } | Should -Throw
    }
}

Describe 'routed-proxy ledger' {
    It 'logs proxyIp and proxyPort but never the URL userinfo or argv' {
        $json = New-RoutedConfigJson -Url 'http://svcuser:SECRETPW@proxy.test:3128'
        $ledger = Join-Path $script:Sandbox 'routed-ledger.jsonl'
        $result = Invoke-RoutedCore -ConfigPath (New-ConfigFile -Json $json) -Ledger $ledger -Seams @{ ProxyProbe = (New-CountingProbe).Probe; Resolver = $script:PublicResolver; HostAddresses = @() }
        $result.Code | Should -Be 'PASS_ROUTED_PROXY'
        $raw = Get-Content -LiteralPath $ledger -Raw
        $entry = ($raw.Trim() | ConvertFrom-Json)
        $entry.outcome | Should -Be 'pass'
        $entry.code | Should -Be 'PASS_ROUTED_PROXY'
        $entry.proxyIp | Should -Be '203.0.113.10'
        $entry.proxyPort | Should -Be 3128
        $entry.provider | Should -Be 'routed-proxy'
        $raw | Should -Not -Match 'SECRETPW|svcuser'
        (($result | ConvertTo-Json -Depth 6) -join '') | Should -Not -Match 'SECRETPW|svcuser'
    }

    It 'records a rejected address with its proxyIp and a fail outcome' {
        $ledger = Join-Path $script:Sandbox 'routed-ledger-fail.jsonl'
        Invoke-RoutedCore -ConfigPath (New-ConfigFile -Json (New-RoutedConfigJson)) -Ledger $ledger -Seams @{ ProxyProbe = (New-CountingProbe).Probe; Resolver = { '127.0.0.1' }; HostAddresses = @() } | Out-Null
        $entry = (Get-Content -LiteralPath $ledger -Raw).Trim() | ConvertFrom-Json
        $entry.outcome | Should -Be 'fail'
        $entry.code | Should -Be 'FAIL_PROXY_ADDRESS_REJECTED'
        $entry.proxyIp | Should -Be '127.0.0.1'
    }

    It 'leaves vpn-mode ledger lines without proxy fields' {
        $ledger = Join-Path $script:Sandbox 'vpn-ledger.jsonl'
        $provider = @{
            GetPlatformName          = { 'Windows' }
            GetDefaultRouteInterface = { @{ Index = 62; Alias = 'peer' } }
            GetUpAdapters            = { @(@{ Index = 62; Name = 'peer'; Description = 'WireGuard Tunnel' }) }
        }
        Invoke-RoutedCore -ConfigPath (New-ConfigFile -Json '{"vpnNamePatterns":["WireGuard"]}') -Provider $provider -Ledger $ledger | Out-Null
        (Get-Content -LiteralPath $ledger -Raw) | Should -Not -Match 'proxyIp|proxyPort'
    }
}
