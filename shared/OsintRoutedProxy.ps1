<#
    OsintRoutedProxy.ps1

    Routed-proxy mode for OsintNetworkGate.psm1 (dot-sourced; private to that module, no exports).
    mode="vpn" and mode="routed-proxy" are exclusive: the VPN adapter state is never consulted in
    routed-proxy mode, and the proxy is never probed in vpn mode. Ambient HTTP(S)_PROXY / ALL_PROXY
    variables are never read; the proxy comes only from the gate config.

    A passing routed-proxy decision carries Enforcement (PeerIp/PeerPort/Tls) so the egress sidecar can
    be pinned to the exact address that was verified (see ConvertTo-OsintSquidUpstreamConfig).

    Test seams live on Invoke-OsintGateCore only (ProxyProbe / HostAddresses / Resolver /
    AllowLoopbackForTests) and are never part of the public surface.
#>

$script:ProxyConfigModes = @('vpn', 'routed-proxy')
$script:ProxyHeaderLimitBytes = 4096
$script:ProxyTunnelPort = 443

function Test-OsintOptionalBoolean {
    param([Parameter(Mandatory)] $Block, [Parameter(Mandatory)] [string] $Name)

    if (-not $Block.PSObject.Properties[$Name]) { return $true }
    return ($Block.$Name -is [bool])
}

function Get-OsintRoutedProxyConfigProblem {
    param([Parameter(Mandatory)] $Config)

    $hasMode = [bool] $Config.PSObject.Properties['mode']
    if ($hasMode -and ($Config.mode -isnot [string] -or $Config.mode -cnotin $script:ProxyConfigModes)) {
        return 'mode must be one of: vpn, routed-proxy.'
    }
    if (-not $hasMode -or $Config.mode -cne 'routed-proxy') { return $null }
    $block = if ($Config.PSObject.Properties['routedProxy']) { $Config.routedProxy } else { $null }
    if ($block -isnot [pscustomobject]) { return 'mode routed-proxy requires a routedProxy object.' }
    return Get-OsintRoutedProxyBlockProblem -Block $block
}

function Get-OsintRoutedProxyUrlProblem {
    param([Parameter(Mandatory)] $Block, [bool] $TlsToProxy)

    $urlText = if ($Block.PSObject.Properties['url']) { $Block.url } else { $null }
    if ($urlText -isnot [string] -or [string]::IsNullOrWhiteSpace($urlText)) { return 'routedProxy.url is required.' }
    $uri = $null
    if (-not [Uri]::TryCreate($urlText, [UriKind]::Absolute, [ref] $uri)) { return 'routedProxy.url is not a valid absolute URL.' }
    $scheme = $uri.Scheme.ToLowerInvariant()
    if ($scheme -like 'socks*') { return "routedProxy.url scheme '$scheme' is not supported: squid cannot chain SOCKS parents." }
    if ($scheme -notin @('http', 'https')) { return "routedProxy.url scheme '$scheme' is not supported (use http, or https with tlsToProxy=true)." }
    if ($scheme -eq 'https' -and -not $TlsToProxy) { return 'routedProxy.url uses https, which requires tlsToProxy=true.' }
    if ($scheme -eq 'http' -and $TlsToProxy) { return 'tlsToProxy=true requires an https routedProxy.url.' }
    if (-not $uri.DnsSafeHost) { return 'routedProxy.url has no host.' }
    if ($uri.Port -lt 1 -or $uri.Port -gt 65535) { return 'routedProxy.url port must be 1..65535.' }
    return $null
}

function Get-OsintRoutedProxyBlockProblem {
    param([Parameter(Mandatory)] $Block)

    foreach ($flag in @('allowPrivate', 'tlsToProxy')) {
        if (-not (Test-OsintOptionalBoolean -Block $Block -Name $flag)) { return "routedProxy.$flag must be true or false." }
    }
    $tlsToProxy = [bool] ($Block.PSObject.Properties['tlsToProxy'] -and $Block.tlsToProxy)
    $urlProblem = Get-OsintRoutedProxyUrlProblem -Block $Block -TlsToProxy $tlsToProxy
    if ($urlProblem) { return $urlProblem }
    $verifyHost = if ($Block.PSObject.Properties['verifyHost']) { $Block.verifyHost } else { $null }
    if ($verifyHost -isnot [string] -or [Uri]::CheckHostName($verifyHost) -ne [UriHostNameType]::Dns) {
        return 'routedProxy.verifyHost must be a non-empty hostname (not an IP address).'
    }
    if ($Block.PSObject.Properties['connectTimeoutSeconds']) {
        $timeout = $Block.connectTimeoutSeconds
        if (($timeout -isnot [int] -and $timeout -isnot [long]) -or $timeout -lt 1 -or $timeout -gt 30) {
            return 'routedProxy.connectTimeoutSeconds must be an integer from 1 to 30.'
        }
    }
    return $null
}

function ConvertTo-OsintRoutedProxySettings {
    param([Parameter(Mandatory)] $Block)

    $uri = [Uri] $Block.url
    $timeout = if ($Block.PSObject.Properties['connectTimeoutSeconds']) { [int] $Block.connectTimeoutSeconds } else { 5 }
    return [pscustomobject]@{
        Host           = $uri.DnsSafeHost
        Port           = [int] $uri.Port
        Scheme         = $uri.Scheme.ToLowerInvariant()
        VerifyHost     = [string] $Block.verifyHost
        AllowPrivate   = [bool] ($Block.PSObject.Properties['allowPrivate'] -and $Block.allowPrivate)
        TlsToProxy     = [bool] ($Block.PSObject.Properties['tlsToProxy'] -and $Block.tlsToProxy)
        TimeoutSeconds = $timeout
    }
}

function ConvertTo-OsintAddressKey {
    param([Parameter(Mandatory)] [System.Net.IPAddress] $Address)

    if ($Address.IsIPv4MappedToIPv6) { $Address = $Address.MapToIPv4() }
    return ($Address.GetAddressBytes() -join '.')
}

function Get-OsintAddressClassName {
    param([Parameter(Mandatory)] [System.Net.IPAddress] $Address, [string[]] $HostAddresses = @())

    $bytes = $Address.GetAddressBytes()
    $isV4 = ($bytes.Length -eq 4)
    if ($isV4 -and $bytes[0] -eq 0) { return 'unspecified' }
    if (-not $isV4 -and $Address.Equals([System.Net.IPAddress]::IPv6Any)) { return 'unspecified' }
    if ([System.Net.IPAddress]::IsLoopback($Address)) { return 'loopback' }
    if ($isV4 -and $bytes[0] -eq 169 -and $bytes[1] -eq 254) { return 'link-local' }
    if (-not $isV4 -and $Address.IsIPv6LinkLocal) { return 'link-local' }
    if (($isV4 -and $bytes[0] -ge 224 -and $bytes[0] -le 239) -or (-not $isV4 -and $Address.IsIPv6Multicast)) { return 'multicast' }
    if ($isV4 -and $bytes[0] -ge 240) { return 'reserved' }
    $key = ConvertTo-OsintAddressKey -Address $Address
    foreach ($owned in $HostAddresses) {
        $parsed = $null
        if ([System.Net.IPAddress]::TryParse($owned, [ref] $parsed) -and (ConvertTo-OsintAddressKey -Address $parsed) -eq $key) { return 'host-owned' }
    }
    if (Test-OsintPrivateAddressBytes -Bytes $bytes -Address $Address) { return 'private' }
    return 'public'
}

function Test-OsintPrivateAddressBytes {
    param([Parameter(Mandatory)] [byte[]] $Bytes, [Parameter(Mandatory)] [System.Net.IPAddress] $Address)

    if ($Bytes.Length -eq 4) {
        if ($Bytes[0] -eq 10) { return $true }
        if ($Bytes[0] -eq 172 -and $Bytes[1] -ge 16 -and $Bytes[1] -le 31) { return $true }
        if ($Bytes[0] -eq 192 -and $Bytes[1] -eq 168) { return $true }
        return ($Bytes[0] -eq 100 -and ($Bytes[1] -band 0xC0) -eq 64)
    }
    return ((($Bytes[0] -band 0xFE) -eq 0xFC) -or $Address.IsIPv6SiteLocal)
}

function Test-OsintProxyAddressClass {
    param(
        [Parameter(Mandatory)] $IPAddress,
        [switch] $AllowPrivate,
        [string[]] $HostAddresses = @(),
        [switch] $AllowLoopback
    )

    $address = if ($IPAddress -is [System.Net.IPAddress]) { $IPAddress } else { [System.Net.IPAddress]::Parse([string] $IPAddress) }
    if ($address.IsIPv4MappedToIPv6) { $address = $address.MapToIPv4() }
    $class = Get-OsintAddressClassName -Address $address -HostAddresses $HostAddresses
    $allowed = switch ($class) {
        'public' { $true }
        'private' { [bool] $AllowPrivate }
        'loopback' { [bool] $AllowLoopback }
        default { $false }
    }
    return [pscustomobject]@{ Allowed = [bool] $allowed; Class = $class }
}

function Get-OsintHostAddresses {
    return @([System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() |
            ForEach-Object { $_.GetIPProperties().UnicastAddresses } |
            ForEach-Object { $_.Address.ToString() })
}

function Resolve-OsintProxyAddress {
    param([Parameter(Mandatory)] [string] $HostName, $Resolver = $null)

    $candidates = if ($Resolver) { @(& $Resolver $HostName) } else { @([System.Net.Dns]::GetHostAddresses($HostName)) }
    $parsed = @($candidates | ForEach-Object {
            $address = $null
            if ([System.Net.IPAddress]::TryParse([string] $_, [ref] $address)) { $address }
        })
    if ($parsed.Count -eq 0) { throw "no usable address for the proxy host." }
    $preferred = $parsed | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1
    if (-not $preferred) { $preferred = $parsed[0] }
    return $preferred.ToString()
}

function Get-OsintInnermostMessage {
    param([Parameter(Mandatory)] [Exception] $Exception)

    while ($Exception.InnerException) { $Exception = $Exception.InnerException }
    return $Exception.Message
}

function Wait-OsintProxyTask {
    param(
        [Parameter(Mandatory)] $Task,
        [Parameter(Mandatory)] $Stopwatch,
        [Parameter(Mandatory)] [int] $DeadlineMs,
        [Parameter(Mandatory)] [string] $FailureCode,
        [Parameter(Mandatory)] [string] $Phase
    )

    $remaining = [Math]::Max(0, $DeadlineMs - [int] $Stopwatch.ElapsedMilliseconds)
    try { $completed = $Task.Wait($remaining) }
    catch { throw ('PROXYFAIL:{0}:{1} failed: {2}' -f $FailureCode, $Phase, (Get-OsintInnermostMessage -Exception $_.Exception)) }
    if (-not $completed) { throw ('PROXYFAIL:FAIL_PROXY_TIMEOUT:{0} exceeded the {1} ms deadline' -f $Phase, $DeadlineMs) }
}

function Open-OsintTlsStream {
    param($Stream, [string] $TargetHost, $Stopwatch, [int] $DeadlineMs, [string] $Phase)

    $secure = [System.Net.Security.SslStream]::new($Stream, $false)
    Wait-OsintProxyTask -Task $secure.AuthenticateAsClientAsync($TargetHost) -Stopwatch $Stopwatch -DeadlineMs $DeadlineMs -FailureCode 'FAIL_PROXY_TLS' -Phase $Phase
    return $secure
}

function Read-OsintConnectStatus {
    param($Stream, [string] $VerifyHost, $Stopwatch, [int] $DeadlineMs)

    $request = [Text.Encoding]::ASCII.GetBytes("CONNECT ${VerifyHost}:$($script:ProxyTunnelPort) HTTP/1.1`r`nHost: ${VerifyHost}:$($script:ProxyTunnelPort)`r`n`r`n")
    Wait-OsintProxyTask -Task $Stream.WriteAsync($request, 0, $request.Length) -Stopwatch $Stopwatch -DeadlineMs $DeadlineMs -FailureCode 'FAIL_PROXY_UNREACHABLE' -Phase 'CONNECT write'
    $limit = $script:ProxyHeaderLimitBytes
    $buffer = [byte[]]::new($limit)
    $total = 0
    while ($total -lt $limit) {
        $readTask = $Stream.ReadAsync($buffer, $total, $limit - $total)
        Wait-OsintProxyTask -Task $readTask -Stopwatch $Stopwatch -DeadlineMs $DeadlineMs -FailureCode 'FAIL_PROXY_UNREACHABLE' -Phase 'CONNECT status read'
        if ($readTask.Result -eq 0) { throw 'PROXYFAIL:FAIL_PROXY_UNREACHABLE:proxy closed the connection before a status line' }
        $total += $readTask.Result
        $text = [Text.Encoding]::ASCII.GetString($buffer, 0, $total)
        if ($text.IndexOf([char] 10) -lt 0) { continue }
        $status = if ($text -match '^HTTP/1\.[01] (\d{3})') { [int] $Matches[1] } else { 0 }
        if ($status -ne 200 -or $text.Contains("`r`n`r`n")) { return $status }
    }
    throw "PROXYFAIL:FAIL_PROXY_CONNECT_DENIED:proxy response header exceeded $limit bytes"
}

function Invoke-OsintRoutedProxyProbe {
    param(
        [Parameter(Mandatory)] [string] $Ip,
        [Parameter(Mandatory)] [int] $Port,
        [Parameter(Mandatory)] [string] $VerifyHost,
        [Parameter(Mandatory)] [int] $TimeoutSeconds,
        [bool] $Tls = $false,
        [string] $ProxyHost = $null
    )

    $deadlineMs = $TimeoutSeconds * 1000
    $stopwatch = [Diagnostics.Stopwatch]::StartNew()
    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        Wait-OsintProxyTask -Task $client.ConnectAsync([System.Net.IPAddress]::Parse($Ip), $Port) -Stopwatch $stopwatch -DeadlineMs $deadlineMs -FailureCode 'FAIL_PROXY_UNREACHABLE' -Phase 'TCP connect'
        $stream = $client.GetStream()
        if ($Tls) { $stream = Open-OsintTlsStream -Stream $stream -TargetHost $ProxyHost -Stopwatch $stopwatch -DeadlineMs $deadlineMs -Phase 'TLS to proxy' }
        $status = Read-OsintConnectStatus -Stream $stream -VerifyHost $VerifyHost -Stopwatch $stopwatch -DeadlineMs $deadlineMs
        if ($status -ne 200) { return @{ Status = $status; TlsProtocol = $null; CertSubject = $null; ElapsedMs = [int] $stopwatch.ElapsedMilliseconds } }
        $tunnel = Open-OsintTlsStream -Stream $stream -TargetHost $VerifyHost -Stopwatch $stopwatch -DeadlineMs $deadlineMs -Phase 'TLS handshake through tunnel'
        return @{ Status = 200; TlsProtocol = [string] $tunnel.SslProtocol; CertSubject = [string] $tunnel.RemoteCertificate.Subject; ElapsedMs = [int] $stopwatch.ElapsedMilliseconds }
    }
    finally { $client.Dispose() }
}

function Invoke-OsintProxyProbeSeam {
    param($ProxyProbe, [Parameter(Mandatory)] $Settings, [Parameter(Mandatory)] [string] $PinnedIp)

    $probeArguments = @{
        Ip = $PinnedIp; Port = $Settings.Port; VerifyHost = $Settings.VerifyHost
        TimeoutSeconds = $Settings.TimeoutSeconds; Tls = $Settings.TlsToProxy; ProxyHost = $Settings.Host
    }
    try {
        $probe = if ($ProxyProbe) { & $ProxyProbe @probeArguments } else { Invoke-OsintRoutedProxyProbe @probeArguments }
        return @{ Probe = $probe; Failure = $null }
    }
    catch {
        $message = $_.Exception.Message
        if ($message -match '(?s)^PROXYFAIL:(FAIL_PROXY_[A-Z_]+):(.*)$') {
            return @{ Probe = $null; Failure = @{ Code = $Matches[1]; Reason = "Routed proxy check failed: $($Matches[2])" } }
        }
        return @{ Probe = $null; Failure = @{ Code = 'FAIL_PROXY_UNREACHABLE'; Reason = "Routed proxy check failed: $message" } }
    }
}

function Resolve-OsintRoutedProxyResult {
    param(
        [Parameter(Mandatory)] $Loaded,
        $ProxyProbe = $null,
        $HostAddresses = $null,
        $Resolver = $null,
        [switch] $AllowLoopbackForTests
    )

    $settings = $Loaded.RoutedProxy
    $allowLoopback = [bool] ($AllowLoopbackForTests -and ($null -ne $ProxyProbe -or $null -ne $Resolver))
    try { $pinnedIp = Resolve-OsintProxyAddress -HostName $settings.Host -Resolver $Resolver }
    catch {
        return New-OsintGateResult -Passed $false -Code 'FAIL_PROXY_UNREACHABLE' -Reason "Could not resolve the routed proxy host: $($_.Exception.Message)" -ConfigPath $Loaded.Path
    }
    $route = New-OsintRoutedProxyRoute -Settings $settings -PinnedIp $pinnedIp
    try { $owned = if ($null -ne $HostAddresses) { @($HostAddresses) } else { @(Get-OsintHostAddresses) } }
    catch {
        return New-OsintGateResult -Passed $false -Code 'FAIL_PROXY_ADDRESS_REJECTED' -Reason 'Could not enumerate this host''s addresses, so the proxy address cannot be classified (fail closed).' -Route $route -ConfigPath $Loaded.Path
    }
    $class = Test-OsintProxyAddressClass -IPAddress $pinnedIp -AllowPrivate:$settings.AllowPrivate -HostAddresses $owned -AllowLoopback:$allowLoopback
    $classEvidence = "address class: $($class.Class) ($pinnedIp)"
    if (-not $class.Allowed) {
        return New-OsintGateResult -Passed $false -Code 'FAIL_PROXY_ADDRESS_REJECTED' -Reason "Routed proxy address $pinnedIp is a $($class.Class) address and is not allowed." -Route $route -Evidence @($classEvidence) -ConfigPath $Loaded.Path
    }
    $outcome = Invoke-OsintProxyProbeSeam -ProxyProbe $ProxyProbe -Settings $settings -PinnedIp $pinnedIp
    return ConvertTo-OsintRoutedProxyResult -Outcome $outcome -Settings $settings -PinnedIp $pinnedIp -Route $route -ClassEvidence $classEvidence -ConfigPath $Loaded.Path
}

function New-OsintRoutedProxyRoute {
    param([Parameter(Mandatory)] $Settings, [Parameter(Mandatory)] [string] $PinnedIp)

    return [pscustomobject]@{
        Mode      = 'routed-proxy'
        ProxyHost = $Settings.Host
        ProxyIp   = $PinnedIp
        ProxyPort = $Settings.Port
        Scheme    = $Settings.Scheme
        Provider  = 'routed-proxy'
    }
}

function ConvertTo-OsintRoutedProxyResult {
    param($Outcome, $Settings, [string] $PinnedIp, $Route, [string] $ClassEvidence, [string] $ConfigPath)

    $evidence = @($ClassEvidence)
    if ($Outcome.Failure) {
        return New-OsintGateResult -Passed $false -Code $Outcome.Failure.Code -Reason $Outcome.Failure.Reason -Route $Route -Evidence $evidence -ConfigPath $ConfigPath
    }
    $probe = $Outcome.Probe
    $status = if ($probe -and $null -ne $probe.Status) { [int] $probe.Status } else { 0 }
    $evidence += "connect status: HTTP $status for CONNECT $($Settings.VerifyHost):$($script:ProxyTunnelPort)"
    if ($status -ne 200) {
        return New-OsintGateResult -Passed $false -Code 'FAIL_PROXY_CONNECT_DENIED' -Reason "The routed proxy refused CONNECT to $($Settings.VerifyHost) (HTTP $status)." -Route $Route -Evidence $evidence -ConfigPath $ConfigPath
    }
    if (-not $probe.TlsProtocol) {
        return New-OsintGateResult -Passed $false -Code 'FAIL_PROXY_TLS' -Reason 'The tunnel returned no verified TLS session (fail closed).' -Route $Route -Evidence $evidence -ConfigPath $ConfigPath
    }
    $evidence += "tls protocol: $($probe.TlsProtocol)", "tls certificate subject: $($probe.CertSubject)", "elapsed ms: $($probe.ElapsedMs)"
    $evidence += "enforcement: sidecar peer must be pinned to ${PinnedIp}:$($Settings.Port)"
    $enforcement = [pscustomobject]@{ Mode = 'routed-proxy'; PeerIp = $PinnedIp; PeerPort = [int] $Settings.Port; Tls = [bool] $Settings.TlsToProxy; VerifyHost = [string] $Settings.VerifyHost }
    $reason = "Routed proxy verified: CONNECT $($Settings.VerifyHost):$($script:ProxyTunnelPort) via ${PinnedIp}:$($Settings.Port) returned 200 and TLS validated."
    return New-OsintGateResult -Passed $true -Code 'PASS_ROUTED_PROXY' -Reason $reason -Route $Route -Evidence $evidence -ConfigPath $ConfigPath -Enforcement $enforcement
}

function ConvertTo-OsintSquidUpstreamConfig {
    param([AllowNull()] $Enforcement)

    if ($null -eq $Enforcement) { return "# vpn mode: no upstream peer`n" }
    $peerIp = $null
    if (-not [System.Net.IPAddress]::TryParse([string] $Enforcement.PeerIp, [ref] $peerIp)) { throw 'Enforcement.PeerIp is not an IP address.' }
    $peerPort = [int] $Enforcement.PeerPort
    if ($peerPort -lt 1 -or $peerPort -gt 65535) { throw 'Enforcement.PeerPort must be 1..65535.' }
    $tlsSuffix = if ($Enforcement.Tls) { ' tls' } else { '' }
    $lines = @(
        "cache_peer $($peerIp.ToString()) parent $peerPort 0 no-query no-digest default name=routed$tlsSuffix",
        'cache_peer_access routed allow all',
        'never_direct allow all',
        'nonhierarchical_direct off',
        'prefer_direct off'
    )
    return (($lines -join "`n") + "`n")
}
