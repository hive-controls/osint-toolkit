<#
    OsintNetworkGate.psm1

    Shared network gate for the OSINT launchers: "is public traffic leaving through an allowlisted
    VPN adapter right now?". A library never terminates the host process; callers map the result to an
    a process code with Get-OsintGateExitCode. Every tool runner (run-maigret, run-phone, run-scanner, run-torbot) calls it.

    Seam: a PROVIDER is a hashtable of scriptblocks
        GetPlatformName          -> string
        GetDefaultRouteInterface -> @{ Index; Alias } or $null
        GetUpAdapters            -> @( @{ Index; Name; Description } ... )
    Providers are chosen by platform only. There is deliberately no env/config switch for it.
    Config parsing and adapter matching live above the seam.
#>

. (Join-Path $PSScriptRoot 'OsintTool.Common.ps1')
. (Join-Path $PSScriptRoot 'OsintRoutedProxy.ps1')

$script:GateSchemaVersion = 1
$script:RouteProbeAddress = '1.1.1.1'
$script:SupportedPlatforms = @('Windows')
$script:ToolProfiles = @{
    maigret = @{ ConfigTool = 'MaigretLauncher'; FileName = 'maigret-gate.json'; LocalDir = 'Maigret Docker' }
    phone   = @{ ConfigTool = 'PhoneLookup'; FileName = 'phone-gate.json'; LocalDir = 'Phone Lookup' }
    torbot  = @{ ConfigTool = 'TorBotLauncher'; FileName = 'torbot-gate.json'; LocalDir = 'TorBot Docker' }
    scanner = @{ ConfigTool = 'ScannerLauncher'; FileName = 'scanner-gate.json'; LocalDir = 'User-Scanner Docker' }
}
$script:InformationalTokens = @('--help', '-h', '--version')
$script:PhoneInformationalTokens = @('--init-secrets')

function Get-OsintPlatformName {
    if ($PSVersionTable.PSEdition -eq 'Desktop') { return 'Windows' }
    if ($IsWindows) { return 'Windows' }
    if ($IsLinux) { return 'Linux' }
    if ($IsMacOS) { return 'macOS' }
    return 'Unknown'
}

function Get-OsintGateProvider {
    param([string] $PlatformName = (Get-OsintPlatformName))

    if ($PlatformName -ne 'Windows') {
        return @{ GetPlatformName = { $PlatformName }.GetNewClosure() }
    }
    return @{
        GetPlatformName          = { 'Windows' }
        GetDefaultRouteInterface = {
            $route = Find-NetRoute -RemoteIPAddress $script:RouteProbeAddress -ErrorAction Stop |
                Where-Object { $_.InterfaceIndex } | Select-Object -First 1
            if (-not $route) { return $null }
            @{ Index = [int] $route.InterfaceIndex; Alias = [string] $route.InterfaceAlias }
        }
        GetUpAdapters            = {
            @(Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -eq 'Up' } | ForEach-Object {
                    @{ Index = [int] $_.ifIndex; Name = [string] $_.Name; Description = [string] $_.InterfaceDescription }
                })
        }
    }
}

function Get-OsintGateConfigCandidates {
    param([Parameter(Mandatory)] [string] $Tool)

    $profile = $script:ToolProfiles[$Tool]
    $repositoryRoot = Split-Path -Parent $PSScriptRoot
    return @(
        (Join-Path (Get-OsintConfigDir -Tool $profile.ConfigTool) $profile.FileName),
        (Join-Path (Join-Path (Join-Path $repositoryRoot $profile.LocalDir) 'gate') $profile.FileName),
        (Join-Path (Join-Path $PSScriptRoot 'gate') 'osint-gate.example.json')
    )
}

function Test-OsintGatePattern {
    param($Pattern)

    if ($Pattern -isnot [string]) { return $false }
    if ($Pattern.Length -lt 3) { return $false }
    return ($Pattern -notmatch '^[\*\?\s]+$')
}

function Read-OsintGateConfig {
    param([Parameter(Mandatory)] [string[]] $Candidates)

    $path = $Candidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
    if (-not $path) { return @{ Error = 'No gate configuration file was found.'; Path = $null } }
    try { $config = Get-Content -LiteralPath $path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop }
    catch { return @{ Error = "Gate configuration is not valid JSON: $($_.Exception.Message)"; Path = $path } }

    $isRouted = [bool] ($config -and $config.PSObject.Properties['mode'] -and $config.mode -ceq 'routed-proxy')
    $patterns = $null
    if ($config -and $config.PSObject.Properties['vpnNamePatterns']) { $patterns = $config.vpnNamePatterns }
    if (-not $isRouted) {
        if ($patterns -isnot [array] -or $patterns.Count -eq 0) {
            return @{ Error = 'vpnNamePatterns must be a non-empty array.'; Path = $path }
        }
        foreach ($pattern in $patterns) {
            if (-not (Test-OsintGatePattern -Pattern $pattern)) {
                return @{ Error = "vpnNamePatterns entry '$pattern' is too short (min 3 characters) or wildcard-only."; Path = $path }
            }
        }
    }
    $problem = Get-OsintGateConfigProblem -Config $config
    if ($problem) { return @{ Error = $problem; Path = $path } }
    if ($isRouted) {
        return @{ Error = $null; Path = $path; Mode = 'routed-proxy'; Patterns = @(); RoutedProxy = (ConvertTo-OsintRoutedProxySettings -Block $config.routedProxy) }
    }
    return @{ Error = $null; Path = $path; Mode = 'vpn'; Patterns = [string[]] $patterns }
}

function Get-OsintGateConfigProblem {
    param([Parameter(Mandatory)] $Config)

    if ($Config.PSObject.Properties['schemaVersion']) {
        $version = $Config.schemaVersion
        $isInteger = ($version -is [int] -or $version -is [long])
        if (-not $isInteger -or $version -gt $script:GateSchemaVersion) {
            return "Unsupported gate config schemaVersion $version (this build supports <=$($script:GateSchemaVersion))."
        }
    }
    if ($Config.PSObject.Properties['proxyUrls'] -and @($Config.proxyUrls | Where-Object { $_ }).Count -gt 0) {
        return 'proxyUrls is retired and no longer evaluated; remove it (use mode "routed-proxy" with a `routedProxy` block instead).'
    }
    return Get-OsintRoutedProxyConfigProblem -Config $Config
}

function New-OsintGateResult {
    param(
        [bool] $Passed,
        [bool] $Skipped = $false,
        [Parameter(Mandatory)] [string] $Code,
        [Parameter(Mandatory)] [string] $Reason,
        $Route = $null,
        [string[]] $Evidence = @(),
        [string] $ConfigPath = $null,
        $Enforcement = $null
    )

    $result = [pscustomobject]@{
        Passed        = $Passed
        Skipped       = $Skipped
        Code          = $Code
        Reason        = $Reason
        Route         = $Route
        Evidence      = @($Evidence)
        ConfigPath    = $ConfigPath
        SchemaVersion = $script:GateSchemaVersion
        Enforcement   = $Enforcement
    }
    $result.PSObject.TypeNames.Insert(0, 'Osint.GateResult')
    return $result
}

function New-OsintGateRoute {
    param($Interface, $Adapter, [string] $ProviderName)

    $alias = if ($Interface) { $Interface.Alias } elseif ($Adapter) { $Adapter.Name } else { $null }
    $index = if ($Interface) { $Interface.Index } elseif ($Adapter) { $Adapter.Index } else { $null }
    $description = if ($Adapter) { $Adapter.Description } else { $null }
    return [pscustomobject]@{
        InterfaceIndex     = $index
        InterfaceAlias     = $alias
        AdapterDescription = $description
        Provider           = $ProviderName
    }
}

function Find-OsintGateAdapters {
    param([Parameter(Mandatory)] $Adapters, [Parameter(Mandatory)] [string[]] $Patterns, [Parameter(Mandatory)] [int] $RouteIndex)

    $matched = New-Object System.Collections.Generic.List[object]
    $evidence = New-Object System.Collections.Generic.List[string]
    foreach ($adapter in $Adapters) {
        $haystack = '{0} {1}' -f $adapter.Name, $adapter.Description
        $isMatch = $false
        foreach ($pattern in $Patterns) {
            if ($haystack -like ('*{0}*' -f $pattern)) { $isMatch = $true; break }
        }
        $ownsRoute = ([int] $adapter.Index -eq $RouteIndex)
        [void]$evidence.Add(('adapter {0} "{1}" ({2}): allowlisted={3} owns-route={4}' -f $adapter.Index, $adapter.Name, $adapter.Description, $isMatch, $ownsRoute))
        if ($isMatch) { [void]$matched.Add($adapter) }
    }
    return @{ Matched = $matched.ToArray(); Evidence = $evidence.ToArray() }
}

function Get-OsintGateDecision {
    param([Parameter(Mandatory)] $Provider, [Parameter(Mandatory)] [string[]] $Patterns)

    $providerName = [string] (& $Provider.GetPlatformName)
    try {
        $route = & $Provider.GetDefaultRouteInterface
        $adapters = @(& $Provider.GetUpAdapters)
    }
    catch { return @{ Code = 'FAIL_ROUTE_UNREADABLE'; Reason = "Could not read the network state, so no VPN can be confirmed: $($_.Exception.Message)"; Route = $null; Evidence = @() } }
    if (-not $route -or $null -eq $route.Index) {
        return @{ Code = 'FAIL_ROUTE_UNREADABLE'; Reason = 'Could not read the route to the internet, so no VPN can be confirmed.'; Route = $null; Evidence = @() }
    }

    $found = Find-OsintGateAdapters -Adapters $adapters -Patterns $Patterns -RouteIndex ([int] $route.Index)
    $carrier = $found.Matched | Where-Object { [int] $_.Index -eq [int] $route.Index } | Select-Object -First 1
    if ($carrier) {
        return @{ Code = 'PASS_VPN_ROUTE'; Reason = "VPN adapter is up and carrying internet traffic: $($carrier.Name) ($($carrier.Description))"; Route = (New-OsintGateRoute -Interface $route -Adapter $carrier -ProviderName $providerName); Evidence = $found.Evidence }
    }
    $fallbackRoute = New-OsintGateRoute -Interface $route -Adapter $null -ProviderName $providerName
    if ($found.Matched.Count -gt 0) {
        $names = ($found.Matched | ForEach-Object { $_.Name }) -join ', '
        return @{ Code = 'FAIL_ADAPTER_NOT_ROUTING'; Reason = "A VPN adapter is up but internet traffic does NOT route through it: $names"; Route = $fallbackRoute; Evidence = $found.Evidence }
    }
    return @{ Code = 'FAIL_NO_MATCHING_ADAPTER'; Reason = 'No connected adapter matched the VPN name allowlist.'; Route = $fallbackRoute; Evidence = $found.Evidence }
}

function Test-OsintInformationalArguments {
    param(
        [Parameter(Mandatory)] [ValidateSet('maigret', 'phone', 'torbot', 'scanner')] [string] $Tool,
        [AllowNull()] [AllowEmptyCollection()] [string[]] $Arguments
    )

    if (-not $Arguments -or $Arguments.Count -eq 0) { return $true }
    if ($Arguments.Count -ne 1) { return $false }
    $allowed = @($script:InformationalTokens)
    if ($Tool -eq 'phone') { $allowed += $script:PhoneInformationalTokens }
    foreach ($token in $allowed) {
        if ($Arguments[0] -ceq $token) { return $true }
    }
    return $false
}

function Write-OsintGateLedger {
    param(
        [Parameter(Mandatory)] $Result,
        [Parameter(Mandatory)] [string] $Tool,
        [Parameter(Mandatory)] [string] $Entrypoint,
        [Parameter(Mandatory)] [string] $LedgerPath
    )

    $outcome = if ($Result.Skipped) { 'skip' } elseif ($Result.Passed) { 'pass' } else { 'fail' }
    $entry = [ordered]@{
        ts         = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
        schema     = $script:GateSchemaVersion
        tool       = $Tool
        entrypoint = $Entrypoint
        outcome    = $outcome
        code       = $Result.Code
        ifIndex    = if ($Result.Route) { $Result.Route.InterfaceIndex } else { $null }
        adapter    = if ($Result.Route) { $Result.Route.InterfaceAlias } else { $null }
        provider   = if ($Result.Route) { $Result.Route.Provider } else { $null }
    }
    if ($Result.Route -and $Result.Route.PSObject.Properties['ProxyIp']) {
        $entry['proxyIp'] = $Result.Route.ProxyIp
        $entry['proxyPort'] = $Result.Route.ProxyPort
    }
    try {
        $directory = Split-Path -Parent $LedgerPath
        if ($directory -and -not (Test-Path -LiteralPath $directory)) {
            New-Item -ItemType Directory -Path $directory -Force -ErrorAction Stop | Out-Null
        }
        Add-Content -LiteralPath $LedgerPath -Value ($entry | ConvertTo-Json -Compress) -Encoding utf8 -ErrorAction Stop
    }
    catch { Write-Warning "Gate ledger write failed (decision unchanged): $($_.Exception.Message)" }
}

function Invoke-OsintGateCore {
    param(
        [Parameter(Mandatory)] [ValidateSet('maigret', 'phone', 'torbot', 'scanner')] [string] $Tool,
        [switch] $ApplySkipRule,
        [string[]] $Arguments = @(),
        [ValidateSet('runner', 'menu')] [string] $Entrypoint = 'runner',
        $Provider = $null,
        [string[]] $ConfigCandidates = $null,
        [string] $LedgerPath = (Join-Path (Get-OsintConfigDir -Tool 'OsintGate') 'gate-events.jsonl'),
        $ProxyProbe = $null,
        $HostAddresses = $null,
        $Resolver = $null,
        [switch] $AllowLoopbackForTests
    )

    $result = Resolve-OsintGateResult -Tool $Tool -ApplySkipRule:$ApplySkipRule -Arguments $Arguments -Provider $Provider -ConfigCandidates $ConfigCandidates `
        -ProxyProbe $ProxyProbe -HostAddresses $HostAddresses -Resolver $Resolver -AllowLoopbackForTests:$AllowLoopbackForTests
    Write-OsintGateLedger -Result $result -Tool $Tool -Entrypoint $Entrypoint -LedgerPath $LedgerPath
    return $result
}

function Resolve-OsintGateResult {
    param(
        [string] $Tool, [switch] $ApplySkipRule, [string[]] $Arguments, $Provider, [string[]] $ConfigCandidates,
        $ProxyProbe = $null, $HostAddresses = $null, $Resolver = $null, [switch] $AllowLoopbackForTests
    )

    if ($ApplySkipRule -and (Test-OsintInformationalArguments -Tool $Tool -Arguments $Arguments)) {
        return New-OsintGateResult -Passed $false -Skipped $true -Code 'SKIP_INFORMATIONAL' -Reason 'Informational invocation: no network traffic, gate not required.'
    }
    if (-not $ConfigCandidates) { $ConfigCandidates = Get-OsintGateConfigCandidates -Tool $Tool }
    $loaded = Read-OsintGateConfig -Candidates $ConfigCandidates
    if ($loaded.Error) {
        return New-OsintGateResult -Passed $false -Code 'FAIL_CONFIG' -Reason $loaded.Error -ConfigPath $loaded.Path
    }
    if ($loaded.Mode -eq 'routed-proxy') {
        return Resolve-OsintRoutedProxyResult -Loaded $loaded -ProxyProbe $ProxyProbe -HostAddresses $HostAddresses -Resolver $Resolver -AllowLoopbackForTests:$AllowLoopbackForTests
    }
    if (-not $Provider) { $Provider = Get-OsintGateProvider }
    $platform = [string] (& $Provider.GetPlatformName)
    if ($platform -notin $script:SupportedPlatforms) {
        return New-OsintGateResult -Passed $false -Code 'FAIL_PROVIDER_UNSUPPORTED' -Reason "Network gate has no route provider for platform '$platform'; refusing (fail closed)." -ConfigPath $loaded.Path
    }
    $decision = Get-OsintGateDecision -Provider $Provider -Patterns $loaded.Patterns
    $passed = ($decision.Code -eq 'PASS_VPN_ROUTE')
    return New-OsintGateResult -Passed $passed -Code $decision.Code -Reason $decision.Reason -Route $decision.Route -Evidence @($decision.Evidence) -ConfigPath $loaded.Path
}

function Test-OsintNetworkGate {
    param(
        [Parameter(Mandatory)] [ValidateSet('maigret', 'phone', 'torbot', 'scanner')] [string] $Tool,
        [switch] $Quiet
    )

    $result = Invoke-OsintGateCore -Tool $Tool
    if (-not $Quiet) {
        $color = if ($result.Passed) { 'Green' } else { 'Yellow' }
        Write-Host $result.Reason -ForegroundColor $color
    }
    return $result
}

function Invoke-OsintNetworkGate {
    param(
        [Parameter(Mandatory)] [ValidateSet('maigret', 'phone', 'torbot', 'scanner')] [string] $Tool,
        [AllowNull()] [AllowEmptyCollection()] [string[]] $Arguments,
        [ValidateSet('runner', 'menu')] [string] $Entrypoint = 'runner'
    )

    $result = Invoke-OsintGateCore -Tool $Tool -ApplySkipRule -Arguments $Arguments -Entrypoint $Entrypoint
    if ($result.Skipped -or $result.Passed) {
        if ($result.Passed) { Write-Host $result.Reason -ForegroundColor Green }
        return $result
    }
    Write-Host 'NETWORK GATE FAILED' -ForegroundColor Black -BackgroundColor Red
    Write-Host $result.Reason -ForegroundColor Yellow
    if ($result.ConfigPath) { Write-Host "Gate config: $($result.ConfigPath)" -ForegroundColor DarkGray }
    if ($result.Route -and $result.Route.PSObject.Properties['Mode'] -and $result.Route.Mode -eq 'routed-proxy') {
        Write-Host 'Fix the routed proxy (see the gate config routedProxy block), then retry.' -ForegroundColor Yellow
        return $result
    }
    Write-Host 'Connect an allowlisted VPN that carries your internet traffic, then retry.' -ForegroundColor Yellow
    return $result
}

function Assert-OsintNetworkGate {
    param(
        [Parameter(Mandatory)] [ValidateSet('maigret', 'phone', 'torbot', 'scanner')] [string] $Tool,
        [AllowNull()] [AllowEmptyCollection()] [string[]] $Arguments,
        [ValidateSet('runner', 'menu')] [string] $Entrypoint = 'runner'
    )

    $result = Invoke-OsintNetworkGate @PSBoundParameters
    return ($result.Passed -or $result.Skipped)
}

function Get-OsintGateExitCode {
    param([Parameter(Mandatory)] $Result)

    if ($Result.Passed -or $Result.Skipped) { return 0 }
    if ($Result.Code -eq 'FAIL_CONFIG') { return 78 }
    return 75
}

Export-ModuleMember -Function Test-OsintNetworkGate, Invoke-OsintNetworkGate, Assert-OsintNetworkGate, Test-OsintInformationalArguments, Get-OsintGateExitCode, ConvertTo-OsintSquidUpstreamConfig
