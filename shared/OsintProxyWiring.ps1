<#
    OsintProxyWiring.ps1

    Requires OsintNetworkGate.psm1 to be imported first (the runners do; it exports
    ConvertTo-OsintSquidUpstreamConfig) and OsintTool.Common.ps1 (Get-OsintConfigDir).

    Routed-proxy wiring shared by the Maigret, Phone and User-Scanner runners (TorBot is
    excluded in v1). Dot-source after OsintTool.Common.ps1:

        . (Join-Path $projectDirectory '..\shared\OsintProxyWiring.ps1')

    Nothing here calls `exit`: functions return a decision or state object and the runner exits.
    Process codes follow the gate library: 75 = refused/enforcement failed, 78 = configuration or
    library-contract error.
#>

$script:RoutedConfName = 'squid-routed.conf'
$script:ProxyServiceName = 'egress-proxy'

function New-OsintSquidUpstreamFile {
    param(
        [Parameter(Mandatory)] [string] $StateDirectory,
        [Parameter(Mandatory)] $Enforcement
    )

    $text = ConvertTo-OsintSquidUpstreamConfig -Enforcement $Enforcement
    $runDirectory = Join-Path $StateDirectory 'proxy-run'
    New-Item -ItemType Directory -Path $runDirectory -Force | Out-Null
    $path = Join-Path $runDirectory ('upstream-{0}.conf' -f [guid]::NewGuid().ToString('N'))
    [System.IO.File]::WriteAllText($path, $text, (New-Object System.Text.UTF8Encoding($false)))
    return $path
}

function Remove-OsintSquidUpstreamFile {
    param([string] $Path)

    if ([string]::IsNullOrEmpty($Path)) { return }
    Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
}

function Resolve-OsintProxyEnforcementAction {
    param([Parameter(Mandatory)] $GateResult)

    $enforcement = $GateResult.Enforcement
    $routeMode = if ($GateResult.Route) { $GateResult.Route.Mode } else { $null }
    $claimsRouted = ($GateResult.Code -eq 'PASS_ROUTED_PROXY') -or ($GateResult.Passed -and $routeMode -eq 'routed-proxy')

    if ($null -ne $enforcement) {
        if ($enforcement.Mode -eq 'routed-proxy') {
            $verifyHost = $enforcement.PSObject.Properties['VerifyHost']
            if (-not $verifyHost -or [string]::IsNullOrWhiteSpace([string] $verifyHost.Value)) {
                return @{ Action = 'exit'; Code = 78; Routed = $false; Reason = 'Gate returned routed Enforcement without VerifyHost (library mismatch); refusing to run.' }
            }
            return @{ Action = 'run'; Code = 0; Routed = $true; Reason = '' }
        }
        return @{ Action = 'exit'; Code = 78; Routed = $false; Reason = "Gate returned an unknown enforcement mode '$($enforcement.Mode)'." }
    }
    if ($claimsRouted) {
        return @{ Action = 'exit'; Code = 78; Routed = $false; Reason = 'Gate passed in routed-proxy mode but returned no Enforcement (library mismatch); refusing to run.' }
    }
    return @{ Action = 'run'; Code = 0; Routed = $false; Reason = '' }
}

function Resolve-OsintTorBotRouteAction {
    param([Parameter(Mandatory)] $GateResult)

    if ($GateResult.Route -and $GateResult.Route.Mode -eq 'routed-proxy') {
        return @{ Action = 'exit'; Code = 78; Reason = 'routed-proxy mode is not available for TorBot' }
    }
    return @{ Action = 'run'; Code = 0; Reason = '' }
}

function Test-OsintSquidHierarchyLine {
    <#
        True only when Squid's access log shows the CONNECT to Target left via a PARENT peer
        (FIRSTUP_PARENT / DEFAULT_PARENT / ...). HIER_DIRECT, a denied request, a missing line
        or a mix that includes any non-parent line is false.
    #>
    param(
        [AllowNull()] [string[]] $Lines,
        [Parameter(Mandatory)] [string] $Target
    )

    $connectPattern = '\sCONNECT\s+' + [regex]::Escape($Target) + '\s'
    $hierarchyPattern = '\s(?<hier>[A-Z_]+)/\S+\s+\S+\s*$'
    $matched = @($Lines | Where-Object { $_ -and $_ -match $connectPattern })
    if ($matched.Count -eq 0) { return $false }
    foreach ($line in $matched) {
        if ($line -notmatch $hierarchyPattern) { return $false }
        if ($Matches['hier'] -notmatch 'PARENT$') { return $false }
    }
    return $true
}

function Invoke-OsintDocker {
    param([Parameter(Mandatory)] [string[]] $Arguments)

    $output = & docker @Arguments 2>&1
    return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = @($output | ForEach-Object { "$_" }) }
}

function Invoke-OsintSquidParsePreflight {
    <# Run from the tool's compose directory with OSINT_SQUID_* already set. #>
    $result = Invoke-OsintDocker -Arguments @(
        'compose', 'run', '--rm', '--no-deps', $script:ProxyServiceName,
        '-k', 'parse', '-f', "/etc/squid/$($script:RoutedConfName)")
    return @{ Ok = ($result.ExitCode -eq 0); Output = ($result.Output -join "`n") }
}

function Get-OsintProbeHost {
    param([Parameter(Mandatory)] $Enforcement)

    $verifyHost = $Enforcement.PSObject.Properties['VerifyHost']
    if ($verifyHost -and -not [string]::IsNullOrWhiteSpace([string] $verifyHost.Value)) { return [string] $verifyHost.Value }
    throw 'Enforcement.VerifyHost is missing; the probe only connects to the operator-configured host.'
}

function Invoke-OsintEnforcementProbe {
    <#
        Issues one CONNECT from the tool container's network to the verify host through the
        sidecar, then requires Squid's access log to show a PARENT hierarchy code.
        Run after `compose up`, from the tool's compose directory.
    #>
    param(
        [Parameter(Mandatory)] [string] $ToolService,
        [Parameter(Mandatory)] $Enforcement,
        [int] $WaitSeconds = 8
    )

    $probeHost = Get-OsintProbeHost -Enforcement $Enforcement
    $target = '{0}:443' -f $probeHost
    $pythonCode = "import http.client as h; c=h.HTTPConnection('{0}',3128,timeout=20); c.set_tunnel('{1}',443); c.connect()" -f $script:ProxyServiceName, $probeHost
    $null = Invoke-OsintDocker -Arguments @(
        'compose', 'run', '--rm', '--no-deps', '--entrypoint', 'python', $ToolService, '-c', $pythonCode)

    $logLines = @()
    for ($attempt = 0; $attempt -lt $WaitSeconds; $attempt++) {
        $logLines = (Invoke-OsintDocker -Arguments @('compose', 'logs', '--no-log-prefix', $script:ProxyServiceName)).Output
        if (Test-OsintSquidHierarchyLine -Lines $logLines -Target $target) { return @{ Ok = $true; Target = $target } }
        Start-Sleep -Seconds 1
    }
    return @{ Ok = $false; Target = $target }
}

function Disable-OsintRoutedProxy {
    param($State)

    Remove-Item Env:OSINT_SQUID_CONF -ErrorAction SilentlyContinue
    Remove-Item Env:OSINT_SQUID_UPSTREAM -ErrorAction SilentlyContinue
    if ($State) { Remove-OsintSquidUpstreamFile -Path $State.UpstreamFile }
}

function Enable-OsintRoutedProxy {
    <#
        Prepares compose for the gate's decision. Vpn mode (no Enforcement) leaves the defaults
        (squid.conf + the empty upstream file). Routed mode renders the upstream snippet, selects
        squid-routed.conf and runs the `squid -k parse` preflight. Returns
        @{ Routed; UpstreamFile; ExitCode; Message }; a non-zero ExitCode means the runner must exit.
    #>
    param(
        [Parameter(Mandatory)] $GateResult,
        [Parameter(Mandatory)] [string] $ConfigTool
    )

    $state = @{ Routed = $false; UpstreamFile = $null; ExitCode = 0; Message = '' }
    Disable-OsintRoutedProxy
    if ($null -eq $GateResult.Enforcement) { return $state }

    $state.Routed = $true
    try {
        $state.UpstreamFile = New-OsintSquidUpstreamFile -StateDirectory (Get-OsintConfigDir -Tool $ConfigTool) -Enforcement $GateResult.Enforcement
    }
    catch {
        $state.ExitCode = 78
        $state.Message = "Could not render the routed-proxy upstream config: $($_.Exception.Message)"
        return $state
    }
    $env:OSINT_SQUID_CONF = $script:RoutedConfName
    $env:OSINT_SQUID_UPSTREAM = $state.UpstreamFile
    # A sidecar image built before squid-routed.conf existed would fail the parse; building is a no-op when current.
    $build = Invoke-OsintDocker -Arguments @('compose', 'build', $script:ProxyServiceName)
    if ($build.ExitCode -ne 0) {
        $state.ExitCode = 78
        $state.Message = "Could not build the egress-proxy image:`n$($build.Output -join "`n")"
        return $state
    }
    $preflight = Invoke-OsintSquidParsePreflight
    if (-not $preflight.Ok) {
        $state.ExitCode = 78
        $state.Message = "squid -k parse rejected the routed-proxy configuration:`n$($preflight.Output)"
    }
    return $state
}
