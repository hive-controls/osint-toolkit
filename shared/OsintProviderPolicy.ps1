<#
    OsintProviderPolicy.ps1

    Host-side reader for Phone Lookup's non-secret providers.json (the Python CLI owns writing it and the
    acknowledgement-phrase check; nothing here can enable a provider). Dot-source from a launcher:

        . (Join-Path $PSScriptRoot '..\shared\OsintProviderPolicy.ps1')

    providers.json lives beside secrets.json: Get-OsintConfigDir -Tool 'PhoneLookup'. It is shared by
    run-phone.ps1 (PHONE_LOOKUP_PROVIDERS) and run-scanner.ps1 (--hudson gating, SCANNER_HUDSON_ALLOWED).
#>

$script:OsintProviderIds = @('numverify', 'hudson_rock', 'dehashed', 'leakcheck', 'leakradar')

function Get-OsintProviderTermsDirectory {
    return Join-Path (Split-Path -Parent $PSScriptRoot) 'Phone Lookup\PROVIDER-TERMS'
}

function Get-OsintProviderTermsVersion {
    <# sha256 over LF-normalised bytes; must match phone_lookup.providers_config.terms_version. #>
    param([Parameter(Mandatory)] [string] $TermsFile)
    $text = [Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($TermsFile)).Replace("`r`n", "`n")
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $hash = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($text)) } finally { $sha.Dispose() }
    return ([BitConverter]::ToString($hash) -replace '-', '').ToLowerInvariant()
}

function Read-OsintProviderEntries {
    <# Returns @{ provider = PSCustomObject } for known providers; missing file = empty; bad JSON throws. #>
    param([Parameter(Mandatory)] [string] $Path)
    $entries = @{}
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $entries }
    $data = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    if ($null -eq $data) { return $entries }
    foreach ($property in $data.PSObject.Properties) {
        if ($script:OsintProviderIds -contains $property.Name -and $property.Value -is [pscustomobject]) {
            $entries[$property.Name] = $property.Value
        }
    }
    return $entries
}

function Get-OsintAckVersion {
    param($Entry)
    if ($null -ne $Entry.terms_ack -and $Entry.terms_ack.version) { return [string]$Entry.terms_ack.version }
    return ''
}

function Get-OsintEnabledProviders {
    <# "name@terms-version" for every enabled provider (bare name when no ack is recorded). The container
       re-checks each version against its own PROVIDER-TERMS copy, so a stale entry fails closed with exit 78. #>
    param(
        [Parameter(Mandatory)] [string] $Path,
        [string] $TermsDirectory
    )
    $entries = Read-OsintProviderEntries -Path $Path
    $enabled = foreach ($name in $script:OsintProviderIds) {
        if ($entries.ContainsKey($name) -and $entries[$name].enabled -eq $true) {
            $version = Get-OsintAckVersion -Entry $entries[$name]
            if ($version) { "$name@$version" } else { $name }
        }
    }
    return @($enabled | Where-Object { $_ })
}

function Test-OsintHudsonAllowed {
    param(
        [Parameter(Mandatory)] [string] $Path,
        [string] $TermsDirectory
    )
    if (-not $TermsDirectory) { $TermsDirectory = Get-OsintProviderTermsDirectory }
    try {
        $entries = Read-OsintProviderEntries -Path $Path
        if (-not $entries.ContainsKey('hudson_rock') -or $entries['hudson_rock'].enabled -ne $true) { return $false }
        $termsFile = Join-Path $TermsDirectory 'hudson_rock.txt'
        $recorded = Get-OsintAckVersion -Entry $entries['hudson_rock']
        return [bool]($recorded -and (Test-Path -LiteralPath $termsFile) -and ($recorded -ceq (Get-OsintProviderTermsVersion -TermsFile $termsFile)))
    } catch {
        return $false
    }
}

function Test-OsintHudsonRequested {
    param([string[]] $Arguments)
    foreach ($argument in $Arguments) {
        if ($argument -match '^--hu') { return $true }
    }
    return $false
}

function Invoke-OsintProviderManagement {
    <# Enable/disable/list run in the Phone container so the acknowledgement-phrase check lives only in the
       Python CLI. No lookup, hence no network gate; the config dir is mounted rw at /config for this one run. #>
    param(
        [Parameter(Mandatory)] [string] $ProjectDirectory,
        [string[]] $ManagementArguments
    )
    $configDirectory = Get-OsintConfigDir -Tool 'PhoneLookup'
    New-Item -ItemType Directory -Path $configDirectory -Force | Out-Null
    Push-Location $ProjectDirectory
    try {
        docker compose run --rm --no-deps `
            -v "${configDirectory}:/config" `
            -e PHONE_LOOKUP_PROVIDERS_FILE=/config/providers.json `
            -e "PHONE_LOOKUP_OPERATOR=$([Environment]::UserName)" `
            phone @ManagementArguments | Out-Host
        return [int]$LASTEXITCODE
    }
    finally {
        docker compose down --remove-orphans | Out-Host
        Pop-Location
    }
}

function Test-OsintProviderManagementArguments {
    param([string[]] $Arguments)
    foreach ($argument in $Arguments) {
        if ($argument -in @('--providers', '--enable', '--disable')) { return $true }
    }
    return $false
}
