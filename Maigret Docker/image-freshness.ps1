# Keeps the local images in step with the hardening files they are built from.
# Both images carry a maigret.build-inputs label (compose.yaml build.labels) holding a
# hash of those files; when the hash on disk differs, the images are rebuilt before use.

$script:MaigretBuildInputFiles = @(
    'Dockerfile',
    'Dockerfile.proxy',
    '.dockerignore',
    'requirements.lock',
    'hardening/entrypoint.sh',
    'proxy/squid.conf',
    'proxy/squid-routed.conf'
)
$script:MaigretImages = @('maigret-hardened:0.6.4', 'maigret-egress-proxy:local')

function Get-MaigretBuildInputsHash {
    param([Parameter(Mandatory)] [string] $ProjectDirectory)
    $lines = foreach ($relative in $script:MaigretBuildInputFiles) {
        $path = Join-Path $ProjectDirectory $relative
        '{0} {1}' -f $relative, (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
    }
    $bytes = [System.Text.Encoding]::UTF8.GetBytes(($lines -join "`n"))
    return [System.Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
}

function Get-StaleMaigretImages {
    param([Parameter(Mandatory)] [string] $ExpectedHash)
    foreach ($image in $script:MaigretImages) {
        $label = & docker image inspect $image --format '{{index .Config.Labels "maigret.build-inputs"}}' 2>$null
        if ($LASTEXITCODE -ne 0 -or $label -ne $ExpectedHash) { $image }
    }
}

function Update-MaigretImages {
    # Rebuilds only when an image is missing or was built from different hardening files.
    param([Parameter(Mandatory)] [string] $ProjectDirectory)
    $hash = Get-MaigretBuildInputsHash -ProjectDirectory $ProjectDirectory
    $stale = @(Get-StaleMaigretImages -ExpectedHash $hash)
    if ($stale.Count -eq 0) { return }
    Write-Host ("Hardening files changed or images missing ({0}); rebuilding..." -f ($stale -join ', ')) -ForegroundColor Yellow
    $env:MAIGRET_BUILD_INPUTS = $hash
    Push-Location $ProjectDirectory
    try {
        docker compose build
        if ($LASTEXITCODE -ne 0) { throw 'docker compose build failed; hardened images were not updated.' }
    }
    finally { Pop-Location }
    $still = @(Get-StaleMaigretImages -ExpectedHash $hash)
    if ($still.Count -gt 0) { throw ("Rebuilt images still do not match the hardening files: {0}" -f ($still -join ', ')) }
}
