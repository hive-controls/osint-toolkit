#requires -Version 7
<#
.SYNOPSIS
  Create OSINT/cases/<case-id>/ from the v1 template (notes + empty tool folders).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$CaseId
)

$ErrorActionPreference = 'Stop'

$slug = $CaseId.Trim().ToLowerInvariant()
if ($slug -notmatch '^[a-z0-9][a-z0-9._-]{0,62}$') {
    throw "Case id must be 1-63 chars: start with letter/digit, then letters, digits, dot, underscore, or hyphen. Got: $CaseId"
}

$root = $PSScriptRoot
$casesRoot = Join-Path $root 'cases'
$template = Join-Path $casesRoot '_template\case.md'
$dest = Join-Path $casesRoot $slug

if (-not (Test-Path -LiteralPath $template)) {
    throw "Missing template: $template"
}
if (Test-Path -LiteralPath $dest) {
    throw "Case already exists: $dest"
}

New-Item -ItemType Directory -Path $dest | Out-Null
foreach ($sub in @('scanner', 'maigret', 'torbot', 'phone', 'browse')) {
    New-Item -ItemType Directory -Path (Join-Path $dest $sub) | Out-Null
}

$today = Get-Date -Format 'yyyy-MM-dd'
$body = Get-Content -LiteralPath $template -Raw
$body = $body.Replace('CASE_ID', $slug).Replace('YYYY-MM-DD', $today)
Set-Content -LiteralPath (Join-Path $dest 'case.md') -Value $body -Encoding utf8

Write-Host "Created $dest"
Write-Host "Edit:   $(Join-Path $dest 'case.md')"
Write-Host "Drop artifacts into scanner\, maigret\, torbot\, phone\, browse\ or record pointers in case.md."
