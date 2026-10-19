<#
    OsintTool.Common.ps1

    Shared cross-platform path helpers for the OSINT toolkit's launcher scripts.
    Dot-source this file relative to the calling script's own location, e.g.:

        . (Join-Path $PSScriptRoot '..\shared\OsintTool.Common.ps1')

    Gate scripts (one level deeper, under a tool's `gate\` folder) use:

        . (Join-Path $PSScriptRoot '..\..\shared\OsintTool.Common.ps1')
#>

function Get-OsintConfigDir {
    <#
        Resolves the per-machine config/secrets directory for a tool.

        Resolution order:
          1. $env:LOCALAPPDATA\<Tool>              (Windows; byte-identical to the prior hardcoded path)
          2. $env:XDG_CONFIG_HOME\<Tool>            (Linux/mac, when XDG_CONFIG_HOME is set)
          3. $HOME\.config\<Tool>                   (mac/Linux fallback)
    #>
    param(
        [Parameter(Mandatory)]
        [string] $Tool
    )

    if ($env:LOCALAPPDATA) {
        return Join-Path $env:LOCALAPPDATA $Tool
    }
    if ($env:XDG_CONFIG_HOME) {
        return Join-Path $env:XDG_CONFIG_HOME $Tool
    }
    return Join-Path (Join-Path $HOME '.config') $Tool
}

function Get-OsintDataRoot {
    <#
        Resolves the OSINT data root (cases, inbox, tool output lanes). The PowerShell twin of
        osint_profiler.util.data_root.

        Resolution order:
          1. -Root                                   (the explicit value, like the profiler's --root)
          2. $env:OSINT_ROOT
          3. $env:LOCALAPPDATA\OsintToolkit\data      (Windows default)
          4. $env:XDG_DATA_HOME\osint-toolkit         (POSIX seam)
          5. $HOME\.local\share\osint-toolkit         (POSIX fallback)
    #>
    param([string] $Root)

    if ($Root) { return $Root }
    if ($env:OSINT_ROOT) { return $env:OSINT_ROOT }
    if ($env:LOCALAPPDATA) {
        return Join-Path (Join-Path $env:LOCALAPPDATA 'OsintToolkit') 'data'
    }
    if ($env:XDG_DATA_HOME) {
        return Join-Path $env:XDG_DATA_HOME 'osint-toolkit'
    }
    return Join-Path (Join-Path (Join-Path $HOME '.local') 'share') 'osint-toolkit'
}

function Get-OsintHomeDir {
    <#
        Resolves the user's home directory.

        Resolution order:
          1. $env:USERPROFILE   (Windows)
          2. $HOME              (mac/Linux, and Windows PowerShell 7 also sets this)
    #>
    if ($env:USERPROFILE) {
        return $env:USERPROFILE
    }
    return $HOME
}
