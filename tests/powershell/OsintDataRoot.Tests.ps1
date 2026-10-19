BeforeAll {
    . (Join-Path $PSScriptRoot '..\..\shared\OsintTool.Common.ps1')
    $script:SavedEnvironment = @{}
    foreach ($name in 'OSINT_ROOT', 'LOCALAPPDATA', 'XDG_DATA_HOME') { $script:SavedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name) }
    function script:Set-DataRootEnvironment {
        param([string] $OsintRoot, [string] $LocalAppData, [string] $XdgDataHome)
        foreach ($pair in @(@('OSINT_ROOT', $OsintRoot), @('LOCALAPPDATA', $LocalAppData), @('XDG_DATA_HOME', $XdgDataHome))) {
            [Environment]::SetEnvironmentVariable($pair[0], $(if ($pair[1]) { $pair[1] } else { $null }))
        }
    }
}

AfterAll {
    foreach ($name in $script:SavedEnvironment.Keys) { [Environment]::SetEnvironmentVariable($name, $script:SavedEnvironment[$name]) }
}

Describe 'Get-OsintDataRoot' {
    It 'resolves <Name>' -ForEach @(
        @{ Name = 'explicit over env over nt default'; Root = 'C:\flag'; Env = 'C:\env'; Local = 'C:\local'; Xdg = ''; Expected = 'C:\flag' }
        @{ Name = 'env over nt default'; Root = ''; Env = 'C:\env'; Local = 'C:\local'; Xdg = ''; Expected = 'C:\env' }
        @{ Name = 'nt default'; Root = ''; Env = ''; Local = 'C:\local'; Xdg = ''; Expected = (Join-Path (Join-Path 'C:\local' 'OsintToolkit') 'data') }
        @{ Name = 'explicit over env over XDG seam'; Root = '/flag'; Env = '/env'; Local = ''; Xdg = '/xdg'; Expected = '/flag' }
        @{ Name = 'env over XDG seam'; Root = ''; Env = '/env'; Local = ''; Xdg = '/xdg'; Expected = '/env' }
        @{ Name = 'XDG seam default'; Root = ''; Env = ''; Local = ''; Xdg = '/xdg'; Expected = (Join-Path '/xdg' 'osint-toolkit') }
        @{ Name = 'HOME fallback when neither platform variable is set'; Root = ''; Env = ''; Local = ''; Xdg = ''; Expected = (Join-Path (Join-Path (Join-Path $HOME '.local') 'share') 'osint-toolkit') }
    ) {
        Set-DataRootEnvironment -OsintRoot $Env -LocalAppData $Local -XdgDataHome $Xdg
        if ($Root) { Get-OsintDataRoot -Root $Root | Should -Be $Expected } else { Get-OsintDataRoot | Should -Be $Expected }
    }
    It 'never defaults to the repository tree' {
        Set-DataRootEnvironment -LocalAppData 'C:\local'
        (Get-OsintDataRoot) | Should -Not -BeLike "$((Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path)*"
    }
}

Describe 'Resolve-OsintCaseLocation fallback' {
    BeforeAll { . (Join-Path $PSScriptRoot '..\..\shared\OsintSubjectAuthorization.ps1') }
    It 'uses the shared resolver rather than the repository OSINT folder' {
        Set-DataRootEnvironment -LocalAppData 'C:\local'
        $saved = @{ Case = $env:OSINT_CASE_ID; Session = $env:OSINT_CASE_SESSION }
        Remove-Item Env:\OSINT_CASE_ID, Env:\OSINT_CASE_SESSION -ErrorAction SilentlyContinue
        try { (Resolve-OsintCaseLocation).Root | Should -Be (Get-OsintDataRoot) }
        finally { $env:OSINT_CASE_ID = $saved.Case; $env:OSINT_CASE_SESSION = $saved.Session }
    }
}
