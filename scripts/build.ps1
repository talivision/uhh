<#
.SYNOPSIS
  Fast configure + build of UHH for x64 and/or x86 (Windows, VS 2022).

.DESCRIPTION
  Uses the "Ninja Multi-Config" generator (Ninja from PATH, or the copy bundled with
  Visual Studio's CMake component) with the MSVC environment from vcvarsall.bat. Output
  layout is the same as the Visual Studio generator's: <build-dir>\Release\*.exe, so
  scripts\regress.py --bin build-x64\Release works with either.

  A build directory that was already configured with another generator (e.g. by
  `cmake -S . -B build-x64 -A x64`) keeps that generator; it is then built with
  --parallel. Pass -Generator vs to force the Visual Studio generator for a fresh dir.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\build.ps1                 # both arches, Release
  powershell -ExecutionPolicy Bypass -File scripts\build.ps1 -Arch x64
  powershell -ExecutionPolicy Bypass -File scripts\build.ps1 -Arch x86 -Target probe_api
#>
param(
    [ValidateSet('x64', 'x86', 'both')] [string]$Arch = 'both',
    [ValidateSet('auto', 'ninja', 'vs')] [string]$Generator = 'auto',
    [string]$Config = 'Release',
    [string]$Target = '',
    [string]$BuildRoot = '.'
)
$ErrorActionPreference = 'Stop'

$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vs = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vs) { throw 'Visual Studio with the MSVC x86/x64 tools not found' }

function Find-Ninja {
    $n = Get-Command ninja -ErrorAction SilentlyContinue
    if ($n) { return $n.Source }
    $b = Join-Path $vs 'Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja\ninja.exe'
    if (Test-Path $b) { return $b }
    return $null
}

# Import the vcvarsall environment for one arch into a hashtable (does not touch ours).
function Get-MsvcEnv([string]$vcArch) {
    $bat = Join-Path $vs 'VC\Auxiliary\Build\vcvarsall.bat'
    $vars = @{}
    cmd /c "call `"$bat`" $vcArch >nul 2>&1 && set" | ForEach-Object {
        if ($_ -match '^([^=]+)=(.*)$') { $vars[$matches[1]] = $matches[2] }
    }
    if (-not $vars['VCToolsInstallDir']) { throw "vcvarsall $vcArch failed" }
    return $vars
}

function Invoke-WithEnv([hashtable]$vars, [scriptblock]$block) {
    $saved = @{}
    foreach ($k in $vars.Keys) { $saved[$k] = [Environment]::GetEnvironmentVariable($k, 'Process') }
    try {
        foreach ($k in $vars.Keys) { [Environment]::SetEnvironmentVariable($k, $vars[$k], 'Process') }
        & $block
    } finally {
        foreach ($k in $saved.Keys) { [Environment]::SetEnvironmentVariable($k, $saved[$k], 'Process') }
    }
}

function Get-CachedGenerator([string]$dir) {
    $cache = Join-Path $dir 'CMakeCache.txt'
    if (-not (Test-Path $cache)) { return $null }
    $line = Select-String -Path $cache -Pattern '^CMAKE_GENERATOR:INTERNAL=(.*)$' | Select-Object -First 1
    if ($line) { return $line.Matches[0].Groups[1].Value }
    return $null
}

$ninja = Find-Ninja
$arches = if ($Arch -eq 'both') { @('x64', 'x86') } else { @($Arch) }
$failed = @()
foreach ($a in $arches) {
    $dir = Join-Path $BuildRoot "build-$a"
    $platform = if ($a -eq 'x64') { 'x64' } else { 'Win32' }
    $cached = Get-CachedGenerator $dir
    $useNinja = if ($cached) { $cached -like 'Ninja*' }
                elseif ($Generator -eq 'vs') { $false }
                elseif ($Generator -eq 'ninja') { if (-not $ninja) { throw 'ninja.exe not found' }; $true }
                else { [bool]$ninja }
    $buildArgs = @('--build', $dir, '--config', $Config)
    if ($Target) { $buildArgs += @('--target', $Target) }
    $sw = [Diagnostics.Stopwatch]::StartNew()
    if ($useNinja) {
        $msvc = Get-MsvcEnv $a
        Invoke-WithEnv $msvc {
            if (-not $cached) {
                cmake -S . -B $dir -G 'Ninja Multi-Config' "-DCMAKE_MAKE_PROGRAM=$ninja" -DCMAKE_C_COMPILER=cl -DCMAKE_CXX_COMPILER=cl
                if ($LASTEXITCODE -ne 0) { throw "configure $a failed" }
            }
            cmake @buildArgs
        }
    } else {
        if (-not $cached) {
            cmake -S . -B $dir -G 'Visual Studio 17 2022' -A $platform
            if ($LASTEXITCODE -ne 0) { throw "configure $a failed" }
        }
        cmake @buildArgs --parallel
    }
    $rc = $LASTEXITCODE
    $gen = if ($useNinja) { 'ninja' } else { 'vs' }
    "BUILD_{0}_{1} ({2}, {3:N1}s)" -f $(if ($rc -eq 0) { 'OK' } else { 'FAIL' }), $a, $gen, $sw.Elapsed.TotalSeconds
    if ($rc -ne 0) { $failed += $a }
}
if ($failed) { exit 1 }
