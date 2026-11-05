# A realistic, self-checking, multi-threaded .NET workload for the bigapps stability
# check (scripts/regress.py --bigapps). Runs under Windows PowerShell 5.1 (x64 and the
# 32-bit SysWOW64 host) and pwsh 7. For -Seconds it repeatedly:
#   - hashes a set of files on a runspace pool (several threads in THIS process: CreateFileW /
#     NtCreateFile / NtReadFile / heap and VM allocations on every thread),
#   - enumerates the directory, compiles a new script block (JIT), throws and catches .NET
#     exceptions, runs a JIT-compiled C# loop checked against its closed form,
#   - every ~8 s starts a background job (a child powershell.exe) and checks its result.
# Every hash is compared with -ExpectedHash, the SHA-256 the suite computes itself (Python
# hashlib over the same deterministic file contents: an oracle independent of this process
# and of the instrumentation); the hash computed here before the loop must equal it too.
# Without -ExpectedHash (manual runs) the pre-loop hash is the reference. Any corruption shows as
# bad>0. Prints BIGAPPS_READY once, BIGAPPS_TICK about every second (liveness: the check
# asserts ticks continue after a detach) and BIGAPPS_DONE at the end; exit code 0 iff bad==0.
param([int]$Seconds = 45, [int]$Files = 48, [int]$Threads = 4, [string]$Work = $env:TEMP,
      [int]$PauseMs = 100, [string]$ExpectedHash = '')
$ErrorActionPreference = 'Stop'
function say([string]$s) { [Console]::Out.WriteLine($s); [Console]::Out.Flush() }

Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Security.Cryptography;
public static class BigAppsWork {
    public static void Fill(string path, int i) {
        byte[] b = new byte[4096 + i * 97];
        for (int k = 0; k < b.Length; k++) b[k] = (byte)((i * 31 + k * 7) % 251);
        File.WriteAllBytes(path, b);
    }
    public static string HashAll(string[] paths) {
        using (SHA256 sha = SHA256.Create()) {
            foreach (string p in paths) {
                byte[] b = File.ReadAllBytes(p);
                sha.TransformBlock(b, 0, b.Length, null, 0);
            }
            sha.TransformFinalBlock(new byte[0], 0, 0);
            return BitConverter.ToString(sha.Hash);
        }
    }
    public static bool SquaresOk(long n) {
        long s = 0;
        for (long k = 0; k < n; k++) s += k * k;
        return s == n * (n - 1) * (2 * n - 1) / 6;
    }
}
'@

$dir = Join-Path $Work ("bigapps_" + $PID)
New-Item -ItemType Directory -Force $dir | Out-Null
$paths = [string[]]@(for ($i = 0; $i -lt $Files; $i++) {
    $p = Join-Path $dir ("f$i.bin"); [BigAppsWork]::Fill($p, $i); $p })
$expected = [BigAppsWork]::HashAll($paths)
$bad = 0
if ($ExpectedHash) {       # (PowerShell names are case-insensitive: not $Expected)
    if ($expected -ne $ExpectedHash) { $bad++; say "BIGAPPS_BAD manifest got=$expected want=$ExpectedHash" }
    $expected = $ExpectedHash
}

$pool = [RunspaceFactory]::CreateRunspacePool(1, $Threads)
$pool.Open()
$task = { param($p) [BigAppsWork]::HashAll($p) }
$iter = 0; $jobs = 0; $exc = 0; $tick = 0
$clock = [Diagnostics.Stopwatch]::StartNew()
$nextJob = 2000
say "BIGAPPS_READY pid=$PID threads=$Threads files=$Files"
while ($clock.ElapsedMilliseconds -lt $Seconds * 1000) {
    $iter++
    $running = @()
    for ($t = 0; $t -lt $Threads; $t++) {
        $ps = [PowerShell]::Create(); $ps.RunspacePool = $pool
        [void]$ps.AddScript($task).AddArgument($paths)
        $running += ,@($ps, $ps.BeginInvoke())
    }
    foreach ($r in $running) {
        $out = $r[0].EndInvoke($r[1])
        if ("$out" -ne $expected) { $bad++; say "BIGAPPS_BAD hash iter=$iter got=$out" }
        $r[0].Dispose()
    }
    if (@(Get-ChildItem -LiteralPath $dir -File).Count -ne $Files) { $bad++; say "BIGAPPS_BAD dir iter=$iter" }
    $sb = [ScriptBlock]::Create("param(`$x) `$x * $iter + 1")
    if ((& $sb 3) -ne (3 * $iter + 1)) { $bad++; say "BIGAPPS_BAD scriptblock iter=$iter" }
    for ($e = 0; $e -lt 5; $e++) { try { throw "boom $e" } catch { $exc++ } }
    try { [void][int]::Parse("x$iter") } catch [FormatException] { $exc++ }
    if (-not [BigAppsWork]::SquaresOk(100000 + $iter)) { $bad++; say "BIGAPPS_BAD squares iter=$iter" }
    if ($clock.ElapsedMilliseconds -ge $nextJob) {
        $nextJob = $clock.ElapsedMilliseconds + 8000
        $v = Receive-Job (Start-Job { 6 * 7 }) -Wait -AutoRemoveJob
        if ($v -ne 42) { $bad++; say "BIGAPPS_BAD job got=$v" } else { $jobs++ }
    }
    $sec = [int]($clock.ElapsedMilliseconds / 1000)
    if ($sec -gt $tick) { $tick = $sec; say "BIGAPPS_TICK t=$sec iter=$iter" }
    Start-Sleep -Milliseconds $PauseMs
}
$pool.Close(); $pool.Dispose()
Remove-Item -Recurse -Force $dir
say "BIGAPPS_DONE iters=$iter bad=$bad jobs=$jobs exc=$exc"
if ($bad -eq 0) { exit 0 } else { exit 5 }
