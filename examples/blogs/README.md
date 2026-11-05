# Blog replicas

Contrived but realistic re-creations of well-known instrumentation scenarios from
security / reverse-engineering write-ups and tools, used to **find issues in UHH**: each
runs uninstrumented (the baseline) and under `PROBE_BREAKPOINT`, `PROBE_HW` and
`PROBE_INLINE`, on x64 and x86, and any crash, hang, dropped log or divergence from the
baseline is a bug.

* `blog_target.exe <scenario>` -- a small program that does what the subject of the
  write-up does, and prints one `{"kind":"target",...}` line of results.
* `blog_driver.exe --scenario <s> --backend breakpoint|hw|inline [--no-log] -- <program> ...`
  -- the monitor. Callbacks: [`blog_callbacks.cpp`](blog_callbacks.cpp), one source for
  every backend (built into the driver for breakpoint/hw and into `probe_api_agent.dll`
  for inline).
* Regression: `python scripts/regress.py --bin build-x64/Release --only blog`
  (`UHH_BLOG_SCENARIOS=crypto,net` / `UHH_BLOG_BACKENDS=hw` narrow it).

Everything is local and cleaned up: files under `%TEMP%` (deleted), a registry key under
`HKCU\Software\UHHBlogTest_<pid>` (deleted by the target; the check verifies and removes
any leftover), sockets on 127.0.0.1 only, DNS with `DNS_QUERY_NO_WIRE_QUERY`.

| Scenario | Pattern it mimics | Probes | What the analyst gets |
|---|---|---|---|
| `crypto` | Ransomware-detection write-ups / API monitors that hook CNG and CryptoAPI to catch bulk file encryption and recover keys (e.g. the "hook BCryptEncrypt / CryptEncrypt" approach of ransomware key-recovery research, API Monitor, Frida crypto-tracers) | `bcrypt!BCryptEncrypt`, `bcrypt!BCryptGenRandom` (+ a return probe added from the callback), `advapi32!CryptEncrypt` (forwarded to `cryptsp`) | plaintext prefix + IV of every encryption, the 48 random key/IV bytes **at the return** of BCryptGenRandom (entry SP -> buffer, read after `ret`), 6 threads x 20 "files" |
| `registry` | Persistence monitors (Sysmon-style registry events, Process Monitor, "hook NtSetValueKey" EDR write-ups) watching `...\CurrentVersion\Run` | `ntdll!NtCreateKey`, `ntdll!NtSetValueKey` | full NT key path (resolved by `call_func(ntdll!NtQueryKey)` in the target on the hit thread), value name, type and data |
| `net` | DNS/network loggers (API Monitor, Frida `socket` tracers, "hook connect/send" C2-analysis posts) | `ws2_32!connect`, `WSAConnect`, `send`, `recv`, `dnsapi!DnsQuery_W` | destination ip:port, payload prefix of every send, recv sizes, queried names |
| `spawn` | Process-creation trackers (Sysmon EID 1 analogues, "hook CreateProcessInternalW" posts) | `kernelbase!CreateProcessInternalW`, `ntdll!NtCreateUserProcess` | application + command line at both layers |
| `com` | COM activity loggers (CLSID tracing of malware that uses `CLSID_ShellLink` to drop .lnk persistence) | `ole32!CoCreateInstance` (forwarded to `combase`) | CLSID, IID and class context of every activation |
| `game` | Game-hacking "hook the per-frame function" posts (Present/Update hooks) | `blog_target.exe!blog_frame` at 1 kHz | per-frame log; the target measures its own frame cost and lateness so each backend's per-hit cost shows up as jitter |
| pwsh (suite only) | "Hook a .NET/JIT host" posts: attach to a running PowerShell, hook a native export it uses, detach mid-run | `kernelbase!CreateFileW` via `uhh_trace --attach --detach-after-ms` | the script's file opens while attached; PowerShell finishes with the same output |

## What an analyst sees (and does not)

* **Children are not followed** (`spawn`). The monitor logs each `CreateProcessInternalW`
  / `NtCreateUserProcess` in the parent with the full command line, but nothing that runs
  inside the children: UHH debugs with `DEBUG_ONLY_THIS_PROCESS`, and the inline agent is
  injected only into the launched process. To trace a child, start a second session with
  `probe_attach_new("blog_target.exe", ...)` (it attaches a few ms after the child
  starts) -- see the roadmap item on following children.
* **hw has four debug registers.** `net` needs five probes, so on hw the driver drops
  `DnsQuery_W` and says so on stderr; `crypto` uses exactly four (three entries + the
  dynamic return probe).
* **Return values need a return probe.** `BCryptGenRandom`'s output and `recv`'s data only
  exist after the call returns. The crypto monitor shows the pattern: at entry read the
  return address at SP and `probe_add_address` it once (under a lock, so a second thread
  cannot return before it is armed), and remember the output pointer keyed by the entry
  SP; at the return site, SP - (pointer + stdcall args) finds it again.
* **Decoding handles runs code in the target.** The registry monitor turns key handles
  into paths with `call_func("ntdll.dll!NtQueryKey", ...)`, and allocates one 64 KiB
  scratch region in the target (`kernelbase!VirtualAlloc`) for the out-buffer -- a
  deliberate, documented side effect. On breakpoint/hw each `call_func` is tens of
  microseconds.
* **Per-hit cost shows up as frame jitter** (`game`): inline costs well under a
  microsecond per frame; hw and breakpoint cost tens to hundreds of microseconds per hit
  (a debug event round trip), visible as `cost_us` percentiles in the target's line.
