// read_logger.js - Frida analogue of examples/gated_config/callbacks.cpp `log_read`
// (and of the shippable `read_logger` CLI described in docs/plan-v2.md).
//
// Our native probe installs an INLINE hook (SafetyHook mid-hook) at ReadSite and,
// on every NtReadVirtualMemory call, grabs probe_arg(c,0) (HANDLE) and
// probe_arg(c,3) (SIZE_T NumberOfBytes) and writes one deferred PROBE_LOG record.
// The read_logger CLI additionally filters by resolved PID and by address range.
//
// Frida's equivalent is Interceptor.attach on ntdll!NtReadVirtualMemory. Frida's
// Interceptor IS an inline trampoline hook, so this is the apples-to-apples
// reference for our inline backend's per-hit overhead. args[i] is calling-
// convention-neutral (registers on x64, stack on x86) - the same arch-neutrality
// our probe_arg gives - so one script covers x64, x86-native and WoW64 targets.
//
// rpc.exports:
//   configure(cfg)  - set mode + filter (see DEFAULTS below)
//   stats()         - { calls, matched, logged, resolveCalls }
//   reset()         - zero the counters
//
// Load standalone for the functional demo:
//   frida -f probe_app.exe -l read_logger.js   (then resume, send a keystroke)
// or driven by bench_frida.py for timing.

'use strict';

// ---- version shim: Frida 17 removed the static Module.* helpers -------------
function modBase(name) {
    if (typeof Process.findModuleByName === 'function') {
        const m = Process.findModuleByName(name);
        return m ? m.base : null;
    }
    if (Module.findBaseAddress) return Module.findBaseAddress(name); // Frida <=16
    return null;
}
function modExport(mod, name) {
    // Frida 17: Process.getModuleByName(mod).getExportByName(name)
    if (typeof Process.findModuleByName === 'function') {
        const m = Process.findModuleByName(mod);
        if (m && typeof m.findExportByName === 'function') {
            const p = m.findExportByName(name);
            if (p) return p;
        }
    }
    if (Module.getExportByName) return Module.getExportByName(mod, name);   // Frida <=16
    if (Module.findExportByName) return Module.findExportByName(mod, name);
    throw new Error('cannot resolve ' + mod + '!' + name);
}

// ---- configuration ---------------------------------------------------------
// mode:
//   'count' - hot-path benchmark: read args[0] and args[3], apply the filter,
//             bump a counter. NEVER send() per call (that would measure Frida's
//             IPC, not the hook). This mirrors log_read's inline hot path, where
//             PROBE_LOG only enqueues a record to a per-thread queue.
//   'log'   - functional demo: send() one message per matched call (optionally
//             sampled by logEvery). Do NOT use for high-volume timing.
// filter (all optional; null/0 = disabled, i.e. "log all"):
//   selectedHandle / decoyHandle - raw HANDLE values from probe_app's
//       {"kind":"waiting"} line. Cheapest filter: compare the handle value, no
//       syscall. This is the read_logger "selected_handle" concept.
//   onlyPid       - resolve HANDLE->PID with a CACHED GetProcessId (one syscall
//       per distinct handle, then a JS-map hit), then compare. Mirrors our
//       handle->pid map + "resolve once, cache" rule; name/PID lookups must never
//       run on the hot path uncached.
//   rangeStart / rangeSize - keep only reads whose BaseAddress is in
//       [rangeStart, rangeStart+rangeSize). Matches probe_app's in-range window.
var cfg = {
    mode: 'count',
    logEvery: 1,
    selectedHandle: 0,
    decoyHandle: 0,
    onlyPid: 0,
    rangeStart: 0,
    rangeSize: 0,
};

var calls = 0, matched = 0, logged = 0, resolveCalls = 0;
var rangeLo = null, rangeHi = null, selPtr = null, decoyPtr = null;

// HANDLE(string) -> pid cache. UHH builds this map at ntdll!NtOpenProcess
// (examples/gated_config/callbacks.cpp); GetProcessId works on any process handle,
// so here we resolve lazily and cache instead.
var pidByHandle = Object.create(null);
var GetProcessId = new NativeFunction(modExport('kernel32.dll', 'GetProcessId'),
                                      'uint32', ['pointer']);

function resolvePid(handle) {
    var key = handle.toString();
    var pid = pidByHandle[key];
    if (pid === undefined) {           // first sighting of this handle only
        resolveCalls++;
        pid = GetProcessId(handle);    // soft-fails to 0, like probe_image_name
        pidByHandle[key] = pid;
    }
    return pid;
}

function applyConfig(c) {
    for (var k in c) cfg[k] = c[k];
    rangeLo = cfg.rangeStart ? ptr('' + cfg.rangeStart) : null;
    rangeHi = rangeLo ? rangeLo.add(cfg.rangeSize) : null;
    selPtr = cfg.selectedHandle ? ptr('' + cfg.selectedHandle) : null;
    decoyPtr = cfg.decoyHandle ? ptr('' + cfg.decoyHandle) : null;
    pidByHandle = Object.create(null);
}

rpc.exports = {
    configure: function (c) { applyConfig(c || {}); return cfg; },
    stats: function () { return { calls: calls, matched: matched, logged: logged, resolveCalls: resolveCalls }; },
    reset: function () { calls = 0; matched = 0; logged = 0; resolveCalls = 0; pidByHandle = Object.create(null); },
};

// ---- the hook --------------------------------------------------------------
// NTSTATUS NtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress,
//                              PVOID Buffer, SIZE_T NumberOfBytes,
//                              PSIZE_T NumberOfBytesRead);
var ntReadVM = modExport('ntdll.dll', 'NtReadVirtualMemory');

Interceptor.attach(ntReadVM, {
    onEnter: function (args) {
        calls++;
        var handle = args[0];       // == probe_arg(c, 0)
        var base = args[1];         // BaseAddress (in the *remote* process)
        var size = args[3];         // == probe_arg(c, 3), SIZE_T

        // ---- filter (mirrors read_logger: PID + address range) ----
        if (selPtr !== null && !handle.equals(selPtr) &&
            !(decoyPtr !== null && handle.equals(decoyPtr))) return;
        if (cfg.onlyPid) {
            if (resolvePid(handle) !== cfg.onlyPid) return;
        }
        if (rangeLo !== null &&
            (base.compare(rangeLo) < 0 || base.compare(rangeHi) >= 0)) return;

        matched++;
        if (cfg.mode === 'log' && (cfg.logEvery <= 1 || (matched % cfg.logEvery) === 0)) {
            logged++;
            // NOTE: base/size address the REMOTE process; Frida runs in-target, so
            // ptr(base).readByteArray() would read the WRONG process. We log the
            // raw args only - exactly what log_read does.
            var pid = cfg.onlyPid ? cfg.onlyPid : resolvePid(handle);
            send({
                type: 'read',
                tid: this.threadId,
                handle: handle.toString(),
                pid: pid,
                base: base.toString(),
                size: size.toString(),
            });
        }
    },
});

send({ type: 'ready', what: 'read_logger', target: ntReadVM.toString() });

// --- benchmark helper: emit the final count at process exit (before Frida/CRT
// teardown), and HOLD the exiting thread briefly so the driver can read an
// accurate count via the 'done' message or a stats() RPC - probe_app otherwise
// exits immediately after its {"kind":"app"} line and tears down the script. ---
(function () {
    function sendDone() {
        var s = {}; try { s = rpc.exports.stats(); } catch (e) {}
        s.type = 'done';
        try { send(s); } catch (e) {}
    }
    try {
        var exitFn = modExport('ntdll.dll', 'RtlExitUserProcess');
        Interceptor.attach(exitFn, { onEnter: function () {
            sendDone();
            var end = Date.now() + 4000;   // keep process (and script) alive
            while (Date.now() < end) {}
        }});
    } catch (e) { /* stats() RPC remains the fallback */ }
})();
