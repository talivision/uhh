// read_hwbp.js - Frida hardware-breakpoint analogue of our `hw` (debug-register)
// backend. Counts NtReadVirtualMemory calls by arming a hardware execution
// breakpoint (debug register) at the function entry on each worker thread and
// counting the resulting exceptions.
//
// Frida 16.x exposes hardware breakpoints ONLY per-thread, as methods on the
// ThreadDetails objects returned by Process.enumerateThreads():
//   td.setHardwareBreakpoint(id, address) / td.unsetHardwareBreakpoint(id)
// There is NO process-wide "all threads / future threads" variant and (in 16.5.9)
// no thread-creation observer. probe_app's W worker threads are created AFTER we
// attach, so - exactly as for Stalker - we arm each thread from its entry thunk
// (BaseThreadInitThunk, which runs on the new thread) by finding our own
// ThreadDetails and calling setHardwareBreakpoint on it.
//
// Each hit raises a single-step/breakpoint exception caught by
// Process.setExceptionHandler. A hardware *execution* breakpoint re-fires on the
// same instruction, so to make forward progress we disable it, set the CPU trap
// flag to execute one instruction, then re-arm on the following single-step. This
// is the same displaced-step dance our debug backend does - and the reason an
// exception-per-call scheme is enormously slower than an inline hook.
//
// rpc.exports: configure() [no-op], stats(), reset().

'use strict';

function modExport(mod, name) {
    if (typeof Process.findModuleByName === 'function') {
        const m = Process.findModuleByName(mod);
        if (m && typeof m.findExportByName === 'function') {
            const p = m.findExportByName(name);
            if (p) return p;
        }
    }
    if (Module.getExportByName) return Module.getExportByName(mod, name);
    if (Module.findExportByName) return Module.findExportByName(mod, name);
    throw new Error('cannot resolve ' + mod + '!' + name);
}

var ntReadVM = modExport('ntdll.dll', 'NtReadVirtualMemory');
var BP_SLOT = 0;
var calls = 0;
var armed = Object.create(null);     // tid -> true while bp is set
var stepping = Object.create(null);  // tid -> true between disable and re-arm
var errors = [];

function tdFor(tid) {
    var ths = Process.enumerateThreads();
    for (var i = 0; i < ths.length; i++) if (ths[i].id === tid) return ths[i];
    return null;
}
function arm(tid) {
    var td = tdFor(tid);
    if (!td) return false;
    try { td.setHardwareBreakpoint(BP_SLOT, ntReadVM); armed[tid] = true; return true; }
    catch (e) { errors.push('arm ' + tid + ': ' + e); return false; }
}
function disarm(tid) {
    var td = tdFor(tid);
    if (!td) return;
    try { td.unsetHardwareBreakpoint(BP_SLOT); } catch (e) { errors.push('disarm ' + tid + ': ' + e); }
    armed[tid] = false;
}

// Trap-flag bit in EFlags/RFlags.
var TF = 0x100;
Process.setExceptionHandler(function (details) {
    var ctx = details.context;
    var tid = details.thread ? details.thread.id : (Process.getCurrentThreadId ? Process.getCurrentThreadId() : 0);
    // A hardware breakpoint hit arrives as 'breakpoint' (or 'single-step' on arm64);
    // on x86/x64 debug-register hits are reported as 'single-step'/'breakpoint'.
    if (details.address && details.address.equals(ntReadVM)) {
        calls++;
        // Disable the bp and single-step one instruction, then re-arm.
        disarm(tid);
        stepping[tid] = true;
        // Set trap flag so the next instruction raises single-step.
        if ('rflags' in ctx) ctx.rflags = ctx.rflags.or(TF);
        else if ('eflags' in ctx) ctx.eflags = ctx.eflags.or(TF);
        return true;
    }
    if (stepping[tid]) {
        // The single step after stepping off the target - re-arm and clear TF.
        stepping[tid] = false;
        if ('rflags' in ctx) ctx.rflags = ctx.rflags.and(ptr(TF).not());
        else if ('eflags' in ctx) ctx.eflags = ctx.eflags.and(ptr(TF).not());
        arm(tid);
        return true;
    }
    return false;
});

// Arm each worker thread from its entry (runs on the new thread).
var thunk = modExport('kernel32.dll', 'BaseThreadInitThunk');
Interceptor.attach(thunk, {
    onEnter: function () { var tid = this.threadId; if (!armed[tid]) arm(tid); },
});

// Also arm any threads that already exist at attach time.
Process.enumerateThreads().forEach(function (t) { arm(t.id); });

rpc.exports = {
    configure: function (c) { return { mode: 'hwbp' }; },
    stats: function () {
        return { calls: calls, matched: calls, logged: 0, resolveCalls: 0,
                 armedThreads: Object.keys(armed).length, errors: errors.slice(0, 8) };
    },
    reset: function () { calls = 0; },
};

send({ type: 'ready', what: 'read_hwbp', target: ntReadVM.toString() });

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
