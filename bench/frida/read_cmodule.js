// read_cmodule.js - Frida CModule analogue of log_read's hot path.
//
// Same hook target as read_logger.js (ntdll!NtReadVirtualMemory) and the same
// "count mode" semantics (read args[0]+args[3], bump a counter, no send()), but
// the onEnter callback is compiled C that runs NATIVELY inside Frida's
// Interceptor - there is NO per-call JS bridge. This is the fairer apples-to-
// apples comparison for our native inline backend, because our log_read is also
// native C++; read_logger.js (JS onEnter) pays the GumV8/QuickJS call bridge on
// every hit, which CModule removes.
//
// rpc.exports: configure(cfg) [no-op, for harness symmetry], stats(), reset().

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

// Native onEnter: read the 1st and 4th args, accumulate so the reads are not
// optimized away, and bump a 64-bit counter. Mirrors log_read's (void)probe_arg
// reads + a hot-path bump; no message is sent (count mode).
var cm = new CModule(
    '#include <gum/guminterceptor.h>\n' +
    'unsigned long long g_calls = 0;\n' +
    'unsigned long long g_sink  = 0;\n' +
    'void onEnter (GumInvocationContext * ic)\n' +
    '{\n' +
    '  g_calls++;\n' +
    '  void * h  = gum_invocation_context_get_nth_argument (ic, 0);\n' +
    '  void * sz = gum_invocation_context_get_nth_argument (ic, 3);\n' +
    '  g_sink += (unsigned long long) h ^ (unsigned long long) sz;\n' +
    '}\n'
);

// Pass the CModule directly: Frida binds its exported onEnter (and onLeave, if
// any) as a NATIVE listener - no per-call JS bridge. (Passing cm.onEnter as a
// plain NativePointer in a listener object is the wrong form and wedges the call.)
Interceptor.attach(ntReadVM, cm);

function calls() { return cm.g_calls.readU64().valueOf(); }

rpc.exports = {
    configure: function (c) { return { mode: 'count-cmodule' }; },
    stats: function () { return { calls: calls(), matched: calls(), logged: 0, resolveCalls: 0 }; },
    reset: function () { cm.g_calls.writeU64(0); cm.g_sink.writeU64(0); },
};

send({ type: 'ready', what: 'read_cmodule', target: ntReadVM.toString() });

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
