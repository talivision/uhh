// read_stalker.js - Frida Stalker analogue: count NtReadVirtualMemory entries by
// dynamically recompiling (stalking) every worker thread and placing a call probe
// on the target.
//
// Unlike Interceptor (which patches the function once, globally, and is caught by
// ALL threads automatically), Stalker is PER-THREAD: Stalker.follow(tid) only
// traces that one thread, and probe_app creates its W worker threads AFTER we
// attach. To cover them we hook the thread entry (kernel32!BaseThreadInitThunk)
// and Stalker.follow() each worker from birth - so every read is executed under
// Stalker and Stalker.addCallProbe(ntReadVM, ...) fires once per call.
//
// This is the honest Stalker implementation for a "count every call" task, but it
// recompiles the ENTIRE execution of every worker thread, not just the one target
// call - so the overhead is expected to be orders of magnitude above a targeted
// hook. That cost IS the finding about Stalker's fitness for syscall counting.
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
var calls = 0;
var followed = Object.create(null);

// Count every call to ntReadVM made from a stalked thread. The probe reads the
// call site's args implicitly (addCallProbe gives us a GumCallDetails); we only
// count, matching 'count' mode.
Stalker.addCallProbe(ntReadVM, function (args) { calls++; });

// Follow every worker thread from its entry thunk (runs ON the new thread).
var thunk = modExport('kernel32.dll', 'BaseThreadInitThunk');
Interceptor.attach(thunk, {
    onEnter: function () {
        var tid = this.threadId;
        if (!followed[tid]) {
            followed[tid] = 1;
            try { Stalker.follow(tid); } catch (e) { send({ type: 'error', what: 'follow', detail: '' + e }); }
        }
    },
});

rpc.exports = {
    configure: function (c) { return { mode: 'stalker' }; },
    stats: function () {
        try { Stalker.flush(); } catch (e) {}
        return { calls: calls, matched: calls, logged: 0, resolveCalls: 0,
                 followedThreads: Object.keys(followed).length };
    },
    reset: function () { calls = 0; },
};

send({ type: 'ready', what: 'read_stalker', target: ntReadVM.toString() });

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
