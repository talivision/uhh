// gated_full.js - the WHOLE examples/gated_config in Frida, for a like-for-like comparison
// with UHH's gated_config (bench/frida/gated_full.py drives both):
//   1. enable_reads: the shipped config says reads_enabled=0; flip it at ParseConfig's
//      return (Frida cannot arm a probe on the module-load debug event: a module observer
//      installs the hook when configparse.dll maps, before ParseConfig runs).
//   2. track_open_process / forget_closed_handle: handle -> pid map built at
//      ntdll!NtOpenProcess (CLIENT_ID.UniqueProcess at entry, *ProcessHandle at return),
//      entries dropped at ntdll!NtClose.
//   3. log_read: EVERY ntdll!NtReadVirtualMemory call becomes one record
//      "handle pid addr size", delivered to the host. Records are batched (4096 per send())
//      -- UHH batches its log records too; one send() per read would measure Frida's IPC.
//      A final flush runs at RtlExitUserProcess, which then holds the exiting thread until
//      the host acknowledges (post 'ack'), so no record is lost to the teardown.
'use strict';

function exp(mod, name) {
    if (typeof Process.findModuleByName === 'function') {
        const m = Process.findModuleByName(mod);
        if (m && typeof m.findExportByName === 'function') { const p = m.findExportByName(name); if (p) return p; }
    }
    if (Module.findExportByName) return Module.findExportByName(mod, name);
    return null;
}

var overrides = 0, opens = 0, reads = 0, sent = 0;
var pidByHandle = Object.create(null);
var batch = [];
const BATCH = 4096;

function flush() {
    if (batch.length === 0) return;
    var lines = batch; batch = [];
    sent += lines.length;
    send({ type: 'recs', text: lines.join('\n') });
}

// 1. the flag
function hookParseConfig() {
    var fn = exp('configparse.dll', 'ParseConfig');
    if (!fn) return false;
    Interceptor.attach(fn, {
        onEnter: function (args) { this.out = args[1]; },
        onLeave: function (retval) {
            if (retval.toInt32() === 1 && !this.out.isNull() && this.out.readU32() === 0) {
                this.out.writeU32(1); overrides++;
            }
        },
    });
    return true;
}
var flagHooked = hookParseConfig();
if (!flagHooked) {
    if (typeof Process.attachModuleObserver === 'function') {          // Frida >= 17
        Process.attachModuleObserver({
            onAdded: function (m) {
                if (!flagHooked && m.name && m.name.toLowerCase() === 'configparse.dll') flagHooked = hookParseConfig();
            },
        });
    } else {                                                            // Frida 16: after each LdrLoadDll
        Interceptor.attach(exp('ntdll.dll', 'LdrLoadDll'), {
            onLeave: function () { if (!flagHooked) flagHooked = hookParseConfig(); },
        });
    }
}

// 2. the handle -> pid map
Interceptor.attach(exp('ntdll.dll', 'NtOpenProcess'), {
    onEnter: function (args) {
        this.out = args[0];
        this.pid = args[3].isNull() ? 0 : args[3].readPointer().toUInt32();   // CLIENT_ID.UniqueProcess
    },
    onLeave: function (retval) {
        if (retval.toInt32() >= 0 && !this.out.isNull() && this.pid) {
            pidByHandle[this.out.readPointer().toString()] = this.pid; opens++;
        }
    },
});
Interceptor.attach(exp('ntdll.dll', 'NtClose'), {
    onEnter: function (args) { delete pidByHandle[args[0].toString()]; },
});

// 3. every read
Interceptor.attach(exp('ntdll.dll', 'NtReadVirtualMemory'), {
    onEnter: function (args) {
        var h = args[0].toString();
        var pid = pidByHandle[h] || 0;
        reads++;
        batch.push(h + ' ' + pid + ' ' + args[1].toString() + ' ' + args[3].toString());
        if (batch.length >= BATCH) flush();
    },
});

// Periodic flush (a slow tail is delivered without waiting for the exit).
setInterval(function () { flush(); }, 50);

Interceptor.attach(exp('ntdll.dll', 'RtlExitUserProcess'), {
    onEnter: function () {
        flush();
        send({ type: 'done', reads: reads, sent: sent, opens: opens, overrides: overrides });
        recv('ack', function () {}).wait();      // hold the exit until the host has everything
    },
});

send({ type: 'ready', flagHooked: flagHooked });
