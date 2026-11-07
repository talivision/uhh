// gated_js.js -- the WHOLE examples/gated_config in Frida JavaScript, record for record:
//
//  1. enable_reads: the shipped config says reads_enabled=0. When configparse.dll maps
//     (Process.attachModuleObserver: synchronously after the load, before the program uses it),
//     an instruction probe at configparse.dll!ParseConfig+0x16 -- Interceptor.attach(address,
//     function) -- sees the freshly parsed flag in EAX and makes it 1. Same site, same register
//     flip as UHH's enable_reads; nothing else is touched.
//  2. track_open_process: ntdll!NtOpenProcess (PHANDLE out, ACCESS_MASK, POBJECT_ATTRIBUTES,
//     PCLIENT_ID). onEnter reads CLIENT_ID.UniqueProcess (the pid) and remembers `out`; onLeave
//     reads the REAL returned handle from *out and maps handle -> pid -> image name (the name by
//     pid via NtQuerySystemInformation(SystemProcessIdInformation), as UHH does: opening the
//     process here would re-enter this hook). Logs "open ..." and "map ...".
//     forget_closed_handle: ntdll!NtClose drops the handle at entry.
//  3. log_read: EVERY ntdll!NtReadVirtualMemory call is one record "read handle=.. pid=.. name=..
//     addr=.. size=..", the same text UHH's log_read produces, with the thread id.
//
// Delivery: records are batched the way real Frida tools do it (frida-trace, fridump, ...):
// accumulated and sent every PARAMS.batch records, and at least every PARAMS.flushMs ms, so a
// slow tail is not held back. Nothing is dropped: the final flush runs at process exit and the
// exit is held until the host has acknowledged it.
const BATCH = PARAMS.batch || 4096;
const FLUSH_MS = PARAMS.flushMs || 20;
const is64 = Process.pointerSize === 8;
const ntdll = Process.getModuleByName('ntdll.dll');

let overrides = 0, flagHits = 0, opens = 0, reads = 0, sent = 0, batches = 0;
const byHandle = new Map();                     // handle string -> { pid, name }
let lines = [];

function flush() {
    if (lines.length === 0) return;
    const text = lines.join('\n');
    sent += lines.length; batches++;
    lines = [];
    send({ type: 'recs', text });
}
function log(tid, msg) {
    lines.push(tid + '\t' + msg);
    if (lines.length >= BATCH) flush();
}

// --- 1. the flag -------------------------------------------------------------------------
function hookFlag(m) {
    const site = m.getExportByName('ParseConfig').add(0x16);
    Interceptor.attach(site, function () {
        flagHits++;
        const ctx = this.context;
        if (is64) { if (ctx.rax.and(0xffffffff).isNull()) { ctx.rax = ptr(1); overrides++; } }
        else if (ctx.eax.isNull()) { ctx.eax = ptr(1); overrides++; }
    });
}
Process.attachModuleObserver({
    onAdded(m) { if (m.name.toLowerCase() === 'configparse.dll') hookFlag(m); },
});

// --- 2. handle -> pid -> name -------------------------------------------------------------
const NtQuerySystemInformation = new NativeFunction(ntdll.getExportByName('NtQuerySystemInformation'),
    'int', ['int', 'pointer', 'uint', 'pointer']);
const SystemProcessIdInformation = 88;
const infoSize = is64 ? 24 : 12;                // { HANDLE ProcessId; UNICODE_STRING ImageName; }
const info = Memory.alloc(infoSize);
const pathBuf = Memory.alloc(1024);
function imageNameOf(pid) {
    info.writePointer(ptr(pid));
    const us = info.add(Process.pointerSize);
    us.writeU16(0); us.add(2).writeU16(1024); us.add(is64 ? 8 : 4).writePointer(pathBuf);
    if (NtQuerySystemInformation(SystemProcessIdInformation, info, infoSize, NULL) < 0) return '?';
    const path = pathBuf.readUtf16String(us.readU16() / 2);
    const name = path.substring(path.lastIndexOf('\\') + 1);
    return name.length ? name : '?';
}

Interceptor.attach(ntdll.getExportByName('NtOpenProcess'), {
    onEnter(args) {
        this.out = args[0];
        const cid = args[3];
        this.pid = cid.isNull() ? 0 : cid.readPointer().toUInt32();
    },
    onLeave(retval) {
        if (retval.toInt32() < 0 || this.out.isNull() || this.pid === 0) return;
        const handle = this.out.readPointer();
        if (handle.isNull()) return;
        const name = imageNameOf(this.pid);
        log(this.threadId, `open pid=${this.pid} name=${name}`);
        byHandle.set(handle.toString(), { pid: this.pid, name });
        opens++;
        log(this.threadId, `map handle=${handle} -> pid=${this.pid} name=${name}`);
    },
});

Interceptor.attach(ntdll.getExportByName('NtClose'), {
    onEnter(args) { byHandle.delete(args[0].toString()); },
});

// --- 3. every read -------------------------------------------------------------------------
Interceptor.attach(ntdll.getExportByName('NtReadVirtualMemory'), {
    onEnter(args) {
        const handle = args[0].toString();
        const e = byHandle.get(handle);
        reads++;
        log(this.threadId, `read handle=${handle} pid=${e ? e.pid : 0} name=${e ? e.name : '?'} ` +
                           `addr=${args[1]} size=${args[3].toUInt32()}`);
    },
});

setInterval(flush, FLUSH_MS);

onProcessExit(() => {
    flush();
    send({ type: 'done', reads, opens, sent, batches, overrides, flagHits });
});
send({ type: 'ready', runtime: Script.runtime });
