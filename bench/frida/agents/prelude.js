// prelude.js -- prepended to every agent by vs_frida.py, after `const PARAMS = {...};`.
'use strict';

function resolveTarget(t) {
    const m = Process.getModuleByName(t.module);
    return t.export !== undefined ? m.getExportByName(t.export) : m.base.add(t.rva);
}

// The target prints its result and exits at once. Deliver the final state at
// ntdll!RtlExitUserProcess and hold the exiting thread until the host acknowledges it
// (a blocking recv), so nothing is lost to the teardown.
function onProcessExit(fn) {
    Interceptor.attach(Process.getModuleByName('ntdll.dll').getExportByName('RtlExitUserProcess'), {
        onEnter() {
            fn();
            recv('ack', () => {}).wait();
        },
    });
}

// Frida's own code reads target memory through the hooked syscall too: since 17.25 its module
// registry handles each DLL load on the loading thread and reads the process's own memory via
// K32GetModuleInformation / GetModuleFileNameExW -> ReadProcessMemory(-1) -> NtReadVirtualMemory
// (~150 calls per DLL load). Those calls are not the program's. Cloak "keeps you from seeing
// yourself": a self-read (handle -1) with a return address into a cloaked (Frida) range among
// the nearest stack words is Frida's and is skipped. Only self-reads pay for the check.
const SELF = ptr(-1);
function isFridaSelfRead(sp) {
    for (let i = 0; i < 64; i++) {
        if (Cloak.hasRangeContaining(sp.add(i * Process.pointerSize).readPointer())) return true;
    }
    return false;
}
