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
