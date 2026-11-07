// count_hw.js -- Frida's hardware breakpoints (or watchpoints): Thread#setHardwareBreakpoint /
// setHardwareWatchpoint on EVERY thread (Process.attachThreadObserver: the existing ones right
// away, each new one synchronously on itself before it runs), and Process.setExceptionHandler
// to count the hits. The handler does the same work as count_js.js (reads the handle and the
// size where they are: registers on x64, the stack on x86).
//
// Continuing after an EXECUTE breakpoint: the CPU would re-trigger it on the same instruction.
// Set the Resume Flag (EFLAGS.RF, bit 16) in the native CONTEXT -- Frida's `context` exposes
// pc/sp/general registers but not EFLAGS -- and return true: the instruction runs once without
// the breakpoint and it stays armed (no unset/single-step/re-arm dance). A data WATCHPOINT
// traps after the access, so it needs nothing.
const kind = PARAMS.kind || 'breakpoint';             // 'breakpoint' | 'watch'
const target = resolveTarget(PARAMS.target);
const is64 = Process.pointerSize === 8;
const EFLAGS = is64 ? 0x44 : 0xc0;                    // CONTEXT.EFlags
const RF = 0x10000;
let calls = 0, sink = 0, armed = 0, other = 0;
const errors = [];

Process.setExceptionHandler(e => {
    if (e.type !== 'single-step') return false;
    if (kind === 'breakpoint') {
        if (!e.address.equals(target)) { other++; return false; }
        const c = e.context;
        const handle = is64 ? c.rcx : c.sp.add(4).readPointer();
        const size = is64 ? c.r9 : c.sp.add(16).readPointer();
        sink ^= handle.toInt32() ^ size.toInt32();
        const ef = e.nativeContext.add(EFLAGS);
        ef.writeU32(ef.readU32() | RF);
    }
    calls++;
    return true;
});

Process.attachThreadObserver({
    onAdded(thread) {
        try {
            if (kind === 'watch')
                thread.setHardwareWatchpoint(0, target, PARAMS.size || Process.pointerSize, 'w');
            else
                thread.setHardwareBreakpoint(0, target);
            armed++;
        } catch (err) {
            if (errors.length < 8) errors.push(`${thread.id}: ${err.message}`);
        }
    },
});

onProcessExit(() => send({ type: 'done', calls, armed, other, errors }));
send({ type: 'ready', target: target.toString(), runtime: Script.runtime, armed, errors });
