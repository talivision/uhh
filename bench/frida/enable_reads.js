// enable_reads.js - Frida analogue of examples/gated_config/callbacks.cpp
// `enable_reads` (the deferred breakpoint-flag probe).
//
// Our native probe registers a BREAKPOINT at "configparse.dll+<ParsedFlagSite RVA>"
// BEFORE configparse.dll is loaded (probe_add stays pending; the controller arms
// it on the LOAD_DLL debug event, before ParseConfig's first call). At the site
// EAX holds the freshly parsed reads_enabled value; the callback reads PROBE_REG_AX
// and, if 0, sets it to 1. A software breakpoint is used because the site is a
// 2-byte store (`mov [rcx],eax`) + ret - too short for a 5-byte inline jump.
//
// HOW FRIDA DIFFERS (important):
//   Frida cannot do our "pending probe that arms on the module-load debug event"
//   directly, because a Frida agent lives INSIDE the target and has no debug-event
//   loop. The equivalent is to watch for the module load from inside:
//     - Frida >= 16.2: Process.attachModuleObserver({ onAdded(module){...} }).
//     - Otherwise: Interceptor.attach(ntdll!LdrLoadDll, { onLeave }) and, once the
//       module is mapped, install the real hook. LdrLoadDll returns before
//       LoadLibraryA returns, which is before ParseConfig runs - so we still catch
//       the flag in time, same as our pre-first-call activation.
//   Also note: Frida's Interceptor is itself an INLINE hook. At ParsedFlagSite
//   (2-byte store + ret) there may not be enough relocatable bytes for Frida's
//   trampoline either - the same physical limit that made us pick a breakpoint.
//   So the DEFAULT method here is 'parseconfig' (hook the exported ParseConfig and
//   fix up its result), which is robust; 'flagsite' is the direct register-flip
//   mirror and is offered with that caveat.
//
// rpc.exports:
//   configure({ method, flagRva })  method = 'parseconfig' (default) | 'flagsite'
//   stats()  -> { overrides, installed, method, base }
//
// Standalone:  frida -f probe_app.exe -l enable_reads.js   (default config, no --config)

'use strict';

function modBase(name) {
    if (typeof Process.findModuleByName === 'function') {
        const m = Process.findModuleByName(name);
        return m ? m.base : null;
    }
    if (Module.findBaseAddress) return Module.findBaseAddress(name);
    return null;
}
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
    return null;
}

var cfg = { method: 'parseconfig', flagRva: 0 };
var overrides = 0, installed = false, resolvedBase = null;
const TARGET_DLL = 'configparse.dll';

rpc.exports = {
    configure: function (c) { for (var k in (c || {})) cfg[k] = c[k]; return cfg; },
    stats: function () {
        return { overrides: overrides, installed: installed, method: cfg.method,
                 base: resolvedBase ? resolvedBase.toString() : null };
    },
};

function flipParseConfig() {
    // int ParseConfig(const char *text, parsed_config *out);
    // parsed_config = { uint32_t reads_enabled; uint32_t reserved; } -> flag at +0.
    var fn = modExport(TARGET_DLL, 'ParseConfig');
    if (!fn) { send({ type: 'error', what: 'ParseConfig not exported' }); return false; }
    Interceptor.attach(fn, {
        onEnter: function (args) { this.out = args[1]; },
        onLeave: function (retval) {
            if (retval.toInt32() !== 1 || this.out.isNull()) return; // parse failed
            if (this.out.readU32() === 0) {        // mirror enable_reads: only flip 0
                this.out.writeU32(1);
                overrides++;
                send({ type: 'override', method: 'parseconfig' });
            }
        },
    });
    return true;
}

function flipFlagSite() {
    // Direct register-flip mirror. At ParsedFlagSite (base + flagRva) EAX holds the
    // parsed value, about to be stored by `mov [rcx],eax`. Set EAX=1 if it is 0.
    if (!cfg.flagRva) { send({ type: 'error', what: 'flagsite method needs flagRva' }); return false; }
    var addr = resolvedBase.add(ptr('' + cfg.flagRva));
    try {
        Interceptor.attach(addr, {
            onEnter: function () {
                var ctx = this.context;
                var hasEax = ('eax' in ctx);                 // x86 target
                var v = (hasEax ? ctx.eax : ctx.rax).toUInt32();
                if (v === 0) {
                    if (hasEax) ctx.eax = ptr(1); else ctx.rax = ptr(1);
                    overrides++;
                    send({ type: 'override', method: 'flagsite' });
                }
            },
        });
        return true;
    } catch (e) {
        // Expected failure mode: too few relocatable bytes at a 2-byte store+ret.
        send({ type: 'error', what: 'flagsite attach failed (short site); use parseconfig',
               detail: '' + e });
        return false;
    }
}

function install() {
    if (installed) return;
    resolvedBase = modBase(TARGET_DLL);
    if (!resolvedBase) return;                 // not loaded yet
    var ok = (cfg.method === 'flagsite') ? flipFlagSite() : flipParseConfig();
    if (ok) {
        installed = true;
        send({ type: 'ready', what: 'enable_reads', method: cfg.method, base: resolvedBase.toString() });
    }
}

// configparse.dll is late-loaded, so watch for it. Try the module observer first,
// fall back to hooking the loader. Also try once now in case it is already mapped.
install();
if (!installed) {
    if (typeof Process.attachModuleObserver === 'function') {
        Process.attachModuleObserver({
            onAdded: function (m) {
                if (m.name && m.name.toLowerCase() === TARGET_DLL) install();
            },
        });
    } else {
        var ldr = modExport('ntdll.dll', 'LdrLoadDll');
        if (ldr) Interceptor.attach(ldr, { onLeave: function () { install(); } });
        else send({ type: 'error', what: 'no LdrLoadDll and no module observer' });
    }
}
