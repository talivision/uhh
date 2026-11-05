// flagflip callback: turn on a feature flag that is a C++ virtual method. Identical source
// under every backend and on both arches: a member function gets `this` in CX (x86
// __thiscall: ECX; x64: RCX, the first argument), and its bool result is AL.
#include "callbacks.h"
#include <stdint.h>

namespace {
uint64_t read_pointer(probe_context *c, uint64_t address) {
    uintptr_t v = 0;                                   // target pointer width == ours
    return address && get_mem(c, address, &v, sizeof(v)) ? (uint64_t)v : 0;
}
}  // namespace

// Probe on the method's first instruction ("flagfeature.dll!Feature::IsEnabled", from the PDB).
extern "C" void ff_force_enabled(probe_context *c) {
    auto *cfg = static_cast<const flagflip_config *>(get_config(c));
    if (!cfg || cfg->cookie != FLAGFLIP_COOKIE) return;
    // NOT get_func_arg(c, 0): on x86 that is the first STACK argument, and __thiscall passes
    // `this` in ECX. The object is {vtable*, const char *name_, bool enabled_}.
    const uint64_t self = get_reg(c, PROBE_REG_CX);
    char name[60] = "?";
    const uint64_t name_ptr = read_pointer(c, self + sizeof(void *));
    if (name_ptr && get_mem(c, name_ptr, name, sizeof(name) - 1)) name[sizeof(name) - 1] = 0;
    else strcpy_s(name, sizeof(name), "?");
    const bool target = !cfg->feature[0] || !strcmp(name, cfg->feature);

    if (cfg->mode == FLAGFLIP_FORCE) {
        if (!target) return;                           // other objects: the original runs
        return_from(c, 1, 0);                          // x86 __thiscall: no stack arguments to pop
        send_log(c, "IsEnabled this=0x%llx name=%s original=skipped returned=1", (unsigned long long)self, name);
        return;
    }
    uint64_t original = 0;
    // nargs counts what is copied from the STACK: none here (`this` travels in CX as it is).
    if (!call_original(c, 0, &original)) {             // refused: the hit falls through unchanged
        send_log(c, "IsEnabled this=0x%llx name=%s call_original refused", (unsigned long long)self, name);
        return;
    }
    const uint64_t result = target ? 1 : (original & 0xff);   // bool: only AL is defined
    return_from(c, result, 0);
    send_log(c, "IsEnabled this=0x%llx name=%s original=%llu returned=%llu", (unsigned long long)self, name,
             (unsigned long long)(original & 0xff), (unsigned long long)result);
}
