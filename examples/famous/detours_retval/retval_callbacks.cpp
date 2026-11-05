// Return values the UHH way (Detours: call the trampoline, look at what it returned).
//
// UHH has no "on return" flag. At the ENTRY of CreateFileW the return address is at [SP];
// the callback adds a probe THERE (once per call site) with probe_add_address. That probe
// fires when CreateFileW returns to its caller: AX holds the HANDLE, and GetLastError is
// called in the target with call_func (on the hit thread, so it is that thread's value).
//
// Entry and return are matched by the STACK POINTER, which is unique per thread at any
// moment: after the return SP = entry SP + one pointer (x64), + the 7 stdcall argument
// slots on x86 (CreateFileW pops them). No thread id is needed, so the same source works
// in the controller (breakpoint/hw) and inside the target (inline), under any number of
// concurrent threads.
//
// One source for every backend: compiled into the driver and into probe_api_agent.dll.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "retval_callbacks.h"

namespace {

constexpr uint64_t kRetSpDelta = sizeof(void *) == 8 ? 8 : 4 + 7 * 4;

// In-flight calls: key = SP the caller will have after the return.
struct pending_call { volatile LONG64 key; char name[200]; };
pending_call g_pending[256];

// Return sites already probed. state: 1 = being added, 2 = armed, 3 = refused.
struct return_site { volatile LONG64 address; volatile LONG state; };
return_site g_sites[64];

void read_wstr(probe_context *c, uint64_t p, char *out, size_t cap) {
    size_t n = 0;
    if (!p) { snprintf(out, cap, "NULL"); return; }
    wchar_t chunk[32];
    for (size_t i = 0; n + 1 < cap && i < 260; i += 32) {
        if (!get_mem(c, p + i * 2, chunk, sizeof(chunk))) {      // page end: one by one
            for (size_t k = 0; n + 1 < cap && k < 32; ++k) {
                wchar_t ch = 0;
                if (!get_mem(c, p + (i + k) * 2, &ch, 2) || !ch) { out[n] = 0; return; }
                out[n++] = (ch >= 0x20 && ch < 0x7f && ch != '"') ? (char)ch : '.';
            }
            continue;
        }
        for (size_t k = 0; k < 32; ++k) {
            if (!chunk[k] || n + 1 >= cap) { out[n] = 0; return; }
            out[n++] = (chunk[k] >= 0x20 && chunk[k] < 0x7f && chunk[k] != '"') ? (char)chunk[k] : '.';
        }
    }
    out[n] = 0;
}

// Make sure a probe sits on this return address. Exactly one caller adds it; any other
// thread arriving meanwhile waits until it is armed, so its own return is not missed.
// Slots are claimed in order and never freed, so the first free slot proves the address
// is not in the table yet.
bool ensure_return_probe(probe_context *c, uint64_t ret, uint32_t flags) {
    for (auto &s : g_sites) {
        const LONG64 was = InterlockedCompareExchange64(&s.address, (LONG64)ret, 0);
        if (was == 0) {                                   // ours: add the probe
            const int ok = probe_add_address(get_session(c), ret, dretval_on_return, flags);
            InterlockedExchange(&s.state, ok ? 2 : 3);
            if (!ok) send_log(c, "return probe at 0x%llx refused", (unsigned long long)ret);
            return ok != 0;
        }
        if (was == (LONG64)ret) {                         // someone else's: wait until armed
            while (InterlockedCompareExchange(&s.state, 0, 0) < 2) SwitchToThread();
            return s.state == 2;
        }
    }
    send_log(c, "return-site table full (0x%llx)", (unsigned long long)ret);
    return false;
}

} // namespace

extern "C" DRETVAL_EXPORT void dretval_on_entry(probe_context *c) {
    const dretval_config *cfg = static_cast<const dretval_config *>(get_config(c));
    const uint64_t sp = get_reg(c, PROBE_REG_SP);
    uint64_t ret = 0;
    if (!cfg || !get_mem(c, sp, &ret, sizeof(void *))) return;
    const LONG64 key = (LONG64)(sp + kRetSpDelta);
    char path[200]; read_wstr(c, get_func_arg(c, 0), path, sizeof(path));
    pending_call *slot = nullptr;
    for (auto &p : g_pending)                         // a stale entry of this same frame first
        if (p.key == key) { slot = &p; break; }
    for (size_t i = 0; !slot && i < sizeof(g_pending) / sizeof(g_pending[0]); ++i)
        if (InterlockedCompareExchange64(&g_pending[i].key, -1, 0) == 0) slot = &g_pending[i];
    if (!slot) { send_log(c, "pending table full"); return; }
    memcpy(slot->name, path, sizeof(path));
    InterlockedExchange64(&slot->key, key);
    const bool armed = ensure_return_probe(c, ret, cfg->return_flags);
    if (cfg->log_entry)
        send_log(c, "entry \"%s\" sp=0x%llx ret=0x%llx armed=%d", path, (unsigned long long)sp,
                 (unsigned long long)ret, armed ? 1 : 0);
}

extern "C" DRETVAL_EXPORT void dretval_on_return(probe_context *c) {
    // GetLastError FIRST, before anything else could touch the thread's last-error value.
    uint64_t err = 0;
    const int err_ok = call_func(c, "KernelBase.dll!GetLastError", &err, 0);
    const uint64_t handle = get_reg(c, PROBE_REG_AX);
    const LONG64 key = (LONG64)get_reg(c, PROBE_REG_SP);
    for (auto &p : g_pending) {
        if (p.key != key) continue;
        char name[200]; memcpy(name, p.name, sizeof(name));
        InterlockedExchange64(&p.key, 0);
        const char *slash = strrchr(name, '\\');
        send_log(c, "CreateFileW(\"%s\") -> handle=0x%llx error=%lld%s", slash ? slash + 1 : name,
                 (unsigned long long)handle, err_ok ? (long long)(uint32_t)err : -1LL, err_ok ? "" : " (call_func failed)");
        return;
    }
    // Something else returned or jumped here (not a CreateFileW we saw the entry of).
    send_log(c, "return without entry at sp=0x%llx handle=0x%llx", (unsigned long long)key, (unsigned long long)handle);
}
