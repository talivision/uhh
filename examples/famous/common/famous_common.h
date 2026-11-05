// Shared helpers for the examples/famous recipes (classic Frida / API Monitor /
// Process Monitor instrumentation re-done on UHH).
//
// Every recipe's callback source is compiled UNCHANGED into famous_driver.exe and into
// probe_api_agent.dll. State the recipes keep across probes lives in UHH_SHARED globals,
// so it is the same memory whichever backend runs a given callback (breakpoint/hw in the
// controller, inline in the target). Shared state holds values only (addresses in the
// TARGET as integers), never pointers into either process.
//
// The helpers below are the reusable "Frida idioms" mapped onto the frozen probe_api:
//   Process.mainModule               -> famous_main_module (PEB via call_func, cached)
//   Interceptor.attach onLeave       -> famous_arm_return: probe the return address read at
//                                       entry, once per distinct call site
//   this.<state> from onEnter        -> famous_pending_put/take, keyed by the stack pointer
//                                       the thread will have at the return site
//   readUtf16String / UNICODE_STRING -> famous_read_ustr / famous_read_wstr
#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "probe_api.h"
#include <stdint.h>
#include <string.h>
#include <atomic>

#define FAMOUS_EXPORT extern "C" __declspec(dllexport)

#define FAMOUS_CONFIG_VERSION 1u
// The config every recipe probe carries (probe_add_symbol_cfg). ret_flags are the flags
// a callback uses for the return-site probes it adds at runtime (the driver's backend).
struct famous_config {
    uint32_t version;
    uint32_t ret_flags;
    uint64_t value;          // recipe-specific (retval_override: the forced return value)
    char filter[96];         // recipe-specific (file_monitor: path substring, "" = everything)
};

// Case-insensitive ASCII substring test (an empty needle matches everything).
static inline char famous_lower(char ch) { return ch >= 'A' && ch <= 'Z' ? (char)(ch + 32) : ch; }
static inline bool famous_contains(const char *hay, const char *needle) {
    if (!needle || !*needle) return true;
    for (; *hay; ++hay) {
        const char *h = hay, *n = needle;
        while (*h && *n && famous_lower(*h) == famous_lower(*n)) { ++h; ++n; }
        if (!*n) return true;
    }
    return false;
}

static constexpr bool famous_x86 = sizeof(void *) == 4;
static constexpr uint64_t famous_ptr = sizeof(void *);

static inline const famous_config *famous_cfg(probe_context *c) {
    const famous_config *cfg = static_cast<const famous_config *>(get_config(c));
    return cfg && cfg->version == FAMOUS_CONFIG_VERSION ? cfg : nullptr;
}

static inline uint32_t famous_ret_flags(probe_context *c) {
    const famous_config *cfg = famous_cfg(c);
    return cfg ? cfg->ret_flags : (uint32_t)PROBE_BREAKPOINT;
}

static inline uint64_t famous_read_ptr(probe_context *c, uint64_t address, bool *ok = nullptr) {
    uint64_t v = 0;
    bool got = address && get_mem(c, address, &v, (size_t)famous_ptr) != 0;
    if (ok) *ok = got;
    return got ? v : 0;
}

// The stack pointer the thread will have at the return site of the function whose ENTRY
// this hit is: past the return address, and on x86 past the stdcall arguments.
static inline uint64_t famous_return_sp(probe_context *c, unsigned stdcall_args) {
    return get_reg(c, PROBE_REG_SP) + famous_ptr + (famous_x86 ? 4ull * stdcall_args : 0ull);
}

static inline uint64_t famous_return_address(probe_context *c) {
    return famous_read_ptr(c, get_reg(c, PROBE_REG_SP));
}

// ---- Process.mainModule ----------------------------------------------------------------
struct famous_module {
    std::atomic<uint64_t> base{0};
    std::atomic<uint64_t> size{0};
};

// The PE image mapped at `b`: SizeOfImage and whether it is an EXE (not IMAGE_FILE_DLL).
static inline bool famous_image_at(probe_context *c, uint64_t b, uint32_t &image, bool &is_exe) {
    uint16_t mz = 0; uint32_t lfanew = 0, sig = 0; uint16_t chars = 0;
    if (!get_mem(c, b, &mz, 2) || mz != 0x5a4d || !get_mem(c, b + 0x3c, &lfanew, 4) || lfanew > 0x1000 ||
        !get_mem(c, b + lfanew, &sig, 4) || sig != 0x4550 || !get_mem(c, b + lfanew + 0x16, &chars, 2) ||
        !get_mem(c, b + lfanew + 0x50, &image, 4) || !image)
        return false;
    is_exe = (chars & 0x2000) == 0;                        // IMAGE_FILE_DLL clear
    return true;
}

// [base, base+size) of the target's main image, from PEB->ImageBaseAddress: one call_func
// the first time, cached in the shared state. call_func can fail on the breakpoint/hw
// backends when another thread's callback is already inside one (calls do not nest);
// then the image containing `hint` (an address the caller cares about) is found by
// walking down the 64 KiB allocation boundaries to its PE header -- if that image is an
// EXE it is the main module.
static inline bool famous_main_module(probe_context *c, famous_module &m, uint64_t &base, uint64_t &size,
                                      uint64_t hint = 0) {
    size = m.size.load(std::memory_order_acquire);
    base = m.base.load(std::memory_order_relaxed);
    if (size) return true;
    uint64_t b = 0;
    uint32_t image = 0;
    bool is_exe = false;
    uint64_t peb = 0;
    if (call_func(c, "ntdll.dll!RtlGetCurrentPeb", &peb, 0) && peb) {
        if (famous_x86) peb &= 0xffffffffull;
        bool ok = false;
        b = famous_read_ptr(c, peb + (famous_x86 ? 0x8 : 0x10), &ok);
        if (!ok || !b || !famous_image_at(c, b, image, is_exe)) return false;
    } else {
        if (!hint) return false;
        bool found = false;
        for (uint64_t at = hint & ~0xffffull, n = 0; n < 512 && at; ++n, at -= 0x10000) {
            if (famous_image_at(c, at, image, is_exe) && hint - at < image) { found = true; b = at; break; }
        }
        if (!found || !is_exe) return false;           // not in the EXE: unknown for now
    }
    m.base.store(b, std::memory_order_relaxed);
    m.size.store(image, std::memory_order_release);
    base = b; size = image;
    return true;
}

static inline bool famous_in_main(probe_context *c, famous_module &m, uint64_t address) {
    uint64_t base = 0, size = 0;
    return famous_main_module(c, m, base, size, address) && address >= base && address - base < size;
}

// ---- onLeave: one return-site probe per distinct call site ------------------------------
struct famous_site {
    std::atomic<uint64_t> address{0};
    std::atomic<uint32_t> state{0};   // 0 being armed, 2 armed, 3 refused
    uint32_t pad{0};
};
enum { FAMOUS_SITE_ARMED = 2, FAMOUS_SITE_REFUSED = 3 };

// Ensure a probe on `ret` (a return address read at a function's entry). The first
// thread to see a site adds the probe -- from inside its callback, so it is armed before
// this very call returns -- and every other thread that sees the same site waits for
// that to finish (otherwise its return could race past the not-yet-written hook).
// Returns 1 armed, 0 refused / table full.
static inline int famous_arm_return(probe_context *c, famous_site *sites, size_t count, uint64_t ret,
                                    probe_callback cb, uint32_t flags) {
    if (!ret) return 0;
    for (size_t i = 0; i < count; ++i) {
        uint64_t a = sites[i].address.load(std::memory_order_acquire);
        if (a == 0) {
            uint64_t expected = 0;
            if (!sites[i].address.compare_exchange_strong(expected, ret, std::memory_order_acq_rel)) {
                a = expected;                         // someone claimed this slot first
            } else {
                int ok = probe_add_address(get_session(c), ret, cb, flags);
                sites[i].state.store(ok ? FAMOUS_SITE_ARMED : FAMOUS_SITE_REFUSED, std::memory_order_release);
                send_log(c, "return-site 0x%llx %s", (unsigned long long)ret, ok ? "armed" : "REFUSED");
                return ok;
            }
        }
        if (a != ret) continue;
        uint32_t st;
        while ((st = sites[i].state.load(std::memory_order_acquire)) < FAMOUS_SITE_ARMED) SwitchToThread();
        return st == FAMOUS_SITE_ARMED;
    }
    return 0;
}

// ---- entry -> return state, keyed by the return-site stack pointer ----------------------
struct famous_pending {
    std::atomic<uint64_t> key{0};     // 0 free, 1 being written/read, else the return-site SP
    uint64_t a{0}, b{0};
    char text[256]{};
};

static inline bool famous_pending_put(famous_pending *p, size_t count, uint64_t key, uint64_t a, uint64_t b,
                                      const char *text = nullptr) {
    // A stale entry with the same key (a call whose return was never seen) is replaced.
    for (int pass = 0; pass < 2; ++pass) {
        for (size_t i = 0; i < count; ++i) {
            uint64_t expected = pass == 0 ? key : 0;
            if (!p[i].key.compare_exchange_strong(expected, 1, std::memory_order_acq_rel)) continue;
            p[i].a = a; p[i].b = b;
            if (text) strncpy_s(p[i].text, sizeof(p[i].text), text, _TRUNCATE); else p[i].text[0] = 0;
            p[i].key.store(key, std::memory_order_release);
            return true;
        }
    }
    return false;
}

static inline bool famous_pending_take(famous_pending *p, size_t count, uint64_t key, uint64_t &a, uint64_t &b,
                                       char *text = nullptr, size_t text_cap = 0) {
    for (size_t i = 0; i < count; ++i) {
        uint64_t expected = key;
        if (!p[i].key.compare_exchange_strong(expected, 1, std::memory_order_acq_rel)) continue;
        a = p[i].a; b = p[i].b;
        if (text && text_cap) strncpy_s(text, text_cap, p[i].text, _TRUNCATE);
        p[i].key.store(0, std::memory_order_release);
        return true;
    }
    return false;
}

// ---- strings ----------------------------------------------------------------------------
// UTF-16 from the target -> printable ASCII (non-ASCII as '?'). Returns the length.
static inline size_t famous_wide_to_ascii(const wchar_t *w, size_t n, char *out, size_t cap) {
    size_t k = 0;
    for (size_t i = 0; i < n && k + 1 < cap; ++i) {
        wchar_t ch = w[i];
        if (!ch) break;
        out[k++] = (ch >= 0x20 && ch < 0x7f) ? (char)ch : '?';
    }
    out[k] = 0;
    return k;
}

// A UNICODE_STRING at `address` in the target: { USHORT Length; USHORT Max; PWSTR Buffer }.
static inline bool famous_read_ustr(probe_context *c, uint64_t address, char *out, size_t cap) {
    out[0] = 0;
    uint16_t len = 0;
    if (!address || !get_mem(c, address, &len, 2)) return false;
    uint64_t buffer = famous_read_ptr(c, address + famous_ptr);   // Buffer follows the padding
    wchar_t w[512];
    size_t n = len / 2; if (n > 511) n = 511;
    if (n && (!buffer || !get_mem(c, buffer, w, n * 2))) return false;
    famous_wide_to_ascii(w, n, out, cap);
    return true;
}

// OBJECT_ATTRIBUTES { ULONG Length; HANDLE RootDirectory; PUNICODE_STRING ObjectName; ... }
static inline bool famous_read_object_name(probe_context *c, uint64_t oa, char *out, size_t cap) {
    out[0] = 0;
    return oa && famous_read_ustr(c, famous_read_ptr(c, oa + 2 * famous_ptr), out, cap);
}

// A NUL-terminated UTF-16 string in the target (read in pieces that never cross a page).
static inline bool famous_read_wstr(probe_context *c, uint64_t address, char *out, size_t cap) {
    out[0] = 0;
    if (!address) return false;
    size_t k = 0;
    while (k + 1 < cap) {
        wchar_t w[32];
        uint64_t chunk = 32;
        uint64_t to_page = (0x1000 - (address & 0xfff)) / 2;
        if (to_page && to_page < chunk) chunk = to_page;
        if (!get_mem(c, address, w, (size_t)chunk * 2)) { out[k] = 0; return k != 0; }
        for (uint64_t i = 0; i < chunk; ++i) {
            if (!w[i] || k + 1 >= cap) { out[k] = 0; return true; }
            out[k++] = (w[i] >= 0x20 && w[i] < 0x7f) ? (char)w[i] : '?';
        }
        address += chunk * 2;
    }
    out[k] = 0;
    return true;
}

// Bytes -> printable text for a log line (Frida's hexdump, lite): printable ASCII kept,
// everything else as \xNN; stops before `cap`.
static inline size_t famous_escape(const uint8_t *data, size_t n, char *out, size_t cap) {
    static const char hex[] = "0123456789abcdef";
    size_t k = 0;
    for (size_t i = 0; i < n; ++i) {
        uint8_t ch = data[i];
        if (ch >= 0x20 && ch < 0x7f && ch != '\\') {
            if (k + 2 > cap) break;
            out[k++] = (char)ch;
        } else {
            if (k + 5 > cap) break;
            out[k++] = '\\'; out[k++] = 'x'; out[k++] = hex[ch >> 4]; out[k++] = hex[ch & 15];
        }
    }
    out[k] = 0;
    return k;
}
