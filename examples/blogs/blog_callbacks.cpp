// Blog-replica callbacks: the argument/buffer decoding that API-monitor write-ups do,
// written once against the UHH context API. Pointer-sized fields are read with the
// TARGET's pointer size, which is this build's (the controller has the target's bitness).
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>

#include "blog_callbacks.h"

namespace {

constexpr size_t PTR = sizeof(void *);

const blog_config *cfg(probe_context *c) {
    const blog_config *k = static_cast<const blog_config *>(get_config(c));
    return (k && k->cookie == BLOG_COOKIE) ? k : nullptr;
}
bool logging(probe_context *c) { const blog_config *k = cfg(c); return !k || k->log; }

uint64_t read_ptr(probe_context *c, uint64_t at, bool *ok = nullptr) {
    uint64_t v = 0;
    bool r = at && get_mem(c, at, &v, PTR);
    if (ok) *ok = r;
    return r ? v : 0;
}

// Printable copy of `n` target bytes (non-printables as '.').
void printable(probe_context *c, uint64_t p, size_t n, char *out, size_t cap) {
    if (cap == 0) return;
    unsigned char buf[128] = {};
    if (n > sizeof buf) n = sizeof buf;
    if (n + 1 > cap) n = cap - 1;
    if (!p || !get_mem(c, p, buf, n)) { snprintf(out, cap, "?"); return; }
    for (size_t i = 0; i < n; ++i) out[i] = (buf[i] >= 0x20 && buf[i] < 0x7f && buf[i] != '"' && buf[i] != '\\') ? (char)buf[i] : '.';
    out[n] = 0;
}

// `chars` UTF-16 code units at p -> ASCII (non-ASCII as '.'), one get_mem for the lot.
void wide(probe_context *c, uint64_t p, size_t chars, char *out, size_t cap) {
    wchar_t buf[300] = {};
    if (cap == 0) return;
    if (chars > 299) chars = 299;
    if (chars + 1 > cap) chars = cap - 1;
    if (!p) { snprintf(out, cap, "NULL"); return; }
    if (!get_mem(c, p, buf, chars * 2)) {
        // Unknown length (a C string near the end of a page): fall back to small chunks.
        size_t got = 0;
        while (got < chars && get_mem(c, p + got * 2, buf + got, 2)) { if (!buf[got]) break; ++got; }
        chars = got;
    }
    size_t i = 0;
    for (; i < chars && buf[i]; ++i) out[i] = (buf[i] >= 0x20 && buf[i] < 0x7f && buf[i] != '"' && buf[i] != '\\') ? (char)buf[i] : (buf[i] == '\\' ? '/' : '.');
    out[i] = 0;
}

// UNICODE_STRING { USHORT Length, MaximumLength; PWSTR Buffer; } at p. `base` is added to
// Buffer when it is an offset (de-normalized RTL_USER_PROCESS_PARAMETERS).
void ustr(probe_context *c, uint64_t p, char *out, size_t cap, uint64_t base = 0) {
    uint16_t len = 0;
    if (!p || !get_mem(c, p, &len, 2)) { snprintf(out, cap, "?"); return; }
    uint64_t buf = read_ptr(c, p + PTR);
    if (!buf) { snprintf(out, cap, "%s", len ? "?" : ""); return; }
    wide(c, buf + base, len / 2u, out, cap);
}

void guid(probe_context *c, uint64_t p, char *out, size_t cap) {
    unsigned char g[16];
    if (!p || !get_mem(c, p, g, 16)) { snprintf(out, cap, "?"); return; }
    uint32_t d1; uint16_t d2, d3; memcpy(&d1, g, 4); memcpy(&d2, g + 4, 2); memcpy(&d3, g + 6, 2);
    snprintf(out, cap, "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}", d1, d2, d3,
             g[8], g[9], g[10], g[11], g[12], g[13], g[14], g[15]);
}

/* ---- target-side scratch memory for call_func out-parameters (registry key names) ----
   Allocated once IN THE TARGET (kernelbase!VirtualAlloc via call_func) -- a deliberate,
   documented side effect: one 64 KiB private region. Its address lives where the callbacks
   run (controller for breakpoint/hw, the agent for inline): either way an address in the
   target. One lock serializes its use. */
SRWLOCK g_scratch_lock = SRWLOCK_INIT;
uint64_t g_scratch;

// Full NT path of a registry key handle: NtQueryKey(h, KeyNameInformation, ...) run IN THE
// target on the hit thread (handles are per process).
void key_path(probe_context *c, uint64_t handle, char *out, size_t cap) {
    snprintf(out, cap, "?");
    if (!handle) { snprintf(out, cap, ""); return; }
    AcquireSRWLockExclusive(&g_scratch_lock);
    uint64_t r = 0;
    if (!g_scratch && call_func(c, "kernelbase.dll!VirtualAlloc", &r, 4, (uint64_t)0, (uint64_t)0x10000,
                                (uint64_t)(MEM_COMMIT | MEM_RESERVE), (uint64_t)PAGE_READWRITE) && r)
        g_scratch = r;
    if (g_scratch) {
        const uint64_t result_len = g_scratch, info = g_scratch + 16, info_len = 0x10000 - 16;
        uint64_t st = 1;
        if (call_func(c, "ntdll.dll!NtQueryKey", &st, 5, handle, (uint64_t)3 /* KeyNameInformation */,
                      info, info_len, result_len) && (uint32_t)st == 0) {
            uint32_t name_len = 0;
            if (get_mem(c, info, &name_len, 4)) wide(c, info + 4, name_len / 2u, out, cap);
        } else {
            snprintf(out, cap, "status=0x%08x", (uint32_t)st);
        }
    }
    ReleaseSRWLockExclusive(&g_scratch_lock);
}

/* ---- BCryptGenRandom: entry -> remember the output buffer by entry SP; return -> read it */
struct pending { uint64_t sp, buf; };
SRWLOCK g_rng_lock = SRWLOCK_INIT;
pending g_pending[256];
uint64_t g_ret_sites[8];

}  // namespace

/* =============================== crypto ================================== */

// NTSTATUS BCryptEncrypt(hKey, pbInput, cbInput, pPaddingInfo, pbIV, cbIV, pbOutput,
//                        cbOutput, pcbResult, dwFlags) -- the plaintext is captured at entry.
BLOG_EXPORT void blog_on_bcrypt_encrypt(probe_context *c) {
    if (!logging(c)) return;
    uint64_t in = get_func_arg(c, 1), cb = get_func_arg(c, 2) & 0xffffffffu, iv = get_func_arg(c, 4);
    unsigned char ivb[16] = {}; char pt[40], ivh[40];
    printable(c, in, 24, pt, sizeof pt);
    if (iv && get_mem(c, iv, ivb, 16)) for (int i = 0; i < 16; ++i) snprintf(ivh + i * 2, 3, "%02x", ivb[i]);
    else snprintf(ivh, sizeof ivh, "none");
    send_log(c, "BCryptEncrypt key=0x%llx len=%llu iv=%s flags=0x%llx pt=\"%s\"",
             (unsigned long long)get_func_arg(c, 0), (unsigned long long)cb, ivh,
             (unsigned long long)(get_func_arg(c, 9) & 0xffffffffu), pt);
}

// NTSTATUS BCryptGenRandom(hAlg, pbBuffer, cbBuffer, dwFlags): the bytes only exist at the
// RETURN, so the entry callback reads the return address and probes it (once per site).
BLOG_EXPORT void blog_on_genrandom(probe_context *c) {
    uint64_t buf = get_func_arg(c, 1), len = get_func_arg(c, 2) & 0xffffffffu;
    if (len != BLOG_RNG_LEN) {
        if (logging(c)) send_log(c, "BCryptGenRandom len=%llu (not captured)", (unsigned long long)len);
        return;
    }
    const uint64_t sp = get_reg(c, PROBE_REG_SP);
    const uint64_t ret = read_ptr(c, sp);
    const blog_config *k = cfg(c);
    uint32_t flags = k ? k->backend : PROBE_BREAKPOINT;
    if (flags & PROBE_INLINE) flags |= PROBE_FALLBACK_HW;   // a return site may not be inline-safe
    AcquireSRWLockExclusive(&g_rng_lock);
    for (auto &p : g_pending) if (!p.sp) { p.sp = sp; p.buf = buf; break; }
    bool known = false;
    for (uint64_t s : g_ret_sites) known = known || s == ret;
    if (!known && ret) {
        // Added under the lock: a second thread at this entry waits until the return
        // probe is armed, so its return cannot slip past unobserved.
        for (auto &s : g_ret_sites) if (!s) { s = ret; break; }
        if (!probe_add_address(get_session(c), ret, blog_on_genrandom_ret, flags))
            send_log(c, "BCryptGenRandom: return probe at 0x%llx REFUSED", (unsigned long long)ret);
    }
    ReleaseSRWLockExclusive(&g_rng_lock);
}

BLOG_EXPORT void blog_on_genrandom_ret(probe_context *c) {
    // Entry SP from the SP after `ret`: x64 pops the return address; x86 stdcall also
    // pops the 4 argument slots.
    const uint64_t sp = get_reg(c, PROBE_REG_SP);
    const uint64_t entry_sp = (PTR == 8) ? sp - 8 : sp - 4 - 16;
    uint64_t buf = 0;
    AcquireSRWLockExclusive(&g_rng_lock);
    for (auto &p : g_pending) if (p.sp == entry_sp) { buf = p.buf; p.sp = 0; break; }
    ReleaseSRWLockExclusive(&g_rng_lock);
    if (!buf) return;          // a return to this site from some other call: not ours
    uint64_t first = 0;
    get_mem(c, buf, &first, 8);
    if (logging(c))
        send_log(c, "BCryptGenRandom ret status=0x%08llx key_first8=%016llx",
                 (unsigned long long)(get_reg(c, PROBE_REG_AX) & 0xffffffffu), (unsigned long long)first);
}

// BOOL CryptEncrypt(hKey, hHash, Final, dwFlags, pbData, pdwDataLen, dwBufLen)
BLOG_EXPORT void blog_on_capi_encrypt(probe_context *c) {
    if (!logging(c)) return;
    uint32_t len = 0; char pt[40];
    get_mem(c, get_func_arg(c, 5), &len, 4);
    printable(c, get_func_arg(c, 4), 24, pt, sizeof pt);
    send_log(c, "CryptEncrypt key=0x%llx final=%llu len=%u buflen=%llu pt=\"%s\"",
             (unsigned long long)get_func_arg(c, 0), (unsigned long long)(get_func_arg(c, 2) & 0xffffffffu), len,
             (unsigned long long)(get_func_arg(c, 6) & 0xffffffffu), pt);
}

/* ============================== registry ================================= */

// NtCreateKey(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, TitleIndex, Class, CreateOptions, Disposition)
// OBJECT_ATTRIBUTES { ULONG Length; HANDLE RootDirectory; PUNICODE_STRING ObjectName; ... }
BLOG_EXPORT void blog_on_ntcreatekey(probe_context *c) {
    if (!logging(c)) return;
    uint64_t oa = get_func_arg(c, 2);
    uint64_t root = read_ptr(c, oa + PTR), name = read_ptr(c, oa + 2 * PTR);
    char rootp[400], namep[400];
    key_path(c, root, rootp, sizeof rootp);
    ustr(c, name, namep, sizeof namep);
    send_log(c, "NtCreateKey root=\"%s\" name=\"%s\"", rootp, namep);
}

// NtSetValueKey(KeyHandle, PUNICODE_STRING ValueName, TitleIndex, Type, Data, DataSize)
BLOG_EXPORT void blog_on_ntsetvaluekey(probe_context *c) {
    if (!logging(c)) return;
    char keyp[400], name[200], data[300];
    key_path(c, get_func_arg(c, 0), keyp, sizeof keyp);
    ustr(c, get_func_arg(c, 1), name, sizeof name);
    const uint32_t type = (uint32_t)get_func_arg(c, 3), size = (uint32_t)get_func_arg(c, 5);
    if (type == REG_SZ || type == REG_EXPAND_SZ) wide(c, get_func_arg(c, 4), size / 2u, data, sizeof data);
    else printable(c, get_func_arg(c, 4), size < 32 ? size : 32, data, sizeof data);
    send_log(c, "NtSetValueKey key=\"%s\" value=\"%s\" type=%u size=%u data=\"%s\"", keyp, name, type, size, data);
}

/* =============================== network ================================= */

// DNS_STATUS DnsQuery_W(PCWSTR name, WORD type, DWORD options, PVOID extra, PDNS_RECORD*, PVOID*)
BLOG_EXPORT void blog_on_dnsquery(probe_context *c) {
    if (!logging(c)) return;
    char name[260];
    wide(c, get_func_arg(c, 0), 255, name, sizeof name);
    send_log(c, "DnsQuery_W name=\"%s\" type=%llu options=0x%llx", name,
             (unsigned long long)(get_func_arg(c, 1) & 0xffff), (unsigned long long)(get_func_arg(c, 2) & 0xffffffffu));
}

// connect(s, const sockaddr*, namelen) and WSAConnect(s, const sockaddr*, namelen, ...)
BLOG_EXPORT void blog_on_connect(probe_context *c) {
    if (!logging(c)) return;
    unsigned char sa[8] = {};
    uint64_t p = get_func_arg(c, 1);
    if (!p || !get_mem(c, p, sa, 8)) { send_log(c, "connect sock=0x%llx addr=?", (unsigned long long)get_func_arg(c, 0)); return; }
    unsigned family = sa[0] | (sa[1] << 8), port = (sa[2] << 8) | sa[3];
    if (family == 2)   /* AF_INET */
        send_log(c, "connect sock=0x%llx addr=%u.%u.%u.%u:%u", (unsigned long long)get_func_arg(c, 0), sa[4], sa[5], sa[6], sa[7], port);
    else
        send_log(c, "connect sock=0x%llx family=%u port=%u", (unsigned long long)get_func_arg(c, 0), family, port);
}

// send(s, buf, len, flags): the payload is captured at entry.
BLOG_EXPORT void blog_on_send(probe_context *c) {
    if (!logging(c)) return;
    char data[40];
    const uint64_t len = get_func_arg(c, 2) & 0xffffffffu;
    printable(c, get_func_arg(c, 1), len < 32 ? (size_t)len : 32, data, sizeof data);
    send_log(c, "send sock=0x%llx len=%llu data=\"%s\"", (unsigned long long)get_func_arg(c, 0), (unsigned long long)len, data);
}

// recv(s, buf, len, flags): at entry only the request is known (the data arrives at return).
BLOG_EXPORT void blog_on_recv(probe_context *c) {
    if (!logging(c)) return;
    send_log(c, "recv sock=0x%llx max=%llu", (unsigned long long)get_func_arg(c, 0),
             (unsigned long long)(get_func_arg(c, 2) & 0xffffffffu));
}

/* =========================== process creation ============================ */

// kernelbase!CreateProcessInternalW(hUserToken, lpApplicationName, lpCommandLine,
//   lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, ...)
BLOG_EXPORT void blog_on_create_process_internal(probe_context *c) {
    if (!logging(c)) return;
    char app[300], cmd[300];
    wide(c, get_func_arg(c, 1), 260, app, sizeof app);
    wide(c, get_func_arg(c, 2), 290, cmd, sizeof cmd);
    send_log(c, "CreateProcessInternalW app=\"%s\" cmd=\"%s\" flags=0x%llx", app, cmd,
             (unsigned long long)(get_func_arg(c, 6) & 0xffffffffu));
}

// ntdll!NtCreateUserProcess(..., ProcessParameters = arg 8, ...): the image and command
// line from RTL_USER_PROCESS_PARAMETERS (ImagePathName/CommandLine at 0x60/0x70 on x64,
// 0x38/0x40 on x86; Buffer is an offset unless Flags has RTL_USER_PROC_PARAMS_NORMALIZED).
BLOG_EXPORT void blog_on_nt_create_user_process(probe_context *c) {
    if (!logging(c)) return;
    const uint64_t pp = get_func_arg(c, 8);
    uint32_t flags = 0;
    get_mem(c, pp + 8, &flags, 4);
    const uint64_t base = (flags & 1u) ? 0 : pp;
    char image[300], cmd[300];
    ustr(c, pp + (PTR == 8 ? 0x60 : 0x38), image, sizeof image, base);
    ustr(c, pp + (PTR == 8 ? 0x70 : 0x40), cmd, sizeof cmd, base);
    send_log(c, "NtCreateUserProcess image=\"%s\" cmd=\"%s\"", image, cmd);
}

/* ================================= COM =================================== */

// HRESULT CoCreateInstance(REFCLSID, LPUNKNOWN, DWORD dwClsContext, REFIID, LPVOID*)
BLOG_EXPORT void blog_on_cocreateinstance(probe_context *c) {
    if (!logging(c)) return;
    char clsid[48], iid[48];
    guid(c, get_func_arg(c, 0), clsid, sizeof clsid);
    guid(c, get_func_arg(c, 3), iid, sizeof iid);
    send_log(c, "CoCreateInstance clsid=%s iid=%s ctx=0x%llx", clsid, iid,
             (unsigned long long)(get_func_arg(c, 2) & 0xffffffffu));
}

/* ================================ game =================================== */

// uint64_t blog_frame(uint32_t frame, uint64_t *state): one hit per frame.
BLOG_EXPORT void blog_on_frame(probe_context *c) {
    if (!logging(c)) return;
    send_log(c, "frame %llu", (unsigned long long)(get_func_arg(c, 0) & 0xffffffffu));
}
