// Detours "traceapi" sample, the UHH way: one callback decodes the arguments of each
// traced API (strings and buffers read from the target with get_mem) and logs one line
// per call. Compiled unchanged into the driver (breakpoint/hw) and the agent DLL (inline).
#include "traceapi_callbacks.h"
#include <stdio.h>
#include <string.h>

// A NUL-terminated string in the target, read in chunks (one get_mem per 64 bytes, not
// per character: on breakpoint/hw every get_mem is a cross-process read). A chunk that
// crosses into an unreadable page falls back to element-wise reads.
static void read_str(probe_context *c, uint64_t p, bool wide, char *out, size_t cap) {
    if (!p) { snprintf(out, cap, "NULL"); return; }
    const size_t unit = wide ? 2 : 1, max_chars = 260;
    size_t n = 0; out[n++] = '"';
    unsigned char chunk[64];
    for (size_t i = 0; i < max_chars;) {
        size_t want = sizeof(chunk) / unit; if (want > max_chars - i) want = max_chars - i;
        size_t got = want;
        if (!get_mem(c, p + i * unit, chunk, want * unit)) {
            got = 0;
            while (got < want && get_mem(c, p + (i + got) * unit, chunk + got * unit, unit)) ++got;
            if (!got) { if (n + 2 < cap) out[n++] = '?'; break; }
        }
        bool end = false;
        for (size_t k = 0; k < got; ++k) {
            uint16_t ch = wide ? (uint16_t)(chunk[2 * k] | (chunk[2 * k + 1] << 8)) : chunk[k];
            if (!ch) { end = true; break; }
            if (n + 3 >= cap) { end = true; break; }
            out[n++] = (ch >= 0x20 && ch < 0x7f && ch != '"') ? (char)ch : '.';
        }
        if (end || got < want) break;
        i += got;
    }
    out[n++] = '"'; out[n] = 0;
}

static const char *hkey_name(uint64_t k, char *buf, size_t cap) {
    switch ((uint32_t)k) {
    case 0x80000000u: return "HKCR";
    case 0x80000001u: return "HKCU";
    case 0x80000002u: return "HKLM";
    case 0x80000003u: return "HKU";
    default: snprintf(buf, cap, "0x%llx", (unsigned long long)k); return buf;
    }
}

// First bytes of a buffer, printable characters only ("UHHDT-PAYLOAD-...").
static void preview(probe_context *c, uint64_t p, uint64_t len, char *out, size_t cap) {
    unsigned char b[16] = {};
    size_t n = len < sizeof(b) ? (size_t)len : sizeof(b);
    if (!p || !n || !get_mem(c, p, b, n)) { snprintf(out, cap, "\"\""); return; }
    size_t o = 0; out[o++] = '"';
    for (size_t i = 0; i < n && o + 3 < cap; ++i) out[o++] = (b[i] >= 0x20 && b[i] < 0x7f && b[i] != '"') ? (char)b[i] : '.';
    out[o++] = '"'; out[o] = 0;
}

extern "C" DTRACE_EXPORT void dtrace_on_call(probe_context *c) {
    const dtrace_config *cfg = static_cast<const dtrace_config *>(get_config(c));
    if (!cfg) return;
    char a[600], b[600], k[32];
    char line[1400];
    switch (cfg->kind) {
    case DTRACE_CREATEFILEW:      // (lpFileName, dwDesiredAccess, dwShareMode, lpSA, dwCreationDisposition, ...)
        read_str(c, get_func_arg(c, 0), true, a, sizeof(a));
        snprintf(line, sizeof(line), "CreateFileW(%s, 0x%llx, disp=%llu)", a,
                 (unsigned long long)(uint32_t)get_func_arg(c, 1), (unsigned long long)(uint32_t)get_func_arg(c, 4));
        break;
    case DTRACE_READFILE:         // (hFile, lpBuffer, nNumberOfBytesToRead, ...)
        snprintf(line, sizeof(line), "ReadFile(0x%llx, %llu)", (unsigned long long)get_func_arg(c, 0),
                 (unsigned long long)(uint32_t)get_func_arg(c, 2));
        break;
    case DTRACE_WRITEFILE: {      // (hFile, lpBuffer, nNumberOfBytesToWrite, ...)
        uint64_t len = (uint32_t)get_func_arg(c, 2);
        preview(c, get_func_arg(c, 1), len, a, sizeof(a));
        snprintf(line, sizeof(line), "WriteFile(0x%llx, %llu, %s)", (unsigned long long)get_func_arg(c, 0),
                 (unsigned long long)len, a);
        break;
    }
    case DTRACE_CLOSEHANDLE:
        snprintf(line, sizeof(line), "CloseHandle(0x%llx)", (unsigned long long)get_func_arg(c, 0));
        break;
    case DTRACE_REGOPENKEYEXW:    // (hKey, lpSubKey, ulOptions, samDesired, phkResult)
        read_str(c, get_func_arg(c, 1), true, a, sizeof(a));
        snprintf(line, sizeof(line), "RegOpenKeyExW(%s, %s, 0x%llx)", hkey_name(get_func_arg(c, 0), k, sizeof(k)), a,
                 (unsigned long long)(uint32_t)get_func_arg(c, 3));
        break;
    case DTRACE_REGQUERYVALUEEXW: // (hKey, lpValueName, lpReserved, lpType, lpData, lpcbData)
        read_str(c, get_func_arg(c, 1), true, a, sizeof(a));
        snprintf(line, sizeof(line), "RegQueryValueExW(%s, %s)", hkey_name(get_func_arg(c, 0), k, sizeof(k)), a);
        break;
    case DTRACE_CREATEPROCESSINTERNALW:   // (hUserToken, lpApplicationName, lpCommandLine, ...)
        read_str(c, get_func_arg(c, 1), true, a, sizeof(a));
        read_str(c, get_func_arg(c, 2), true, b, sizeof(b));
        snprintf(line, sizeof(line), "CreateProcessInternalW(%s, %s)", a, b);
        break;
    case DTRACE_LOADLIBRARYW:
        read_str(c, get_func_arg(c, 0), true, a, sizeof(a));
        snprintf(line, sizeof(line), "LoadLibraryW(%s)", a);
        break;
    case DTRACE_LOADLIBRARYEXW:   // (lpLibFileName, hFile, dwFlags)
        read_str(c, get_func_arg(c, 0), true, a, sizeof(a));
        snprintf(line, sizeof(line), "LoadLibraryExW(%s, 0x%llx)", a, (unsigned long long)(uint32_t)get_func_arg(c, 2));
        break;
    default:
        return;
    }
    if (cfg->stack) send_log_stack(c, "%s", line); else send_log(c, "%s", line);
}
