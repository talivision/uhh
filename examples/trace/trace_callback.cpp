// The one callback behind uhh_trace. Compiled into the tracer (breakpoint/hw backends)
// and into the agent DLL (inline backend): same source, every backend.
#include "trace_callback.h"
#include <stdio.h>
#include <string.h>

static void append(char *out, size_t cap, size_t &at, const char *text) {
    while (*text && at + 1 < cap) out[at++] = *text++;
    out[at] = 0;
}

static void read_string(probe_context *c, uint64_t p, bool wide, char *out, size_t cap) {
    size_t n = 0;
    if (!p) { snprintf(out, cap, "NULL"); return; }
    out[n++] = '"';
    for (size_t i = 0; i < 200 && n + 3 < cap; ++i) {
        uint16_t ch = 0;
        if (!get_mem(c, p + i * (wide ? 2 : 1), &ch, wide ? 2 : 1)) { out[n++] = '?'; break; }
        if (!ch) break;
        out[n++] = (ch >= 0x20 && ch < 0x7f) ? (char)ch : '.';
    }
    out[n++] = '"'; out[n] = 0;
}

/* OBJECT_ATTRIBUTES -> its ObjectName (UNICODE_STRING), e.g. NtCreateFile/NtOpenFile arg 2. */
static void read_objattr(probe_context *c, uint64_t p, char *out, size_t cap) {
    size_t ptr = sizeof(void *);
    uint64_t name_ptr = 0, buf = 0; uint16_t len = 0;
    if (!p || !get_mem(c, p + 2 * ptr, &name_ptr, ptr) || !name_ptr ||   /* Length+pad, RootDirectory, ObjectName */
        !get_mem(c, name_ptr, &len, 2) || !get_mem(c, name_ptr + ptr, &buf, ptr) || !buf) {
        snprintf(out, cap, "objattr@0x%llx", (unsigned long long)p); return;
    }
    size_t n = 0; out[n++] = '"';
    for (size_t i = 0; i < len / 2u && n + 3 < cap; ++i) {
        uint16_t ch = 0;
        if (!get_mem(c, buf + i * 2, &ch, 2)) break;
        out[n++] = (ch >= 0x20 && ch < 0x7f) ? (char)ch : '.';
    }
    out[n++] = '"'; out[n] = 0;
}

static void read_sockaddr(probe_context *c, uint64_t p, char *out, size_t cap) {
    unsigned char sa[28] = {0};
    if (!p || !get_mem(c, p, sa, 8)) { snprintf(out, cap, "sockaddr@0x%llx", (unsigned long long)p); return; }
    unsigned family = sa[0] | (sa[1] << 8), port = (sa[2] << 8) | sa[3];
    if (family == 2)
        snprintf(out, cap, "%u.%u.%u.%u:%u", sa[4], sa[5], sa[6], sa[7], port);
    else if (family == 23)
        snprintf(out, cap, "[ipv6]:%u", port);
    else
        snprintf(out, cap, "family=%u port=%u", family, port);
}

extern "C" __declspec(dllexport) void uhh_trace_call(probe_context *c) {
    const trace_config *cfg = (const trace_config *)get_config(c);
    if (!cfg || cfg->fmt[0] == '-') return;            // ":-" = count hits only, no log
    char line[600]; size_t at = 0; line[0] = 0;
    append(line, sizeof(line), at, cfg->name);
    append(line, sizeof(line), at, "(");
    for (size_t i = 0; i < sizeof(cfg->fmt) && cfg->fmt[i]; ++i) {
        char item[260];
        uint64_t v = get_func_arg(c, i);
        switch (cfg->fmt[i]) {
        case 'd': snprintf(item, sizeof(item), "%lld", (long long)(int64_t)v); break;
        case 's': read_string(c, v, false, item, sizeof(item)); break;
        case 'W': read_string(c, v, true, item, sizeof(item)); break;
        case 'S': read_sockaddr(c, v, item, sizeof(item)); break;
        case 'O': read_objattr(c, v, item, sizeof(item)); break;
        case '-': snprintf(item, sizeof(item), "_"); break;
        default:  snprintf(item, sizeof(item), "0x%llx", (unsigned long long)v); break;
        }
        if (i) append(line, sizeof(line), at, ", ");
        append(line, sizeof(line), at, item);
    }
    append(line, sizeof(line), at, ")");
    if (cfg->stack) send_log_stack(c, "%s", line); else send_log(c, "%s", line);
}
