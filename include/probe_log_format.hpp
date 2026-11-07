// Library-private: format one send_log / send_log_stack line. Shared by the controller
// (breakpoint/hw callbacks) and the inline agent (inside the target) so that every
// backend produces the SAME text for the same call, including the bad cases:
//   - fits:            the formatted text
//   - too long:        truncated to cap-1, ending in "...[truncated]" (also when the
//                      "[unformattable]" copy of a long format does not fit)
//   - embedded NULs (%c of 0) are part of the text: the length is returned, and the JSON
//     writer escapes them (\u0000) like every other control character
//   - invalid format (%n, a lone trailing %; the CRT itself prints an unknown conversion
//     such as %k as its letter) or an
//     argument that faults while formatting (%s of a bad pointer):
//                      "[unformattable] " followed by the raw format string
// Never terminates the process: the CRT's invalid-parameter handler (whose default is a
// fast-fail of the WHOLE process -- the controller, or the target for inline) is replaced
// for this thread for the duration of the call, and faults are caught. (A fault inside
// the target is still a first-chance exception the target's vectored handlers can see.)
#pragma once
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

inline void __cdecl uhh_ignore_invalid_parameter(const wchar_t *, const wchar_t *, const wchar_t *, unsigned, uintptr_t) {}

// The fast path: the conversions callbacks log in hot paths, formatted without the CRT's printf
// engine (whose setup -- per-thread locale and invalid-parameter state, a generic state machine --
// cost more than the hook itself: profiles of a send_log-bound inline target). Handles only
//   %% and %d %i %u %x %X %o %c %s %p with no flags, width or precision, and the length
//   modifiers hh h l ll I I32 I64 z t j (not on %c/%s/%p),
// and produces exactly what the CRT's vsnprintf does for those (checked against it by
// log_format_selftest, regress `logs-format-fast`): %s of NULL is "(null)", %p is
// 2*sizeof(void*) upper-case hex digits, %c of 0 writes a NUL. Writes up to cap-1 bytes and a
// NUL, and returns the FULL length like vsnprintf (a longer line is truncated by the caller).
// Anything else returns -2 before the caller's va_list is used: the caller formats with
// vsnprintf instead. A fault (%s of a bad pointer) is the caller's to catch, as with vsnprintf.
inline int uhh_format_fast(char *buf, size_t cap, const char *format, va_list ap) {
    size_t n = 0;
    auto put = [&](char ch) { if (n + 1 < cap) buf[n] = ch; ++n; };
    for (const char *p = format; *p; ++p) {
        if (*p != '%') { put(*p); continue; }
        ++p;
        if (*p == '%') { put('%'); continue; }
        enum { L_INT, L_CHAR, L_SHORT, L_64, L_PTR } len = L_INT;
        bool modified = true;
        switch (*p) {
        case 'h': if (p[1] == 'h') { len = L_CHAR; p += 2; } else { len = L_SHORT; ++p; } break;
        case 'l': if (p[1] == 'l') { len = L_64; p += 2; } else { len = L_INT; ++p; } break;   // long: 32 bits on Windows
        case 'j': len = L_64; ++p; break;
        case 'z': case 't': len = L_PTR; ++p; break;
        case 'I':
            if (p[1] == '6' && p[2] == '4') { len = L_64; p += 3; }
            else if (p[1] == '3' && p[2] == '2') { len = L_INT; p += 3; }
            else { len = L_PTR; ++p; }
            break;
        default: modified = false;
        }
        const char conv = *p;
        if (conv == 's' || conv == 'c' || conv == 'p') {
            if (modified) return -2;
            if (conv == 's') {
                const char *str = va_arg(ap, const char *);
                if (!str) str = "(null)";
                for (; *str; ++str) put(*str);
            } else if (conv == 'c') {
                put((char)va_arg(ap, int));
            } else {
                uint64_t v = (uint64_t)(uintptr_t)va_arg(ap, void *);
                for (int d = (int)(2 * sizeof(void *)) - 1; d >= 0; --d) put("0123456789ABCDEF"[(v >> (4 * d)) & 15]);
            }
            continue;
        }
        const bool is_signed = conv == 'd' || conv == 'i';
        unsigned base = conv == 'x' || conv == 'X' ? 16 : conv == 'o' ? 8 : 10;
        if (!is_signed && conv != 'u' && conv != 'x' && conv != 'X' && conv != 'o') return -2;
        uint64_t v; bool neg = false;
        if (len == L_64 || (len == L_PTR && sizeof(void *) == 8)) {
            const uint64_t raw = va_arg(ap, uint64_t);
            if (is_signed && (int64_t)raw < 0) { neg = true; v = 0 - raw; } else v = raw;
        } else {
            const uint32_t raw = va_arg(ap, uint32_t);       // int-sized (also every promoted short/char)
            int32_t sv; uint32_t uv;
            if (len == L_CHAR) { sv = (signed char)raw; uv = (unsigned char)raw; }
            else if (len == L_SHORT) { sv = (short)raw; uv = (unsigned short)raw; }
            else { sv = (int32_t)raw; uv = raw; }
            if (is_signed && sv < 0) { neg = true; v = 0 - (uint64_t)(int64_t)sv; }
            else v = is_signed ? (uint64_t)sv : uv;
        }
        char digits[24]; int k = 0;
        const char *set = conv == 'X' ? "0123456789ABCDEF" : "0123456789abcdef";
        if (base == 10) {
            while (v >> 32) { digits[k++] = (char)('0' + v % 10); v /= 10; }
            for (uint32_t w = (uint32_t)v; ; ) { digits[k++] = (char)('0' + w % 10); w /= 10; if (!w) break; }
        } else {
            const unsigned shift = base == 16 ? 4 : 3;
            do { digits[k++] = set[v & (base - 1)]; v >>= shift; } while (v);
        }
        if (neg) put('-');
        while (k) put(digits[--k]);
    }
    if (n > 0x7ffffffe) return -2;
    buf[n < cap ? n : cap - 1] = 0;
    return (int)n;
}

inline int uhh_vformat_guarded(char *buf, size_t cap, const char *format, va_list ap) {
    {
        int n = -1;
        __try {
            va_list aq;
            va_copy(aq, ap);
            n = uhh_format_fast(buf, cap, format, aq);
            va_end(aq);
        } __except (EXCEPTION_EXECUTE_HANDLER) { n = -1; }
        if (n != -2) return n;
    }
    _invalid_parameter_handler prev = _set_thread_local_invalid_parameter_handler(uhh_ignore_invalid_parameter);
    int n = -1;
    __try { n = vsnprintf(buf, cap, format, ap); }
    __except (EXCEPTION_EXECUTE_HANDLER) { n = -1; }
    _set_thread_local_invalid_parameter_handler(prev);
    return n;
}

// Copies the raw format after the tag; returns the length, or cap (the format did not fit).
inline size_t uhh_copy_format_guarded(char *buf, size_t cap, size_t used, const char *format) {
    bool cut = false;
    __try {
        for (; format && *format; ++format) {
            if (used + 1 >= cap) { cut = true; break; }
            buf[used++] = *format;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
    buf[used] = 0;
    return cut ? cap : used;
}

// Returns the length of the text in buf (it may contain NULs a %c wrote: the length, not
// strlen, is the text), or -1 only when there is nothing to log (null format).
inline int uhh_format_log(char *buf, size_t cap, const char *format, va_list ap) {
    static const char tag[] = "[unformattable] ", mark[] = "...[truncated]";
    if (!format || cap < sizeof(tag) + sizeof(mark) + 1 || cap > 0x7fffffff) return -1;
    buf[0] = 0;
    int n = uhh_vformat_guarded(buf, cap, format, ap);
    size_t len;
    if (n < 0) {
        memcpy(buf, tag, sizeof(tag));
        len = uhh_copy_format_guarded(buf, cap, sizeof(tag) - 1, format);
    } else {
        len = (size_t)n;
    }
    if (len >= cap) {                                                  // never silently
        memcpy(buf + cap - sizeof(mark), mark, sizeof(mark));
        len = cap - 1;
    }
    buf[len] = 0;
    return (int)len;
}
