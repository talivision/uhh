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

inline int uhh_vformat_guarded(char *buf, size_t cap, const char *format, va_list ap) {
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
