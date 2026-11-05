// Library-private: format one send_log / send_log_stack line. Shared by the controller
// (breakpoint/hw callbacks) and the inline agent (inside the target) so that every
// backend produces the SAME text for the same call, including the bad cases:
//   - fits:            the formatted text
//   - too long:        truncated to cap-1, ending in "...[truncated]"
//   - invalid format (an unknown conversion such as %k, %n, a lone trailing %) or an
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

inline void uhh_copy_format_guarded(char *buf, size_t cap, size_t used, const char *format) {
    __try { for (; used + 1 < cap && format && *format; ++format) buf[used++] = *format; }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
    buf[used] = 0;
}

// Returns false only when there is nothing to log (null format).
inline bool uhh_format_log(char *buf, size_t cap, const char *format, va_list ap) {
    static const char tag[] = "[unformattable] ", mark[] = "...[truncated]";
    if (!format || cap < sizeof(mark) + 1) return false;
    buf[0] = 0;
    int n = uhh_vformat_guarded(buf, cap, format, ap);
    if (n < 0) {
        memcpy(buf, tag, sizeof(tag));
        uhh_copy_format_guarded(buf, cap, sizeof(tag) - 1, format);
        return true;
    }
    buf[cap - 1] = 0;
    if ((size_t)n >= cap) memcpy(buf + cap - sizeof(mark), mark, sizeof(mark));   // never silently
    return true;
}
