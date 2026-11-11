// Callbacks for logs_target (regress `logs-*`): the same source runs in the controller
// (breakpoint/hw) and inside the target (inline, built into probe_api_agent).
// The tag (first argument) selects what is logged; the seq (second) is echoed.
#include "probe_api.h"
#include <stdint.h>
#include <string.h>
#include <wchar.h>

static const char *repeat_x(size_t n) {            // n 'x' characters (n < 2048)
    static char buf[2048];
    static bool ready = false;
    if (!ready) { memset(buf, 'x', sizeof(buf) - 1); buf[sizeof(buf) - 1] = 0; ready = true; }
    return buf + (sizeof(buf) - 1 - n);
}

extern "C" __declspec(dllexport) void logs_eval_cb(probe_context *c) {
    unsigned tag = (unsigned)get_func_arg(c, 0), seq = (unsigned)get_func_arg(c, 1);
    switch (tag) {
    case 0xA: send_log(c, "o %u", seq); return;
    case 0xB: send_log_stack(c, "o %u", seq); return;
    case 0xF: send_log(c, "UHH_TEST_DELAY o %u", seq); return;   // delayed ring publication
    case 0xE: send_log(c, "UHH_TEST_WEDGE o %u", seq); return;   // logs-wedge: the agent's test stop (agent.cpp)
    default: break;
    }
    switch (tag - 0x100) {   // format cases: see check_logs_format in scripts/regress.py
    case 0: send_log(c, "%s", repeat_x(1023)); return;                       // exactly the cap: whole
    case 1: send_log(c, "%s", repeat_x(1024)); return;                       // one over: marked
    case 2: { int n = 0; send_log(c, "k2 %n", &n); return; }                 // %n: refused
    case 3: send_log(c, "k3 %k"); return;                                    // unknown conversion
    case 4: send_log(c, "k4 %5000d", 7); return;                             // huge width
    case 5: send_log(c, "k5 a%cb", 0); return;                               // embedded NUL
    case 6: send_log(c, "k6 t\tr\rx\x01" "e\x1b" "f\x7f"); return;          // control characters
    case 7: send_log(c, "k7 \xc3\xa9\xe2\x86\x92\xf0\x9f\x98\x80"); return;  // valid UTF-8: e-acute, arrow, emoji
    case 8: send_log(c, "k8 \xff\xfe ok \xc3"); return;                     // invalid UTF-8
    case 9: send_log(c, "k9 %s", (const char *)nullptr); return;             // null %s
    case 10: {                                                               // long AND invalid FORMAT
        static char fmt[1200];
        if (!fmt[0]) { memset(fmt, 'y', 1100); memcpy(fmt + 1100, " %n", 4); }
        int n = 0; send_log(c, fmt, &n); return;
    }
    case 11: send_log(c, "k11 \"quoted\" back\\slash /"); return;            // JSON specials
    case 12: send_log(c, ""); return;                                        // empty
    case 13: send_log_stack(c, "k13 %s", repeat_x(1100)); return;            // truncated + stack
    case 14: send_log(c, "k14 %ls", L"wé"); return;                     // wide non-ASCII
    case 15: send_log(c, "k15 %.3s|%-4d|%+.2f|%#x|%%", "abcdef", 5, 2.5, 255); return;
    default: send_log(c, "unknown tag %u", tag); return;
    }
}
