#include "probe_api.h"

#if defined(_WIN32)
#define BREAKAGE_EXPORT __declspec(dllexport)
#else
#define BREAKAGE_EXPORT
#endif

extern "C" BREAKAGE_EXPORT void breakage_hit_a(probe_context *c) { PROBE_LOG(c, "breakage-a"); }
extern "C" BREAKAGE_EXPORT void breakage_hit_b(probe_context *c) { PROBE_LOG(c, "breakage-b"); }

#ifndef BREAKAGE_AGENT_ONLY
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cerrno>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

enum SiteId { SHORT_SITE, PREHOOK_SITE, UNRELOC_SITE, STACK_SITE, STACK_INSIDE_SITE, SITE_COUNT };

struct Registration { SiteId site; probe_callback callback; };
// Every row has ONE required outcome. PASS: every probe installed, each hit exactly once,
// and the target returned exactly what it returns uninstrumented (exit 0). REFUSED: UHH
// refused the probe with a reason (error text), nothing was hit, and the target was not
// corrupted (it never ran its case, or ran it unaffected). Anything else is BROKEN.
enum Required { PASS, REFUSED };
struct Case {
    const char *name, *site, *target_case, *backend, *expected;
    uint32_t flags;
    Required required;
    std::vector<Registration> registrations;
};
struct RunResult {
    bool install_ok = false, target_ok = false; uint64_t hits = 0; int prehook_reports = 0;
    unsigned long app_exit = 0; std::string error;
};

static bool parse_rva(const char *text, const char *name, uint64_t &value) {
    if (!text || !*text) {
        std::fprintf(stderr, "breakage_driver: invalid %s RVA: %s\n", name, text ? text : "(null)");
        return false;
    }
    errno = 0; char *end = nullptr; unsigned long long parsed = std::strtoull(text, &end, 0);
    if (*text == '-' || errno == ERANGE || !end || *end) {
        std::fprintf(stderr, "breakage_driver: invalid %s RVA: %s\n", name, text ? text : "(null)");
        return false;
    }
    value = (uint64_t)parsed; return true;
}

static RunResult run_case(const char *target, const Case &c, const uint64_t rvas[SITE_COUNT]) {
    RunResult result;
    probe_session *session = probe_session_create();
    if (!session) return result;
    bool added = true;
    for (const auto &registration : c.registrations) {
        char location[96];
        std::snprintf(location, sizeof(location), "hook_edge.exe+0x%llx",
                      (unsigned long long)rvas[registration.site]);
        if (!probe_add_symbol_cfg(session, location, registration.callback, c.flags, nullptr, 0)) added = false;
    }
    char case_arg[32]; std::snprintf(case_arg, sizeof(case_arg), "%s", c.target_case);
    char option[] = "--case";
    std::vector<char *> child{const_cast<char *>(target), option, case_arg, nullptr};
    bool launched = added && probe_launch(session, child.data());
    bool ran = launched && probe_run(session);
    result.target_ok = ran && probe_wait_for_exit(session);

    FILE *report = std::tmpfile();
    size_t active = 0, probes = 0;
    if (report) {
        probe_report(session, report); std::rewind(report);
        char line[16384];
        while (std::fgets(line, sizeof(line), report)) {
            if (std::strstr(line, "\"kind\":\"prehook\"")) { ++result.prehook_reports; continue; }
            if (std::strstr(line, "\"kind\":\"probe_report\"")) {
                if (const char *e = std::strstr(line, "\"app_exit\":")) result.app_exit = std::strtoul(e + 11, nullptr, 10);
                if (const char *e = std::strstr(line, "\"error\":\"")) {
                    result.error = e + 9;
                    result.error.resize(result.error.rfind('"'));
                }
                continue;
            }
            if (!std::strstr(line, "\"kind\":\"probe\"")) continue;
            ++probes;
            if (std::strstr(line, "\"active\":true")) ++active;
            const char *hits = std::strstr(line, "\"hits\":");
            if (hits) result.hits += std::strtoull(hits + 7, nullptr, 10);
        }
        std::fclose(report);
    }
    result.install_ok = added && launched && probes == c.registrations.size() && active == probes;
    probe_close(session);
    return result;
}

static void json_string(const char *text) {
    std::putchar('"');
    for (const unsigned char *p = (const unsigned char *)text; *p; ++p) {
        if (*p == '"' || *p == '\\') { std::putchar('\\'); std::putchar(*p); }
        else if (*p == '\n') std::fputs("\\n", stdout);
        else if (*p >= 0x20) std::putchar(*p);
    }
    std::putchar('"');
}

static const char *verdict(const Case &c, const RunResult &r) {
    if (r.install_ok && r.target_ok && r.hits == c.registrations.size()) return "pass";
    // Refused: a reason, no hit, and no sign of corruption -- hook_edge's own wrong-result
    // exits are 4..7 and a fault is an NTSTATUS (>= 0x80000000); a refused launch never
    // releases the target's gate, so it is ended before it runs its case.
    const bool corrupted = (r.app_exit >= 4 && r.app_exit <= 7) || r.app_exit >= 0x80000000ul;
    if (!r.install_ok && r.hits == 0 && !r.error.empty() && !corrupted) return "refused";
    return "broken";
}

static bool print_result(const Case &c, const RunResult &r) {
    std::fputs("{\"site\":", stdout); json_string(c.site);
    std::fputs(",\"backend\":", stdout); json_string(c.backend);
    std::fprintf(stdout, ",\"install_ok\":%s,\"hits\":%llu,\"prehook_reports\":%d,\"expected\":",
                 r.install_ok ? "true" : "false", (unsigned long long)r.hits, r.prehook_reports);
    json_string(c.expected);
    std::fprintf(stdout, ",\"app_exit\":%lu,\"error\":", r.app_exit); json_string(r.error.c_str());
    std::fputs(",\"required\":", stdout); json_string(c.required == PASS ? "pass" : "refused");
    std::fputs(",\"verdict\":", stdout); json_string(verdict(c, r));
    std::fputs("}\n", stdout); std::fflush(stdout);
    return !std::strcmp(verdict(c, r), c.required == PASS ? "pass" : "refused");
}

int main(int argc, char **argv) {
    static const char *names[SITE_COUNT] = {
        "ShortSite", "PrehookSite", "UnrelocSite", "StackSite", "StackInsideSite"
    };
    if (argc != SITE_COUNT + 2) {
        std::fprintf(stderr, "usage: breakage_driver <hook_edge.exe> <short> <prehook> <unreloc> <stack> <stack_inside>\n"
                             "       (site RVAs from hook_edge.map, e.g. via scripts/site_rvas.py)\n");
        return 2;
    }
    const char *target = argv[1];
    uint64_t rvas[SITE_COUNT]{};
    for (int i = 0; i < SITE_COUNT; ++i)
        if (!parse_rva(argv[i + 2], names[i], rvas[i])) return 2;

    const char *control = "one install, one hit, correct target exit";
    std::vector<Case> cases = {
        {"short_inline", "ShortSite", "short", "inline",
         "refused: the 5-byte patch would run past the ret", PROBE_INLINE, REFUSED,
         {{SHORT_SITE, breakage_hit_a}}},
        {"prehook_inline", "PrehookSite", "prehook", "inline",
         "one hit, then relocated foreign E9 -> replacement -> foreign trampoline (opted in)",
         PROBE_INLINE | PROBE_ALLOW_PREHOOKED, PASS,
         {{PREHOOK_SITE, breakage_hit_a}}},
        {"prehook_inline_default", "PrehookSite", "prehook", "inline-default",
         "the E9 is in the image file too (live == disk: not a pre-hook): relocated and chained, one hit, 1017",
         PROBE_INLINE, PASS,
         {{PREHOOK_SITE, breakage_hit_a}}},
        {"prehook_inline_fallback", "PrehookSite", "prehook", "inline-fallback",
         "pre-hook detected -> moved to a debug register; one hit, clean exit", PROBE_INLINE | PROBE_FALLBACK_HW, PASS,
         {{PREHOOK_SITE, breakage_hit_a}}},
        {"unreloc_inline", "UnrelocSite", "unreloc", "inline",
         "refused: jrcxz/jecxz (rel8-only) cannot be relocated", PROBE_INLINE, REFUSED,
         {{UNRELOC_SITE, breakage_hit_a}}},
        {"stack_same_inline", "StackSite+StackSite", "stack", "inline",
         "second inline hook at the same address refused (overlapping patch)", PROBE_INLINE, REFUSED,
         {{STACK_SITE, breakage_hit_a}, {STACK_SITE, breakage_hit_b}}},
        {"stack_overlap_inline", "StackSite+StackInsideSite", "stack", "inline",
         "inner probe refused: its address lies in the outer hook's patch", PROBE_INLINE, REFUSED,
         {{STACK_SITE, breakage_hit_a}, {STACK_INSIDE_SITE, breakage_hit_b}}}
    };
    for (int backend = 0; backend < 2; ++backend) {
        uint32_t flag = backend ? PROBE_HW : PROBE_BREAKPOINT;
        const char *label = backend ? "hw" : "breakpoint";
        cases.push_back({"control_short", "ShortSite", "short", label, control, flag, PASS,
                         {{SHORT_SITE, breakage_hit_a}}});
        cases.push_back({"control_prehook", "PrehookSite", "prehook", label, control, flag, PASS,
                         {{PREHOOK_SITE, breakage_hit_a}}});
        cases.push_back({"control_unreloc", "UnrelocSite", "unreloc", label, control, flag, PASS,
                         {{UNRELOC_SITE, breakage_hit_a}}});
        cases.push_back({"control_stack_outer", "StackSite", "stack", label, control, flag, PASS,
                         {{STACK_SITE, breakage_hit_a}}});
        cases.push_back({"control_stack_inner", "StackInsideSite", "stack", label, control, flag, PASS,
                         {{STACK_INSIDE_SITE, breakage_hit_a}}});
    }
    int wrong = 0;
    for (const auto &c : cases) wrong += !print_result(c, run_case(target, c, rvas));
    return wrong ? 1 : 0;   /* any row off its required outcome fails the driver */
}
#endif
