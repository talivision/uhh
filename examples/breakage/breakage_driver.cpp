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
enum Expected { MUST_PASS, MUST_BREAK, MAY_RELOCATE, PREHOOK_CHAIN, STACK_SAME, STACK_OVERLAP };
struct Case {
    const char *name, *site, *target_case, *backend, *expected;
    uint32_t flags;
    Expected outcome;
    std::vector<Registration> registrations;
};
struct RunResult { bool install_ok = false, target_ok = false; uint64_t hits = 0; int prehook_reports = 0; };

static std::string sibling_target() {
    char path[MAX_PATH]; DWORD n = GetModuleFileNameA(nullptr, path, MAX_PATH);
    if (!n || n >= MAX_PATH) return "hook_edge.exe";
    std::string result(path); size_t slash = result.find_last_of("\\/");
    return result.substr(0, slash == std::string::npos ? 0 : slash + 1) + "hook_edge.exe";
}

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

static RunResult run_case(const Case &c, const uint64_t rvas[SITE_COUNT]) {
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
    std::string target = sibling_target();
    char case_arg[32]; std::snprintf(case_arg, sizeof(case_arg), "%s", c.target_case);
    char option[] = "--case";
    std::vector<char *> child{target.data(), option, case_arg, nullptr};
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
    size_t wanted = c.registrations.size();
    bool clean = r.install_ok && r.target_ok && r.hits == wanted;
    switch (c.outcome) {
    case MUST_PASS: return clean ? "pass" : "unexpected_failure";
    case MUST_BREAK: return clean ? "unexpected_inline_success" : "expected_breakage";
    case MAY_RELOCATE: return clean ? "relocated_safely" : "expected_relocation_breakage";
    case PREHOOK_CHAIN: return clean ? "foreign_then_uhh_chain_ok" : "prehook_chain_broken";
    case STACK_SAME: return clean ? "unexpected_clean_stack" : "expected_stack_breakage";
    case STACK_OVERLAP:
        return r.install_ok && r.target_ok && r.hits == 2 ? "unexpected_clean_overlap" : "expected_overlap_breakage";
    }
    return "unknown";
}

static void print_result(const Case &c, const RunResult &r) {
    std::fputs("{\"site\":", stdout); json_string(c.site);
    std::fputs(",\"backend\":", stdout); json_string(c.backend);
    std::fprintf(stdout, ",\"install_ok\":%s,\"hits\":%llu,\"prehook_reports\":%d,\"expected\":",
                 r.install_ok ? "true" : "false", (unsigned long long)r.hits, r.prehook_reports);
    json_string(c.expected); std::fputs(",\"verdict\":", stdout); json_string(verdict(c, r));
    std::fputs("}\n", stdout); std::fflush(stdout);
}

int main(int argc, char **argv) {
    static const char *names[SITE_COUNT] = {
        "ShortSite", "PrehookSite", "UnrelocSite", "StackSite", "StackInsideSite"
    };
    static const char *envs[SITE_COUNT] = {
        "UHH_SHORT_RVA", "UHH_PREHOOK_RVA", "UHH_UNRELOC_RVA", "UHH_STACK_RVA", "UHH_STACK_INSIDE_RVA"
    };
    uint64_t rvas[SITE_COUNT]{};
    bool any_env = false, all_env = true;
    for (int i = 0; i < SITE_COUNT; ++i) {
        const char *value = std::getenv(envs[i]); any_env = any_env || (value && *value);
        all_env = all_env && value && *value;
    }
    if (any_env && !all_env) {
        std::fprintf(stderr, "breakage_driver: set all five UHH_*_RVA variables or none\n"); return 2;
    }
    if (!all_env && argc != SITE_COUNT + 1) {
        std::fprintf(stderr, "usage: breakage_driver <short> <prehook> <unreloc> <stack> <stack_inside>\n");
        return 2;
    }
    for (int i = 0; i < SITE_COUNT; ++i) {
        const char *value = all_env ? std::getenv(envs[i]) : argv[i + 1];
        if (!parse_rva(value, names[i], rvas[i])) return 2;
    }

    const char *control = "one install, one hit, correct target exit";
    std::vector<Case> cases = {
        {"short_inline", "ShortSite", "short", "inline",
         "inline install rejection/no hit at the two-byte region", PROBE_INLINE, MUST_BREAK,
         {{SHORT_SITE, breakage_hit_a}}},
        {"prehook_inline", "PrehookSite", "prehook", "inline",
         "one hit, then relocated foreign E9 -> replacement -> foreign trampoline (opted in)",
         PROBE_INLINE | PROBE_ALLOW_PREHOOKED, PREHOOK_CHAIN,
         {{PREHOOK_SITE, breakage_hit_a}}},
        {"prehook_inline_default", "PrehookSite", "prehook", "inline-default",
         "refused with a pre-hook report (live vs disk bytes, disassembly, suggestions)", PROBE_INLINE, MUST_BREAK,
         {{PREHOOK_SITE, breakage_hit_a}}},
        {"prehook_inline_fallback", "PrehookSite", "prehook", "inline-fallback",
         "pre-hook detected -> moved to a debug register; one hit, clean exit", PROBE_INLINE | PROBE_FALLBACK_HW, MUST_PASS,
         {{PREHOOK_SITE, breakage_hit_a}}},
        {"unreloc_inline", "UnrelocSite", "unreloc", "inline",
         "naive rel8 copy misbranches; aware relocation may preserve one hit and exit", PROBE_INLINE, MAY_RELOCATE,
         {{UNRELOC_SITE, breakage_hit_a}}},
        {"stack_same_inline", "StackSite+StackSite", "stack", "inline",
         "unsupported double install: reject or fewer than two hits", PROBE_INLINE, STACK_SAME,
         {{STACK_SITE, breakage_hit_a}, {STACK_SITE, breakage_hit_b}}},
        {"stack_overlap_inline", "StackSite+StackInsideSite", "stack", "inline",
         "inner install/hit fails because its address lies in outer stolen bytes", PROBE_INLINE, STACK_OVERLAP,
         {{STACK_SITE, breakage_hit_a}, {STACK_INSIDE_SITE, breakage_hit_b}}}
    };
    for (int backend = 0; backend < 2; ++backend) {
        uint32_t flag = backend ? PROBE_HW : PROBE_BREAKPOINT;
        const char *label = backend ? "hw" : "breakpoint";
        cases.push_back({"control_short", "ShortSite", "short", label, control, flag, MUST_PASS,
                         {{SHORT_SITE, breakage_hit_a}}});
        cases.push_back({"control_prehook", "PrehookSite", "prehook", label, control, flag, MUST_PASS,
                         {{PREHOOK_SITE, breakage_hit_a}}});
        cases.push_back({"control_unreloc", "UnrelocSite", "unreloc", label, control, flag, MUST_PASS,
                         {{UNRELOC_SITE, breakage_hit_a}}});
        cases.push_back({"control_stack_outer", "StackSite", "stack", label, control, flag, MUST_PASS,
                         {{STACK_SITE, breakage_hit_a}}});
        cases.push_back({"control_stack_inner", "StackInsideSite", "stack", label, control, flag, MUST_PASS,
                         {{STACK_INSIDE_SITE, breakage_hit_a}}});
    }
    for (const auto &c : cases) print_result(c, run_case(c, rvas));
    return 0; /* Rows carry the expected failures; setup/usage errors return nonzero. */
}
#endif
