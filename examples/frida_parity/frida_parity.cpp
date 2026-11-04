#include "probe_api.h"
#include <cstdint>
#include <cstring>

#ifdef _WIN32
#define PARITY_EXPORT __declspec(dllexport)
#else
#define PARITY_EXPORT
#endif

struct parity_string_config { uint32_t max_bytes; };

static void append_u64(char *out, size_t cap, size_t &at, uint64_t value) {
    char reversed[24]; size_t n = 0;
    do { reversed[n++] = (char)('0' + value % 10); value /= 10; } while (value && n < sizeof(reversed));
    while (n && at + 1 < cap) out[at++] = reversed[--n];
    out[at] = 0;
}

static void log_string(probe_context *c, const char *tag, uint64_t address, uint64_t requested) {
    char line[96]; size_t at = 0;
    while (*tag && at + 1 < sizeof(line)) line[at++] = *tag++;
    size_t room = sizeof(line) - at - 1;
    size_t n = requested < room ? (size_t)requested : room;
    if (!n || !get_mem(c, address, line + at, n)) {
        const char failed[] = "<read-failed>";
        n = sizeof(failed) - 1 < room ? sizeof(failed) - 1 : room;
        std::memcpy(line + at, failed, n);
    }
    line[at + n] = 0;
    PROBE_LOG(c, line);       // Current inline logging records this completed text.
}

extern "C" PARITY_EXPORT void parity_b1_log_argument(probe_context *c) {
    /* Frida: Interceptor.attach(..., { onEnter(args) { send(args[0]); } }). */
    char line[48] = "B1:"; size_t at = 3;
    append_u64(line, sizeof(line), at, get_func_arg(c, 0));
    PROBE_LOG(c, line);
}

extern "C" PARITY_EXPORT void parity_b2_read_string(probe_context *c) {
    /* Frida: args[1].readUtf8String(). UHH explicitly reads target memory. */
    const auto *cfg = static_cast<const parity_string_config *>(get_config(c));
    uint64_t n = get_func_arg(c, 2);
    if (cfg && n > cfg->max_bytes) n = cfg->max_bytes;
    log_string(c, "B2:", get_func_arg(c, 1), n);
}

extern "C" PARITY_EXPORT void parity_b4_modify_argument(probe_context *c) {
    /* Frida: onEnter(args) { args[1] = ptr(...); }. The fixture puts the desired
       target pointer in arg0, avoiding any target-allocation feature. */
    uint64_t replacement = get_func_arg(c, 0);
#if defined(_WIN64)
    int changed = set_reg(c, PROBE_REG_DX, replacement); // x64 arg1 is RDX
#else
    uint32_t value = (uint32_t)replacement;
    int changed = set_mem(c, get_reg(c, PROBE_REG_SP) + 8, &value, sizeof(value));
#endif
    if (changed) log_string(c, "B4:", replacement, get_func_arg(c, 2));
    else PROBE_LOG(c, "B4:<write-failed>");
}

extern "C" PARITY_EXPORT void parity_b6_modify_register(probe_context *c) {
    /* Frida: read/assign this.context.rax at an arbitrary instruction. AX is UHH's
       documented 32-bit EAX view, which is the same contract on x64 and x86. */
    uint64_t before = get_reg(c, PROBE_REG_AX);
    int changed = set_reg(c, PROBE_REG_AX, 42);
    char line[48] = "B6:"; size_t at = 3;
    append_u64(line, sizeof(line), at, before);
    if (at + 2 < sizeof(line)) { line[at++] = '-'; line[at++] = '>'; line[at] = 0; }
    if (changed) append_u64(line, sizeof(line), at, get_reg(c, PROBE_REG_AX));
    else std::strcpy(line, "B6:<write-failed>");
    PROBE_LOG(c, line);
}

#ifndef FRIDA_PARITY_AGENT_ONLY
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

enum Demo { B1, B2, B4, B6, DEMO_COUNT };

struct Results {
    std::string seen[DEMO_COUNT];
    uint64_t hits[DEMO_COUNT]{};
    bool active[DEMO_COUNT]{};
    unsigned long app_exit = ~0ul;
    bool report_ok = false;
};

static bool parse_rva(const char *text, const char *name, uint64_t &value) {
    if (!text || !*text) {
        std::fprintf(stderr, "frida_parity: missing %s RVA\n", name); return false;
    }
    errno = 0; char *end = nullptr; unsigned long long parsed = std::strtoull(text, &end, 0);
    if (*text == '-' || errno == ERANGE || !end || *end) {
        std::fprintf(stderr, "frida_parity: invalid %s RVA: %s\n", name, text); return false;
    }
    value = (uint64_t)parsed; return true;
}

static Demo demo_from_message(const char *message) {
    if (!std::strncmp(message, "B1:", 3)) return B1;
    if (!std::strncmp(message, "B2:", 3)) return B2;
    if (!std::strncmp(message, "B4:", 3)) return B4;
    return B6;
}

static Results read_report(FILE *report) {
    Results out; std::rewind(report); char line[2048]; size_t probe_index = 0;
    while (std::fgets(line, sizeof(line), report)) {
        if (std::strstr(line, "\"kind\":\"probe_log\"")) {
            const char marker[] = "\"message\":\"";
            char *begin = std::strstr(line, marker);
            if (!begin) continue;
            begin += sizeof(marker) - 1; char *end = std::strchr(begin, '"');
            if (!end || std::strncmp(begin, "B", 1)) continue;
            *end = 0; Demo demo = demo_from_message(begin);
            if (std::strlen(begin) >= 3) out.seen[demo] = begin + 3;
        } else if (std::strstr(line, "\"kind\":\"probe\"")) {
            if (probe_index >= DEMO_COUNT) continue;
            char *hits = std::strstr(line, "\"hits\":");
            out.hits[probe_index] = hits ? std::strtoull(hits + 7, nullptr, 10) : 0;
            out.active[probe_index] = std::strstr(line, "\"active\":true") != nullptr;
            ++probe_index;
        } else if (std::strstr(line, "\"kind\":\"probe_report\"")) {
            char *exit = std::strstr(line, "\"app_exit\":");
            if (exit) out.app_exit = std::strtoul(exit + 11, nullptr, 10);
            out.report_ok = std::strstr(line, "\"error\":null") != nullptr;
        }
    }
    out.report_ok = out.report_ok && probe_index == DEMO_COUNT;
    return out;
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

static bool print_demo(Demo demo, const Results &r, bool ran) {
    static const char *names[] = {"B1_log_argument", "B2_read_string", "B4_modify_argument", "B6_register_rw"};
    static const char *frida[] = {"Interceptor.attach/onEnter args[0]", "args[1].readUtf8String()",
                                  "onEnter: args[1] = ptr(...)", "this.context.rax read/write"};
    static const char *expected[] = {"4660", "hello-from-target", "instrumented", "7->42"};
    bool target_ok = r.app_exit <= 0xful && !(r.app_exit & (1ul << demo));
    bool pass = ran && r.report_ok && r.active[demo] && r.hits[demo] == 1 &&
                r.seen[demo] == expected[demo] && target_ok;
    std::fputs("{\"name\":", stdout); json_string(names[demo]);
    std::fputs(",\"frida_equivalent\":", stdout); json_string(frida[demo]);
    std::fputs(",\"arg_seen\":", stdout);
    if (r.seen[demo].empty()) std::fputs("null", stdout); else json_string(r.seen[demo].c_str());
    std::fputs(",\"verdict\":", stdout); json_string(pass ? "pass" : "fail");
    std::fputs("}\n", stdout);
    return pass;
}

int main(int argc, char **argv) {
    static const char *site_names[] = {"ParityB1Site", "ParityB2Site", "ParityB4Site", "ParityB6Site"};
    if (argc != DEMO_COUNT + 2) {
        std::fprintf(stderr, "usage: frida_parity <parity_target.exe> <b1_rva> <b2_rva> <b4_rva> <b6_rva>\n");
        return 2;
    }
    uint64_t rvas[DEMO_COUNT]{};
    for (int i = 0; i < DEMO_COUNT; ++i)
        if (!parse_rva(argv[i + 2], site_names[i], rvas[i])) return 2;

    probe_session *session = probe_session_create();
    if (!session) {
        Results empty;
        for (int i = 0; i < DEMO_COUNT; ++i) print_demo((Demo)i, empty, false);
        return 1;
    }
    char locations[DEMO_COUNT][96];
    for (int i = 0; i < DEMO_COUNT; ++i)
        std::snprintf(locations[i], sizeof(locations[i]), "parity_target.exe+0x%llx",
                      (unsigned long long)rvas[i]);

    parity_string_config string_cfg{64};
    bool added = true;
    added &= !!probe_add_symbol(session, locations[B1], parity_b1_log_argument, PROBE_INLINE);
    added &= !!probe_add_symbol_cfg(session, locations[B2], parity_b2_read_string, PROBE_INLINE,
                             &string_cfg, sizeof(string_cfg));
    added &= !!probe_add_symbol(session, locations[B4], parity_b4_modify_argument, PROBE_INLINE);
    added &= !!probe_add_symbol(session, locations[B6], parity_b6_modify_register, PROBE_HW);

    char *child[] = {argv[1], nullptr};
    bool launched = added && probe_launch(session, child);
    bool ran = launched && probe_run(session);
    if (ran) (void)probe_wait_for_exit(session); // Nonzero target bits are decoded below.

    Results results; FILE *report = std::tmpfile();
    if (report) {
        probe_report(session, report); results = read_report(report); std::fclose(report);
    }
    probe_close(session);

    bool pass = true;
    for (int i = 0; i < DEMO_COUNT; ++i) pass &= print_demo((Demo)i, results, ran);
    return pass ? 0 : 1;
}
#endif
