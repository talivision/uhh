// log_format_selftest: the send_log fast formatter (include/probe_log_format.hpp,
// uhh_format_fast) against the CRT's vsnprintf, which it must match byte for byte on every
// format it accepts. Every format below is formatted with a grid of argument values by both;
// a format the fast path declines (-2) is fine (send_log then uses vsnprintf itself). Prints one
// JSON line: {"kind":"log_format_selftest","cases":N,"fast":F,"declined":D,"mismatch":M,...}.
// Regress: logs-format-fast. Also checks the formats the fast path exists for are taken by it.
#include "probe_log_format.hpp"
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

static int g_cases = 0, g_fast = 0, g_declined = 0, g_mismatch = 0, g_unexpected_decline = 0;
static std::string g_first;

static int fast_v(char *buf, size_t cap, const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    int n = uhh_format_fast(buf, cap, fmt, ap);
    va_end(ap);
    return n;
}
static int crt_v(char *buf, size_t cap, const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    int n = vsnprintf(buf, cap, fmt, ap);
    va_end(ap);
    return n;
}

static void note(const char *fmt, const char *why, const char *a, int na, const char *b, int nb) {
    ++g_mismatch;
    if (g_first.empty()) {
        char line[512];
        std::snprintf(line, sizeof(line), "fmt=[%s] %s fast(%d)=[%.60s] crt(%d)=[%.60s]", fmt, why, na, a, nb, b);
        for (char *p = line; *p; ++p) if (*p == '"' || *p == '\\' || (unsigned char)*p < 0x20) *p = '?';
        g_first = line;
    }
}

// Formats both ways at several buffer sizes (truncation included) and compares length + bytes.
template <class... A>
static void check(bool must_take, const char *fmt, A... args) {
    for (size_t cap : {size_t(256), size_t(7), size_t(1)}) {
        ++g_cases;
        char a[256], b[256];
        std::memset(a, 0x5A, sizeof(a)); std::memset(b, 0x5A, sizeof(b));
        int na = fast_v(a, cap, fmt, args...);
        if (na == -2) {
            ++g_declined;
            if (must_take) ++g_unexpected_decline;
            continue;
        }
        ++g_fast;
        int nb = crt_v(b, cap, fmt, args...);
        if (na != nb) { note(fmt, "length", a, na, b, nb); continue; }
        size_t used = nb < 0 ? 0 : ((size_t)nb < cap ? (size_t)nb + 1 : cap);    // text + NUL as written
        if (std::memcmp(a, b, used)) note(fmt, "bytes", a, na, b, nb);
    }
}

int main() {
    const long long ll[] = {0, 1, -1, 9, 10, 99, 4294967295LL, 4294967296LL, -4294967296LL,
                            9223372036854775807LL, (-9223372036854775807LL - 1), 0x123456789abcdefLL, -1234567};
    const int ii[] = {0, 1, -1, 7, 10, 255, 256, 32767, -32768, 65535, 65536, 2147483647, (-2147483647 - 1), -200, 128};
    for (long long v : ll) {
        check(true, "%lld", v); check(true, "%llu", (unsigned long long)v); check(true, "%llx", v);
        check(true, "%llX", v); check(true, "%llo", v); check(true, "%I64d", v); check(true, "%I64u", v);
        check(true, "%I64x", v); check(true, "%jd", (intmax_t)v); check(true, "%ju", (uintmax_t)v);
        check(true, "%zu", (size_t)v); check(true, "%zd", (ptrdiff_t)v); check(true, "%zx", (size_t)v);
        check(true, "%td", (ptrdiff_t)v); check(true, "%Iu", (size_t)v); check(true, "%Ix", (size_t)v);
        check(true, "%p", (void *)(uintptr_t)v);
        check(true, "read handle=0x%llx pid=%llu name=%s addr=0x%llx size=%llu", v, (unsigned long long)v,
              "probe_app.exe", v, (unsigned long long)v);
        check(true, "hit %llu", (unsigned long long)v);
    }
    for (int v : ii) {
        check(true, "%d", v); check(true, "%i", v); check(true, "%u", (unsigned)v); check(true, "%x", v);
        check(true, "%X", v); check(true, "%o", v); check(true, "%ld", (long)v); check(true, "%lu", (unsigned long)v);
        check(true, "%lx", (unsigned long)v); check(true, "%hd", v); check(true, "%hu", v); check(true, "%hx", v);
        check(true, "%hhd", v); check(true, "%hhu", v); check(true, "%hhx", v); check(true, "%I32d", v);
        check(true, "%I32x", v); check(true, "%c", v); check(true, "[%c|%c]", v, 'q');
        check(true, "a%%b %d %% %u%%", v, (unsigned)v);
    }
    const char *strs[] = {"", "x", "probe_app.exe", "with \"quotes\" and \\ and \t tab", "\xc3\xa9t\xc3\xa9", nullptr,
                          "a long string, longer than the small buffer sizes the check also uses"};
    for (const char *s : strs) {
        check(true, "%s", s); check(true, "<%s>", s); check(true, "name=%s pid=%d", s, 42);
        check(false, "%10s", s); check(false, "%-4s|", s); check(false, "%.3s", s);
    }
    // Declined on purpose (flags, width, precision, wide, floating, %n, unknown, a lone %): the
    // fast path must hand them to vsnprintf before touching anything.
    check(false, "%5d", 42); check(false, "%-5d|", 42); check(false, "%05d", -42); check(false, "%+d", 42);
    check(false, "% d", 42); check(false, "%#x", 255); check(false, "%.3d", 7); check(false, "%*d", 5, 42);
    check(false, "%f", 1.5); check(false, "%g", 2.5); check(false, "%ls", L"wide"); check(false, "%lc", (int)L'w');
    check(false, "%hs", "narrow"); check(false, "%S", L"wide"); check(false, "%k", 1); check(false, "%Lf", 1.0L);
    check(false, "%I6x", 1); check(false, "%w", 1); check(false, "plain text, no conversions");
    check(true, "plain text, no conversions");
    check(true, "");
    std::printf("{\"kind\":\"log_format_selftest\",\"bits\":%d,\"cases\":%d,\"fast\":%d,\"declined\":%d,"
                "\"mismatch\":%d,\"unexpected_decline\":%d,\"first\":\"%s\"}\n",
                (int)(8 * sizeof(void *)), g_cases, g_fast, g_declined, g_mismatch, g_unexpected_decline,
                g_first.c_str());
    return g_mismatch || g_unexpected_decline ? 1 : 0;
}
