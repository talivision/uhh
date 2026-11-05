// famous_driver -- classic Frida / API Monitor / Process Monitor recipes on UHH.
//
//   famous_driver --recipe heap|files|tls|loader|tick --backend breakpoint|hw|inline
//                 [--fallback-hw] [--value 0xN] [--filter text] -- program.exe [args...]
//     --value   retval_override: the forced return value (default 0x1337BEEF)
//     --filter  file_monitor: only paths containing this text (Procmon "Path contains")
//   famous_driver ... --attach-new <image.exe> [--timeout ms]     (attach to the next new one)
//
// One callback source per recipe (examples/famous/<recipe>/*_callbacks.cpp), compiled
// unchanged into this driver and into probe_api_agent.dll; --backend picks how EVERY probe
// of the recipe is delivered, including the return-site probes the callbacks add at
// runtime. Output: the target's own stdout, the probe_log lines, the probe report.
#include "probe_api.h"
#include "common/famous_common.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

extern "C" {
void famous_heap_on_alloc(probe_context *);
void famous_heap_on_free(probe_context *);
void famous_heap_on_exit(probe_context *);
void famous_file_on_create(probe_context *);
void famous_file_on_read(probe_context *);
void famous_file_on_write(probe_context *);
void famous_tls_on_encrypt(probe_context *);
void famous_tls_on_decrypt(probe_context *);
void famous_loader_on_loadlibrary(probe_context *);
void famous_loader_on_ldrloaddll(probe_context *);
void famous_loader_on_alloc(probe_context *);
void famous_loader_on_protect(probe_context *);
void famous_tick_on_entry(probe_context *);
}

struct recipe_probe { const char *symbol; probe_callback cb; };
struct recipe { const char *name; recipe_probe probes[4]; };

static const recipe k_recipes[] = {
    {"heap", {{"ntdll.dll!RtlAllocateHeap", famous_heap_on_alloc},
              {"ntdll.dll!RtlFreeHeap", famous_heap_on_free},
              {"ntdll.dll!RtlExitUserProcess", famous_heap_on_exit}}},
    {"files", {{"ntdll.dll!NtCreateFile", famous_file_on_create},
               {"ntdll.dll!NtReadFile", famous_file_on_read},
               {"ntdll.dll!NtWriteFile", famous_file_on_write}}},
    {"tls", {{"sspicli.dll!EncryptMessage", famous_tls_on_encrypt},
             {"sspicli.dll!DecryptMessage", famous_tls_on_decrypt}}},
    {"loader", {{"kernelbase.dll!LoadLibraryExW", famous_loader_on_loadlibrary},
                {"ntdll.dll!LdrLoadDll", famous_loader_on_ldrloaddll},
                {"ntdll.dll!NtAllocateVirtualMemory", famous_loader_on_alloc},
                {"ntdll.dll!NtProtectVirtualMemory", famous_loader_on_protect}}},
    {"tick", {{"kernel32.dll!GetTickCount", famous_tick_on_entry}}},
};

static int usage() {
    std::fprintf(stderr, "usage: famous_driver --recipe heap|files|tls|loader|tick --backend breakpoint|hw|inline "
                         "[--fallback-hw] [--value 0xN] [--filter text] [--attach-new image.exe [--timeout ms]] [-- program args...]\n");
    return 2;
}

int main(int argc, char **argv) {
    const recipe *r = nullptr;
    uint32_t backend = 0;
    bool fallback_hw = false;
    uint64_t value = 0x1337BEEF;
    const char *attach_new = nullptr, *filter = "";
    unsigned long timeout = 30000;
    int i = 1;
    for (; i < argc; ++i) {
        if (!std::strcmp(argv[i], "--")) { ++i; break; }
        if (!std::strcmp(argv[i], "--recipe") && i + 1 < argc) {
            const char *name = argv[++i];
            for (const recipe &x : k_recipes) if (!std::strcmp(x.name, name)) r = &x;
            if (!r) return usage();
        } else if (!std::strcmp(argv[i], "--backend") && i + 1 < argc) {
            const char *b = argv[++i];
            backend = !std::strcmp(b, "breakpoint") ? PROBE_BREAKPOINT : !std::strcmp(b, "hw") ? PROBE_HW
                    : !std::strcmp(b, "inline") ? PROBE_INLINE : 0;
            if (!backend) return usage();
        } else if (!std::strcmp(argv[i], "--fallback-hw")) {
            fallback_hw = true;
        } else if (!std::strcmp(argv[i], "--value") && i + 1 < argc) {
            value = std::strtoull(argv[++i], nullptr, 0);
        } else if (!std::strcmp(argv[i], "--filter") && i + 1 < argc) {
            filter = argv[++i];
        } else if (!std::strcmp(argv[i], "--attach-new") && i + 1 < argc) {
            attach_new = argv[++i];
        } else if (!std::strcmp(argv[i], "--timeout") && i + 1 < argc) {
            timeout = std::strtoul(argv[++i], nullptr, 0);
        } else {
            return usage();
        }
    }
    if (!r || !backend || (!attach_new && i >= argc)) return usage();

    const uint32_t flags = backend | (backend == PROBE_INLINE && fallback_hw ? (uint32_t)PROBE_FALLBACK_HW : 0u);
    famous_config cfg{FAMOUS_CONFIG_VERSION, flags, value, {}};
    std::snprintf(cfg.filter, sizeof(cfg.filter), "%s", filter);
    probe_session *s = probe_session_create();
    if (!s) return 1;
    int ok = 1;
    for (const recipe_probe &p : r->probes) {
        if (!p.symbol) break;
        ok = ok && probe_add_symbol_cfg(s, p.symbol, p.cb, flags, &cfg, sizeof(cfg));
    }
    if (attach_new) {
        std::printf("{\"kind\":\"waiting_for\",\"image\":\"%s\"}\n", attach_new);
        std::fflush(stdout);
        ok = ok && probe_attach_new(s, attach_new, (uint32_t)timeout);
        if (ok) { std::printf("{\"kind\":\"attached\"}\n"); std::fflush(stdout); }
        ok = ok && probe_run(s) && probe_wait_for_exit(s);
    } else {
        std::vector<char *> child(argv + i, argv + argc);
        child.push_back(nullptr);
        ok = ok && probe_launch(s, child.data()) && probe_run(s) && probe_wait_for_exit(s);
    }
    probe_report(s, stdout);
    probe_close(s);
    return ok ? 0 : 1;
}
