// filetrace -- log every file a program opens and writes, by path.
//
//   filetrace [--backend b] [--create-backend b] [--write-backend b] [--close-backend b]
//             [--filter TEXT] -- <target.exe> [args]
//
// b = breakpoint | hw | inline (default inline; --backend sets all three, the others one
// probe each). --filter logs only paths containing TEXT (case-sensitive).
//   create path=\??\C:\x\a.txt access=0x40100080 status=0x00000000 handle=0x1a4
//   write path=\??\C:\x\a.txt handle=0x1a4 len=512 offset=-1
#include "callbacks.h"
#include <cstdio>
#include <cstring>

static int usage() {
    std::fprintf(stderr, "usage: filetrace [--backend b] [--create-backend b] [--write-backend b] "
                         "[--close-backend b] [--filter TEXT] -- <target.exe> [args]\n"
                         "       b = breakpoint | hw | inline\n");
    return 2;
}

int main(int argc, char **argv) {
    uint32_t create = PROBE_INLINE, write = ~0u, close = ~0u;   // ~0u: same as create
    filetrace_config cfg{FILETRACE_COOKIE, {}};
    int i = 1;
    for (; i < argc && std::strcmp(argv[i], "--"); ++i) {
        const bool more = i + 1 < argc;
        if (!std::strcmp(argv[i], "--backend") && more) create = write = close = filetrace_backend(argv[++i]);
        else if (!std::strcmp(argv[i], "--create-backend") && more) create = filetrace_backend(argv[++i]);
        else if (!std::strcmp(argv[i], "--write-backend") && more) write = filetrace_backend(argv[++i]);
        else if (!std::strcmp(argv[i], "--close-backend") && more) close = filetrace_backend(argv[++i]);
        else if (!std::strcmp(argv[i], "--filter") && more) strncpy_s(cfg.filter, argv[++i], _TRUNCATE);
        else return usage();
    }
    if (write == ~0u) write = create;
    if (close == ~0u) close = create;
    if (!create || !write || !close || i + 1 >= argc) return usage();

    probe_session *s = probe_session_create();
    if (!s) return 1;
    int ok = probe_add_symbol_cfg(s, "ntdll.dll!NtCreateFile", ft_on_create, create, &cfg, sizeof(cfg)) &&
             probe_add_symbol_cfg(s, "ntdll.dll!NtWriteFile", ft_on_write, write, &cfg, sizeof(cfg)) &&
             probe_add_symbol(s, "ntdll.dll!NtClose", ft_on_close, close) &&
             probe_launch(s, argv + i + 1) && probe_run(s) && probe_wait_for_exit(s);
    probe_report(s, stdout);
    probe_close(s);
    return ok ? 0 : 1;
}
