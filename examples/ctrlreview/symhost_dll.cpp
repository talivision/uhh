// symhost.dll -- a host DLL that links UHH STATICALLY (regress ctrl-symload-unload, codex3 #4):
// symhost_run() creates a session and closes it without launching anything; the host process
// then unloads this DLL at once. UHH's background dbghelp preload thread (started by
// probe_session_create) must not run on in the unmapped image.
#include <windows.h>
#include "probe_api.h"

extern "C" __declspec(dllexport) int symhost_run(void) {
    probe_session *s = probe_session_create();
    if (!s) return 0;
    probe_close(s);
    return 1;
}
