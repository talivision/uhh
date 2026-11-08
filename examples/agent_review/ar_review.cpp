// Deterministic inline-agent review fixtures (regress cdx-agent-*).
#include "probe_agent_shared.hpp"
#include "ar_review.hpp"
#include <immintrin.h>
#include <aclapi.h>
#include <cstring>
#include <cstdlib>
#include <initializer_list>
#include <vector>
#define AR_EXPORT extern "C" __declspec(dllexport) __declspec(noinline)
static volatile LONG review_sink;
AR_EXPORT void ar_pressure_site() { InterlockedIncrement(&review_sink); }
AR_EXPORT void ar_vector_site() { InterlockedIncrement(&review_sink); }
AR_EXPORT void ar_epoch_site(ArEpochControl *) { InterlockedIncrement(&review_sink); }
AR_EXPORT void ar_cache_site(void *) { InterlockedIncrement(&review_sink); }
AR_EXPORT uint64_t ar_guard_buffer(void *p) {
    DWORD old = 0;
    return VirtualProtect(p, 4096, PAGE_READWRITE | PAGE_GUARD, &old) ? 1 : 0;
}
AR_EXPORT void ar_guarantee_throw() { RaiseException(0xE0A01234, 0, 0, nullptr); }
static int guarantee_call() {
    __try { ar_guarantee_throw(); }
    __except (GetExceptionCode() == 0xE0A01234 ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) { return 1; }
    return 0;
}
static probe_agent_shared *review_channel() {
    wchar_t name[64]; probe_agent_mapping_name(GetCurrentProcessId(), name);
    HANDLE h = OpenFileMappingW(FILE_MAP_READ, FALSE, name);
    auto *p = h ? (probe_agent_shared *)MapViewOfFile(h, FILE_MAP_READ, 0, 0, sizeof(probe_agent_shared)) : nullptr;
    if (h) CloseHandle(h);
    return p;
}
static volatile LONG pressure_ready;
static DWORD WINAPI pressure_thread(void *event) {
    ar_pressure_site();
    InterlockedIncrement(&pressure_ready);
    if (event) WaitForSingleObject((HANDLE)event, 60000);
    return 0;
}
static DWORD WINAPI epoch_thread(void *p) { ar_epoch_site((ArEpochControl *)p); return 0; }
static int epoch_case() {
    ArEpochControl control{CreateEventW(nullptr, TRUE, FALSE, nullptr), CreateEventW(nullptr, TRUE, FALSE, nullptr), 0};
    printf("{\"kind\":\"ready\",\"pid\":%lu}\n", GetCurrentProcessId()); fflush(stdout);
    if (getchar() == EOF) return 2;
    HANDLE t = CreateThread(nullptr, 0, epoch_thread, &control, 0, nullptr);
    if (!t || WaitForSingleObject(control.entered, 10000) != WAIT_OBJECT_0) return 3;
    // Suspend the callback so bounded detach reports it as interrupted immediately.
    if (SuspendThread(t) == (DWORD)-1) return 4;
    printf("{\"kind\":\"parked\"}\n"); fflush(stdout);
    if (getchar() == EOF) return 5;
    SetEvent(control.release); ResumeThread(t);
    if (WaitForSingleObject(t, 10000) != WAIT_OBJECT_0) return 6;
    const LONG old_config = control.observed;
    ar_epoch_site(&control);
    printf("{\"kind\":\"ar\",\"old_config\":%ld,\"new_config\":%ld}\n", old_config, control.observed); fflush(stdout);
    if (getchar() == EOF) return 7;
    CloseHandle(t); CloseHandle(control.entered); CloseHandle(control.release);
    return old_config == 1 && control.observed == 2 ? 0 : 8;
}
AR_EXPORT void ar_shared_write_site(int value) { InterlockedExchange(&review_sink, value); }
AR_EXPORT void ar_shared_read_site() { InterlockedIncrement(&review_sink); }
AR_EXPORT int ar_config_site() { InterlockedIncrement(&review_sink); return 1; }
AR_EXPORT void ar_vector_clobber() {
    int cp[4]; __cpuid(cp, 1);
    if (!(cp[2] & (1 << 27))) return;
    const uint64_t enabled = _xgetbv(0);
    if ((enabled & 6) != 6) return;
    const uint64_t mask = 4ull | ((enabled & 0xE0) == 0xE0 ? 0x20ull : 0);
    alignas(64) unsigned char area[4096] = {};
    *(uint64_t *)(area + 512) = mask;
    for (int i : {2, 5}) if (mask & (1ull << i)) {
        __cpuidex(cp, 0xD, i);
        memset(area + cp[1], 0xA5, (size_t)cp[0]);
    }
#if defined(_WIN64)
    _xrstor64(area, mask);
#else
    _xrstor(area, mask);
#endif
}
static int stop_guarded() {
    using Stop = DWORD (WINAPI *)(void *);
    auto fn = (Stop)GetProcAddress(GetModuleHandleW(L"probe_api_agent.dll"), "probe_agent_stop");
    if (!fn) return 0;
    __try { fn(nullptr); return 1; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}
int ar_review_case(const char *k) {
    if (!strcmp(k, "review-epoch")) return epoch_case();
    if (!strcmp(k, "review-shared") || !strcmp(k, "review-config")) {
        // /OPT:ICF can fold identical exported bodies, even with different signatures.
        const bool distinct = (uintptr_t)&ar_shared_write_site != (uintptr_t)&ar_shared_read_site;
        printf("{\"kind\":\"ready\",\"pid\":%lu,\"distinct\":%d}\n", GetCurrentProcessId(), distinct ? 1 : 0); fflush(stdout);
        if (!distinct) return 2;
        int n = 0;
        for (int ch; (ch = getchar()) != EOF && ch != 'q'; ) {
            if (ch == 'm') {
                char text[64] = {}; if (!fgets(text, sizeof(text), stdin)) return 2;
                MEMORY_BASIC_INFORMATION mbi{};
                const SIZE_T got = VirtualQuery((void *)(uintptr_t)strtoull(text, nullptr, 16), &mbi, sizeof(mbi));
                printf("{\"kind\":\"memory\",\"state\":%lu}\n", got ? mbi.State : 0); fflush(stdout);
            }
            if (ch == 'x') {
                ++n;
                int value = 0;
                if (!strcmp(k, "review-shared")) { ar_shared_write_site(n); ar_shared_read_site(); }
                else value = ar_config_site();
                printf("{\"kind\":\"ar\",\"n\":%d,\"value\":%d}\n", n, value); fflush(stdout);
            }
        }
        return 0;
    }
    if (!strcmp(k, "review-cache")) {
        void *p = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!p) return 2;
        ar_cache_site(p);
        MEMORY_BASIC_INFORMATION mbi{}; VirtualQuery(p, &mbi, sizeof(mbi));
        const int intact = (mbi.Protect & PAGE_GUARD) != 0;
        DWORD old = 0; VirtualProtect(p, 4096, PAGE_READWRITE, &old); VirtualFree(p, 0, MEM_RELEASE);
        printf("{\"kind\":\"ar\",\"guard_intact\":%d}\n", intact);
        return intact ? 0 : 3;
    }
    if (!strcmp(k, "review-guarantee")) {
        ULONG before = 0, after = 0;
        SetThreadStackGuarantee(&before);
        const int caught = guarantee_call();
        SetThreadStackGuarantee(&after);
        printf("{\"kind\":\"ar\",\"caught\":%d,\"before\":%lu,\"after\":%lu}\n", caught, before, after);
        return caught && before == after ? 0 : 3;
    }
    if (!strcmp(k, "review-error") || !strcmp(k, "review-denied")) {
        const bool denied = !strcmp(k, "review-denied");
        HANDLE event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        HANDLE victim_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        DWORD tid = 0;
        HANDLE t = CreateThread(nullptr, 0, pressure_thread, victim_event, 0, &tid);
        if (!t) return 2;
        const ULONGLONG deadline = GetTickCount64() + 30000;
        while (pressure_ready != 1 && GetTickCount64() < deadline) Sleep(1);
        auto *sh = review_channel();
        std::vector<HANDLE> fillers;
        for (uint32_t i = 1; i < PROBE_AGENT_TBLOCKS; ++i) {
            HANDLE h = CreateThread(nullptr, 0, pressure_thread, event, 0, nullptr);
            if (h) fillers.push_back(h);
        }
        while (pressure_ready != (LONG)PROBE_AGENT_TBLOCKS && GetTickCount64() < deadline) Sleep(1);
        const int filled = sh && pressure_ready == (LONG)PROBE_AGENT_TBLOCKS && sh->tblocks[0].owner == (LONG)tid;
        int blocked = 0, gone = 0;
        HANDLE restricted = nullptr;
        bool impersonating = false;
        if (denied) {
            // An empty DACL alone is insufficient when the effective token has SeDebugPrivilege.
            // Deny the precise rights explicitly, then run BOTH the preflight OpenThread and
            // the agent sweep under a duplicate impersonation token with all privileges disabled.
            BYTE everyone[SECURITY_MAX_SID_SIZE] = {};
            DWORD sid_size = sizeof(everyone);
            EXPLICIT_ACCESSA ea{};
            ea.grfAccessPermissions = SYNCHRONIZE | THREAD_QUERY_LIMITED_INFORMATION;
            ea.grfAccessMode = DENY_ACCESS;
            ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
            ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
            ea.Trustee.ptstrName = (LPSTR)everyone;
            PACL acl = nullptr;
            HANDLE process_token = nullptr;
            const bool secured = CreateWellKnownSid(WinWorldSid, nullptr, everyone, &sid_size) &&
                SetEntriesInAclA(1, &ea, nullptr, &acl) == ERROR_SUCCESS &&
                SetSecurityInfo(t, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                                nullptr, nullptr, acl, nullptr) == ERROR_SUCCESS;
            if (acl) LocalFree(acl);
            if (secured && OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &process_token)) {
                if (DuplicateTokenEx(process_token, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES | TOKEN_IMPERSONATE,
                                     nullptr, SecurityImpersonation, TokenImpersonation, &restricted) &&
                    AdjustTokenPrivileges(restricted, TRUE, nullptr, 0, nullptr, nullptr))
                    impersonating = SetThreadToken(nullptr, restricted) != FALSE;
                CloseHandle(process_token);
            }
            if (impersonating) {
                HANDLE h = OpenThread(SYNCHRONIZE | THREAD_QUERY_LIMITED_INFORMATION, FALSE, tid);
                blocked = !h && GetLastError() == ERROR_ACCESS_DENIED;
                if (h) CloseHandle(h);
            }
        } else {
            SetEvent(victim_event); WaitForSingleObject(t, 10000);
            CloseHandle(t); t = nullptr;                  // no handle keeps the dead thread id alive
            const ULONGLONG until = GetTickCount64() + 5000;
            do {
                HANDLE h = OpenThread(SYNCHRONIZE | THREAD_QUERY_LIMITED_INFORMATION, FALSE, tid);
                gone = !h && GetLastError() == ERROR_INVALID_PARAMETER;
                if (h) CloseHandle(h);
                if (gone) break;
                Sleep(1);                               // let the debugger release its exit-event handle
            } while (GetTickCount64() < until);
        }
        SetLastError(0x12345678);
        ar_pressure_site();
        const DWORD error = GetLastError();
        const int kept = sh && sh->tblocks[0].owner == (LONG)tid;
        if (impersonating) RevertToSelf();
        if (restricted) CloseHandle(restricted);
        SetEvent(event); SetEvent(victim_event);
        if (t) { WaitForSingleObject(t, 10000); CloseHandle(t); }
        for (HANDLE h : fillers) { WaitForSingleObject(h, 10000); CloseHandle(h); }
        CloseHandle(event); CloseHandle(victim_event);
        if (sh) UnmapViewOfFile(sh);
        printf("{\"kind\":\"ar\",\"filled\":%d,\"blocked\":%d,\"gone\":%d,\"kept\":%d,\"error\":%lu}\n", filled, blocked, gone, kept, error);
        return filled && (denied ? blocked && kept : gone && !kept && error == 0x12345678) ? 0 : 3;
    }
    if (!strcmp(k, "review-vector")) {
        int cp[4]; __cpuid(cp, 1);
        const uint64_t enabled = (cp[2] & (1 << 27)) ? _xgetbv(0) : 0;
        const uint64_t mask = (enabled & 6) == 6 ? (4ull | ((enabled & 0xE0) == 0xE0 ? 0xE0ull : 0)) : 0;
#if defined(_WIN64)
        const uint64_t state_mask = mask | 2ull;         // XMM/MXCSR are restored by the stub/agent
#else
        const uint64_t state_mask = mask | 3ull;         // also exercise newly activated x87
#endif
        int clean = 1, bad_phase = -1;
#if defined(_WIN64)
        const int checks = !mask ? 0 : (mask & 0x20) ? 5 : 2;
#else
        const int checks = !mask ? 0 : (mask & 0x20) ? 4 : 2;
#endif
        for (int phase = 0; phase < checks; ++phase) {
            alignas(64) unsigned char area[4096] = {}, before[4096] = {};
            *(unsigned int *)(area + 24) = _mm_getcsr();
            if (phase == 1) *(unsigned int *)(area + 24) ^= 0x4000u; // non-INIT MXCSR must survive too
            // 0: all INIT (no-save/x86 FX path). 1: live YMM (ordinary save path).
            // 2: live opmasks, INIT YMM: adding component 2 before saved component 5
            // must NOT change the offsets of the XSAVEC image being restored.
            // 3/4: a live ZMM upper/high-register component must survive VZEROUPPER on
            // newly dirtied YMM state (component 6 is restored after VZEROUPPER zeros it).
            const uint64_t live = phase == 1 ? 4ull : phase == 2 ? 0x20ull
                                : phase == 3 ? 0x40ull : phase == 4 ? 0x80ull : 0;
            *(uint64_t *)(area + 512) = live;
            for (int i : {2, 5, 6, 7}) {
                if (!(live & (1ull << i))) continue;
                __cpuidex(cp, 0xD, i);
                for (int j = 0; j < cp[0]; ++j) area[cp[1] + j] = (unsigned char)(0x50 + phase);
            }
#if defined(_WIN64)
            _xrstor64(area, state_mask);
            _xsave64(before, state_mask);                 // canonical baseline, including INIT bits
            ar_vector_site();
            _xsave64(area, state_mask);
#else
            _xrstor(area, state_mask);
            _xsave(before, state_mask);
            ar_vector_site();
            _xsave(area, state_mask);
#endif
            if (memcmp(area + 24, before + 24, 4) ||
                memcmp(area + 160, before + 160, sizeof(void *) == 8 ? 256 : 128)) {
                clean = 0; bad_phase = phase;
            }
#if !defined(_WIN64)
            // Ignore reserved FXSAVE padding; check FCW/FSW/FTW, pointers/opcode and
            // all physical data registers, including those tagged empty after INIT.
            if (memcmp(area, before, 5) || memcmp(area + 6, before + 6, 18)) {
                clean = 0; bad_phase = phase;
            }
            for (int reg = 0; reg < 8; ++reg)
                if (memcmp(area + 32 + reg * 16, before + 32 + reg * 16, 10)) {
                    clean = 0; bad_phase = phase;
                }
#endif
            const uint64_t bv = *(uint64_t *)(area + 512), prior = *(uint64_t *)(before + 512);
            for (int i : {2, 5, 6, 7}) {
                if (!(mask & (1ull << i))) continue;
                __cpuidex(cp, 0xD, i);
                int bytes = cp[0];
#if !defined(_WIN64)
                if (i == 2 && bytes > 128) bytes = 128;    // x86 has YMM0..7 only
                if (i == 6 && bytes > 256) bytes = 256;    // likewise ZMM0..7 upper halves
#endif
                for (int j = 0; j < bytes; ++j) {
                    const int got = (bv & (1ull << i)) ? area[cp[1] + j] : 0;
                    const int want = (prior & (1ull << i)) ? before[cp[1] + j] : 0;
                    if (got != want) { clean = 0; bad_phase = phase; }
                }
            }
        }
        printf("{\"kind\":\"ar\",\"avx\":%d,\"opmask\":%d,\"checks\":%d,\"clean\":%d,\"bad_phase\":%d}\n",
               mask ? 1 : 0, (mask & 0x20) ? 1 : 0, checks, clean, bad_phase);
        return clean ? 0 : 3;
    }
    if (!strcmp(k, "review-guard")) {
        // Separate DLL code: guarding it cannot fault this fixture's own instructions.
        HMODULE dll = LoadLibraryW(L"ctrl_cfr_a.dll");
        void *fn = dll ? (void *)GetProcAddress(dll, "CfrValue") : nullptr;
        if (!fn) return 2;
        DWORD old = 0;
        const int armed = VirtualProtect(fn, 1, PAGE_EXECUTE_READ | PAGE_GUARD, &old) ? 1 : 0;
        const int stopped = stop_guarded();
        MEMORY_BASIC_INFORMATION mbi{}; VirtualQuery(fn, &mbi, sizeof(mbi));
        const int intact = (mbi.Protect & PAGE_GUARD) != 0;
        DWORD ignore = 0; VirtualProtect(fn, 1, old, &ignore);
        // Abandoned hook remains in place: do not call or unload its module.
        printf("{\"kind\":\"ar\",\"armed\":%d,\"stopped\":%d,\"guard_intact\":%d}\n", armed, stopped, intact);
        return armed && stopped && intact ? 0 : 3;
    }
    return -1;
}
