/* cet_probe: does THIS machine (CPU + hypervisor + Windows) give a /CETCOMPAT process a
   hardware shadow stack? Built with /CETCOMPAT, it reports, as one JSON line:
     cpuid_cet_ss / cpuid_cet_ibt  CPUID.(EAX=7,ECX=0):ECX[7] / EDX[20] -- what the (virtual) CPU exposes
     os_cet_u                      the OS enabled the CET_U XSAVE component (GetEnabledXStateFeatures bit 11)
     ssp                           RDSSP in this thread: non-zero only when a shadow stack is ACTIVE
     policy.*                      ProcessUserShadowStackPolicy of this process (GetProcessMitigationPolicy)
   enforced = ssp != 0. It never violates the shadow stack and changes no setting.
   cet_probe --block-non-cet <dll>...: turns on BlockNonCetBinaries for ITSELF at runtime
   (SetProcessMitigationPolicy) and maps each DLL (LoadLibraryEx DONT_RESOLVE_DLL_REFERENCES:
   no DllMain): which images the policy lets in -- e.g. the injected inline agent. */
#include <windows.h>
#include <intrin.h>
#include <immintrin.h>
#include <stdio.h>
#include <string.h>

#ifndef XSTATE_MASK_CET_U
#define XSTATE_MASK_CET_U (1ull << 11)
#endif

static int block_non_cet(int argc, char **argv) {
    PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY pol;
    memset(&pol, 0, sizeof(pol));
    pol.BlockNonCetBinaries = 1;
    const BOOL set = SetProcessMitigationPolicy(ProcessUserShadowStackPolicy, &pol, sizeof(pol));
    const DWORD set_err = set ? 0 : GetLastError();
    memset(&pol, 0, sizeof(pol));
    GetProcessMitigationPolicy(GetCurrentProcess(), ProcessUserShadowStackPolicy, &pol, sizeof(pol));
    printf("{\"kind\":\"cet_block\",\"set\":%d,\"set_error\":%lu,\"BlockNonCetBinaries\":%u}\n",
           set ? 1 : 0, set_err, pol.BlockNonCetBinaries);
    for (int i = 2; i < argc; ++i) {
        HMODULE h = LoadLibraryExA(argv[i], NULL, DONT_RESOLVE_DLL_REFERENCES);
        const DWORD err = h ? 0 : GetLastError();
        printf("{\"kind\":\"cet_block_load\",\"dll\":\"%s\",\"loaded\":%d,\"error\":%lu}\n",
               strrchr(argv[i], '\\') ? strrchr(argv[i], '\\') + 1 : argv[i], h ? 1 : 0, err);
        if (h) FreeLibrary(h);
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "--block-non-cet")) return block_non_cet(argc, argv);
    int r[4] = {0};
    char vendor[13] = {0};
    __cpuid(r, 0);
    const int max_leaf = r[0];
    memcpy(vendor, &r[1], 4); memcpy(vendor + 4, &r[3], 4); memcpy(vendor + 8, &r[2], 4);
    __cpuid(r, 1);
    const int hypervisor = (r[2] >> 31) & 1;
    int ss = 0, ibt = 0;
    if (max_leaf >= 7) {
        __cpuidex(r, 7, 0);
        ss = (r[2] >> 7) & 1;     /* ECX bit 7: CET_SS */
        ibt = (r[3] >> 20) & 1;   /* EDX bit 20: CET_IBT */
    }

    typedef DWORD64 (WINAPI *get_xs_fn)(void);
    get_xs_fn get_xs = (get_xs_fn)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetEnabledXStateFeatures");
    const DWORD64 xs = get_xs ? get_xs() : 0;

#if defined(_WIN64)
    const unsigned long long ssp = _rdsspq();
#else
    const unsigned long long ssp = _rdsspd();
#endif

    PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY pol;
    memset(&pol, 0, sizeof(pol));
    const BOOL got = GetProcessMitigationPolicy(GetCurrentProcess(), ProcessUserShadowStackPolicy, &pol, sizeof(pol));
    const DWORD err = got ? 0 : GetLastError();

    OSVERSIONINFOW ov;
    memset(&ov, 0, sizeof(ov)); ov.dwOSVersionInfoSize = sizeof(ov);
    typedef LONG (WINAPI *rtl_ver_fn)(OSVERSIONINFOW *);
    rtl_ver_fn rtl_ver = (rtl_ver_fn)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion");
    if (rtl_ver) rtl_ver(&ov);

    printf("{\"kind\":\"cet_probe\",\"arch\":\"%s\",\"vendor\":\"%s\",\"hypervisor\":%d,\"windows_build\":%lu,"
           "\"cpuid_cet_ss\":%d,\"cpuid_cet_ibt\":%d,\"os_cet_u\":%d,\"ssp\":%llu,\"enforced\":%s,"
           "\"policy_ok\":%d,\"policy_error\":%lu,\"policy\":{\"EnableUserShadowStack\":%u,\"AuditUserShadowStack\":%u,"
           "\"SetContextIpValidation\":%u,\"AuditSetContextIpValidation\":%u,\"EnableUserShadowStackStrictMode\":%u,"
           "\"BlockNonCetBinaries\":%u,\"BlockNonCetBinariesNonEhcont\":%u,\"AuditBlockNonCetBinaries\":%u,"
           "\"CetDynamicApisOutOfProcOnly\":%u,\"SetContextIpValidationRelaxedMode\":%u,\"flags\":%lu}}\n",
#if defined(_WIN64)
           "x64",
#else
           "x86",
#endif
           vendor, hypervisor, ov.dwBuildNumber, ss, ibt, (xs & XSTATE_MASK_CET_U) ? 1 : 0, ssp,
           ssp ? "true" : "false", got ? 1 : 0, err,
           pol.EnableUserShadowStack, pol.AuditUserShadowStack, pol.SetContextIpValidation,
           pol.AuditSetContextIpValidation, pol.EnableUserShadowStackStrictMode, pol.BlockNonCetBinaries,
           pol.BlockNonCetBinariesNonEhcont, pol.AuditBlockNonCetBinaries, pol.CetDynamicApisOutOfProcOnly,
           pol.SetContextIpValidationRelaxedMode, pol.Flags);
    return 0;
}
