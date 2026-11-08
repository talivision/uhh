#pragma once
// Fixture-only AV diagnostics. Never handles the exception or changes its context.
#include <windows.h>
#include <intrin.h>
#include <cstdio>
static const char *review_fault_tag = "review_fault";
static thread_local bool review_fault_reporting;
static LONG WINAPI review_fault_report(EXCEPTION_POINTERS *ep) {
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_ACCESS_VIOLATION) return EXCEPTION_CONTINUE_SEARCH;
    if (review_fault_reporting) return EXCEPTION_CONTINUE_SEARCH;
    review_fault_reporting = true;
    const auto *er = ep->ExceptionRecord;
    std::fprintf(stderr, "%s code=0x%lx ip=%p access=%llu address=0x%llx\n", review_fault_tag,
                 er->ExceptionCode, er->ExceptionAddress,
                 er->NumberParameters > 0 ? (unsigned long long)er->ExceptionInformation[0] : 0,
                 er->NumberParameters > 1 ? (unsigned long long)er->ExceptionInformation[1] : 0);
    int cp[4]; __cpuid(cp, 1);
    const unsigned long long xcr0 = (cp[2] & (1 << 27)) ? _xgetbv(0) : 0;
    __cpuidex(cp, 0xD, 0);
    std::fprintf(stderr, "%s xcr0=0x%llx supported=0x%08x%08x enabled_size=%u maximum_size=%u\n",
                 review_fault_tag, xcr0, (unsigned)cp[3], (unsigned)cp[0], (unsigned)cp[1], (unsigned)cp[2]);
    CONTEXT c = *ep->ContextRecord;
    c.ContextFlags &= ~(DWORD)0x40;                    // no CONTEXT_EX/XSTATE extension was copied
    const auto *tib = reinterpret_cast<const NT_TIB *>(NtCurrentTeb());
    const ULONG_PTR lo = (ULONG_PTR)tib->StackLimit, hi = (ULONG_PTR)tib->StackBase;
#if defined(_WIN64)
    std::fprintf(stderr, "%s sp=0x%llx ax=0x%llx bx=0x%llx dx=0x%llx si=0x%llx di=0x%llx bp=0x%llx\n",
                 review_fault_tag, c.Rsp, c.Rax, c.Rbx, c.Rdx, c.Rsi, c.Rdi, c.Rbp);
#endif
    __try {
        for (unsigned frame = 0; frame != 16; ++frame) {
#if defined(_WIN64)
            const ULONG_PTR ip = (ULONG_PTR)c.Rip, sp = (ULONG_PTR)c.Rsp;
#else
            const ULONG_PTR ip = (ULONG_PTR)c.Eip, sp = (ULONG_PTR)c.Esp;
#endif
            if (!ip || sp < lo || sp > hi - sizeof(ULONG_PTR)) break;
            MEMORY_BASIC_INFORMATION mbi{};
            wchar_t module[MAX_PATH] = L"?";
            ULONG_PTR base = 0;
            if (VirtualQuery((void *)ip, &mbi, sizeof(mbi)) && mbi.Type == MEM_IMAGE) {
                base = (ULONG_PTR)mbi.AllocationBase;
                GetModuleFileNameW((HMODULE)base, module, MAX_PATH);
            }
            std::fprintf(stderr, "%s frame=%u ip=0x%llx sp=0x%llx module=%ls+0x%llx\n", review_fault_tag,
                         frame, (unsigned long long)ip, (unsigned long long)sp, module, (unsigned long long)(ip - base));
#if defined(_WIN64)
            DWORD64 image = 0;
            if (PRUNTIME_FUNCTION fn = RtlLookupFunctionEntry(c.Rip, &image, nullptr)) {
                void *handler = nullptr; DWORD64 establisher = 0;
                RtlVirtualUnwind(UNW_FLAG_NHANDLER, image, c.Rip, fn, &c, &handler, &establisher, nullptr);
            } else { c.Rip = *(const ULONG_PTR *)sp; c.Rsp += sizeof(ULONG_PTR); }
#else
            const ULONG_PTR bp = (ULONG_PTR)c.Ebp;
            if (bp < sp || bp > hi - 2 * sizeof(ULONG_PTR)) break;
            c.Eip = ((const ULONG_PTR *)bp)[1]; c.Esp = (DWORD)(bp + 2 * sizeof(ULONG_PTR));
            c.Ebp = *(const ULONG_PTR *)bp;
#endif
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    std::fflush(stderr);
    review_fault_reporting = false;
    return EXCEPTION_CONTINUE_SEARCH;
}
