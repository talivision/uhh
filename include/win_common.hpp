#pragma once
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <string>
#include <initializer_list>
#include "probe_internal.hpp"
inline void require(bool ok, const char *message) {
    if (!ok) throw std::runtime_error(std::string(message) + " (Win32=" + std::to_string(GetLastError()) + ")");
}
inline int remote_read(void *h, uint64_t a, void *b, size_t n, size_t *done) {
    SIZE_T bytes = 0; BOOL ok = ReadProcessMemory((HANDLE)h, (const void *)(uintptr_t)a, b, n, &bytes);
    *done = bytes; return !!ok;
}
inline int remote_write(void *h, uint64_t a, const void *b, size_t n, size_t *done) {
    SIZE_T bytes = 0; BOOL ok = WriteProcessMemory((HANDLE)h, (void *)(uintptr_t)a, b, n, &bytes);
    *done = bytes; return !!ok;
}
inline const probe_ops remote_ops = {remote_read, remote_write};
/* Same CONTEXT struct both arches; the register image differs only by field
   name/width, so from/to_context fork on the build target. Logical register
   names stay the gospel probe_regs on both arches; on x86 r8..r15 stay zero. */
#define PROBE_GPRS(X) X(rax,Rax) X(rbx,Rbx) X(rcx,Rcx) X(rdx,Rdx) X(rsi,Rsi) X(rdi,Rdi) X(rbp,Rbp) X(r8,R8) X(r9,R9) X(r10,R10) X(r11,R11) X(r12,R12) X(r13,R13) X(r14,R14) X(r15,R15)
inline probe_context from_context(CONTEXT &w, uint32_t site, uint64_t pc, const probe_ops *ops, void *backend) {
    probe_context c{};
#if defined(_WIN64)
#define COPY(a,b) c.regs.a = w.b;
    PROBE_GPRS(COPY)
#undef COPY
    c.regs.rsp = w.Rsp;
#else
    c.regs.rax = w.Eax; c.regs.rbx = w.Ebx; c.regs.rcx = w.Ecx; c.regs.rdx = w.Edx;
    c.regs.rsi = w.Esi; c.regs.rdi = w.Edi; c.regs.rbp = w.Ebp; c.regs.rsp = w.Esp;
#endif
    c.regs.flags = w.EFlags; c.regs.pc = pc; c.hit_sp = c.regs.rsp;
    c.site = site; c.ops = ops; c.backend = backend; return c;
}
inline void to_context(const probe_context &c, CONTEXT &w) {
#if defined(_WIN64)
#define COPY(a,b) w.b = c.regs.a;
    PROBE_GPRS(COPY)
#undef COPY
#else
    w.Eax = (DWORD)c.regs.rax; w.Ebx = (DWORD)c.regs.rbx; w.Ecx = (DWORD)c.regs.rcx;
    w.Edx = (DWORD)c.regs.rdx; w.Esi = (DWORD)c.regs.rsi; w.Edi = (DWORD)c.regs.rdi;
    w.Ebp = (DWORD)c.regs.rbp;
#endif
    /* PC/SP and flags are read-only in this first common contract. */
}
/* call_original / return_from are only meaningful from a probe on a function's FIRST
   instruction, where [SP] is the caller's return address. A cheap, arch-neutral test: the
   bytes before that address must end with a CALL encoding (E8 rel32, FF /2 in its register,
   [reg], [reg+disp8/32], SIB and RIP/absolute forms; a REX prefix before FF /2 is ignored).
   pre = the 8 bytes immediately before the candidate return address. A false "no" refuses
   the call (safe: the original simply runs natively); a false "yes" needs a random stack
   word that happens to follow a call instruction. */
inline bool looks_like_return_site(const unsigned char pre[8]) {
    const unsigned char *p = pre + 8;
    auto ff2 = [](unsigned char m) { return ((m >> 3) & 7) == 2; };
    if (p[-5] == 0xE8) return true;                                                     // call rel32
    if (p[-2] == 0xFF && ff2(p[-1]) && ((p[-1] >> 6) == 3 ||                            // call reg
        ((p[-1] >> 6) == 0 && (p[-1] & 7) != 4 && (p[-1] & 7) != 5))) return true;      // call [reg]
    if (p[-3] == 0xFF && ff2(p[-2]) && (((p[-2] >> 6) == 1 && (p[-2] & 7) != 4) ||      // call [reg+d8]
        ((p[-2] >> 6) == 0 && (p[-2] & 7) == 4 && (p[-1] & 7) != 5))) return true;      // call [sib]
    if (p[-4] == 0xFF && ff2(p[-3]) && (p[-3] >> 6) == 1 && (p[-3] & 7) == 4) return true;   // call [sib+d8]
    if (p[-6] == 0xFF && ff2(p[-5]) && (((p[-5] >> 6) == 2 && (p[-5] & 7) != 4) ||      // call [reg+d32]
        (p[-5] & 0xC7) == 5)) return true;                                              // call [rip/abs32]
    if (p[-7] == 0xFF && ff2(p[-6]) && (((p[-6] >> 6) == 2 && (p[-6] & 7) == 4) ||      // call [sib+d32]
        ((p[-6] >> 6) == 0 && (p[-6] & 7) == 4 && (p[-5] & 7) == 5))) return true;      // call [idx*s+d32]
    return false;
}
// Every export name of `callback`'s module that points at it, '\n'-separated, in export
// table order. Several when the linker folded identical functions (/OPT:ICF: two empty
// callbacks share one address) -- any of them is the same code, but another copy of the
// callbacks (the agent DLL vs the controller executable) may export only some of them, so
// the receiving side tries each. Reporting only the FIRST name made a dynamic add from an
// inline callback fail (0) whenever that name was one the controller does not export.
inline bool callback_export_names(probe_callback callback, std::string &names) {
    names.clear();
    HMODULE module{};
    if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            reinterpret_cast<LPCSTR>(callback), &module)) return false;
    auto base = reinterpret_cast<const unsigned char *>(module);
    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto nt = reinterpret_cast<const IMAGE_NT_HEADERS *>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
        return false;
    auto dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir.VirtualAddress || !dir.Size) return false;
    auto exports = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY *>(base + dir.VirtualAddress);
    auto functions = reinterpret_cast<const DWORD *>(base + exports->AddressOfFunctions);
    auto names_rva = reinterpret_cast<const DWORD *>(base + exports->AddressOfNames);
    auto ordinals = reinterpret_cast<const WORD *>(base + exports->AddressOfNameOrdinals);
    uint64_t callback_rva = reinterpret_cast<const unsigned char *>(callback) - base;
    for (DWORD i = 0; i < exports->NumberOfNames; ++i) {
        WORD ordinal = ordinals[i];
        if (ordinal < exports->NumberOfFunctions && functions[ordinal] == callback_rva) {
            if (!names.empty()) names += '\n';
            names += reinterpret_cast<const char *>(base + names_rva[i]);
        }
    }
    return !names.empty();
}
inline bool callback_export_name(probe_callback callback, std::string &name) {
    if (!callback_export_names(callback, name)) return false;
    const size_t nl = name.find('\n');
    if (nl != std::string::npos) name.resize(nl);
    return true;
}
// The leading whole names of a '\n'-separated list that fit in cap-1 chars ("" if the first
// does not fit).
inline std::string export_names_fit(const std::string &names, size_t cap) {
    size_t end = 0;
    for (size_t next; end < names.size(); end = next) {
        next = names.find('\n', end + 1);
        if (next == std::string::npos) next = names.size();
        if (next >= cap) break;
    }
    return names.substr(0, end);
}

inline std::string exe_directory() {
    char p[MAX_PATH]; DWORD n = GetModuleFileNameA(nullptr,p,MAX_PATH);
    require(n && n < MAX_PATH,"executable path");
    std::string s(p); return s.substr(0,s.find_last_of("\\/")+1);
}

// A thread of OURS in the target (the agent's service thread; the controller's agent load /
// init / stop threads), created suspended and WITHOUT the loader's thread-attach callouts
// (THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH): a plain CreateThread / CreateRemoteThread runs the
// PROGRAM's DllMain(DLL_THREAD_ATTACH / DLL_THREAD_DETACH) and TLS callbacks on our thread --
// program code running for a thread the program never made, at a moment it does not expect
// (seen: hunt_target's TLS callback counts every thread attach/detach; the agent init thread
// started while main ran and its attach/detach made reads the program never meant, and a hit
// that raced the program's own count -- hunt-early-inline x86, reads=11 hits=12). The loader
// still allocates the thread's static TLS (the agent's thread_locals). Falls back to
// CreateRemoteThread (callouts and all) only if ntdll lacks NtCreateThreadEx.
inline HANDLE create_quiet_thread(HANDLE process, LPTHREAD_START_ROUTINE entry, void *argument, DWORD *tid) {
    using NtCreateThreadExFn = LONG(NTAPI *)(PHANDLE, ACCESS_MASK, void *, HANDLE, void *, void *, ULONG, SIZE_T, SIZE_T,
                                             SIZE_T, void *);
    static const auto create = reinterpret_cast<NtCreateThreadExFn>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateThreadEx"));
    constexpr ULONG CREATE_SUSPENDED_FLAG = 0x1, SKIP_THREAD_ATTACH = 0x2;
    if (!create) return CreateRemoteThread(process, nullptr, 0, entry, argument, CREATE_SUSPENDED, tid);
    HANDLE t = nullptr;
    const LONG st = create(&t, THREAD_ALL_ACCESS, nullptr, process, reinterpret_cast<void *>(entry), argument,
                           CREATE_SUSPENDED_FLAG | SKIP_THREAD_ATTACH, 0, 0, 0, nullptr);
    if (st < 0 || !t) {
        SetLastError(st == (LONG)0xC0000022 ? ERROR_ACCESS_DENIED : ERROR_GEN_FAILURE);
        return nullptr;
    }
    if (tid) *tid = GetThreadId(t);
    return t;
}
