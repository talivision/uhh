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
inline bool callback_export_name(probe_callback callback, std::string &name) {
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
    auto names = reinterpret_cast<const DWORD *>(base + exports->AddressOfNames);
    auto ordinals = reinterpret_cast<const WORD *>(base + exports->AddressOfNameOrdinals);
    uint64_t callback_rva = reinterpret_cast<const unsigned char *>(callback) - base;
    for (DWORD i = 0; i < exports->NumberOfNames; ++i) {
        WORD ordinal = ordinals[i];
        if (ordinal < exports->NumberOfFunctions && functions[ordinal] == callback_rva) {
            name = reinterpret_cast<const char *>(base + names[i]); return true;
        }
    }
    return false;
}

inline std::string exe_directory() {
    char p[MAX_PATH]; DWORD n = GetModuleFileNameA(nullptr,p,MAX_PATH);
    require(n && n < MAX_PATH,"executable path");
    std::string s(p); return s.substr(0,s.find_last_of("\\/")+1);
}
