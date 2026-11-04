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
#ifdef PROBE_PUBLIC_API
#include "probe_api.h"
#else
#include "probe.h"
#endif
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
    c.regs.flags = w.EFlags; c.regs.pc = pc;
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
#ifndef PROBE_PUBLIC_API
inline uint64_t record_digest(const probe_stats &s) {
    uint64_t h=14695981039346656037ULL;
    for(uint64_t i=0;i<s.recorded;++i) {
        const auto &r=s.records[i];
        for(uint64_t v: {r.handle,r.address,r.size,r.sequence}) {h^=v; h*=1099511628211ULL;}
    }
    return h;
}
inline void dump_records(const probe_stats &s) {
    char value[8];
    if (!GetEnvironmentVariableA("PROBE_DUMP_LOGS",value,sizeof(value))) return;
    for(uint64_t i=0;i<s.recorded;++i) {
        const auto &r=s.records[i];
        std::printf("{\"kind\":\"record\",\"handle\":%llu,\"address\":%llu,\"size\":%llu,\"sequence\":%llu}\n",
            (unsigned long long)r.handle,(unsigned long long)r.address,(unsigned long long)r.size,(unsigned long long)r.sequence);
    }
}
inline uint64_t process_cpu_ns(HANDLE process) {
    FILETIME created{},exited{},kernel{},user{};
    require(!!GetProcessTimes(process,&created,&exited,&kernel,&user),"process CPU time");
    ULARGE_INTEGER k{},u{}; k.LowPart=kernel.dwLowDateTime;k.HighPart=kernel.dwHighDateTime;
    u.LowPart=user.dwLowDateTime;u.HighPart=user.dwHighDateTime;return (k.QuadPart+u.QuadPart)*100;
}
inline void print_stats(const probe_stats &s) {
    std::printf("\"flag_hits\":%llu,\"read_hits\":%llu,\"matches\":%llu,\"errors\":%llu,\"recorded\":%llu,\"dropped\":%llu",
        (unsigned long long)s.flag_hits,(unsigned long long)s.read_hits,(unsigned long long)s.matches,
        (unsigned long long)s.errors,(unsigned long long)s.recorded,(unsigned long long)s.dropped);
    std::printf(",\"record_digest\":%llu",(unsigned long long)record_digest(s));
}
inline uint32_t callback_kind(const char *s) {
    if (!std::strcmp(s,"noop")) return CALLBACK_NOOP;
    if (!std::strcmp(s,"filter")) return CALLBACK_FILTER;
    if (!std::strcmp(s,"mutate")) return CALLBACK_MUTATE;
    if (!std::strcmp(s,"log")) return CALLBACK_LOG;
    throw std::runtime_error("callback must be noop|filter|mutate|log");
}
#endif
inline std::string exe_directory() {
    char p[MAX_PATH]; DWORD n = GetModuleFileNameA(nullptr,p,MAX_PATH);
    require(n && n < MAX_PATH,"executable path");
    std::string s(p); return s.substr(0,s.find_last_of("\\/")+1);
}
