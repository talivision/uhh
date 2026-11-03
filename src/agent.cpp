#include "win_common.hpp"
#include "agent.h"
#include "detect.hpp"
#include <safetyhook.hpp>
static probe_config config;
static probe_stats stats;
static SafetyHookMid hooks[2];
static void *sites[2]{};
static unsigned char original[2]{};
static PVOID veh{};
static DWORD owner{};
static bool software=false;
static int stepping=-1;
/* Do not invoke C++ destructors in an SEH scope. Only ordinary readable/writable
   data is supported: no protection changes, no executable writes. */
static int local_read(void *,uint64_t a,void *b,size_t n,size_t *done) {
    *done=0;
    __try {std::memcpy(b,(const void *)(uintptr_t)a,n); *done=n; return 1;}
    __except(EXCEPTION_EXECUTE_HANDLER) {return 0;}
}
static int local_write(void *,uint64_t a,const void *b,size_t n,size_t *done) {
    *done=0;
    __try {std::memcpy((void *)(uintptr_t)a,b,n); *done=n; return 1;}
    __except(EXCEPTION_EXECUTE_HANDLER) {return 0;}
}
static const probe_ops local_ops{local_read,local_write};
static bool patch(void *site,unsigned char byte) {
    DWORD old{},ignored{};
    if (!VirtualProtect(site,1,PAGE_EXECUTE_READWRITE,&old)) return false;
    *(volatile unsigned char *)site=byte;
    BOOL flushed=FlushInstructionCache(GetCurrentProcess(),site,1);
    BOOL restored=VirtualProtect(site,1,old,&ignored); return flushed && restored;
}
static void call_win(CONTEXT &w,int index) {
    auto c=from_context(w,(uint32_t)(index+1),(uint64_t)(uintptr_t)sites[index],&local_ops,nullptr);
    c.tid=GetCurrentThreadId(); example_callback(&c,&config,&stats); to_context(c,w);
}
static LONG CALLBACK handler(EXCEPTION_POINTERS *p) {
    if (GetCurrentThreadId()!=owner) return EXCEPTION_CONTINUE_SEARCH;
    auto &w=*p->ContextRecord;
    DWORD code=p->ExceptionRecord->ExceptionCode;
    if (code==EXCEPTION_SINGLE_STEP && stepping>=0) {
        int index=stepping; stepping=-1;
        if (!patch(sites[index],0xcc)) return EXCEPTION_CONTINUE_SEARCH;
        w.EFlags &= ~0x100u; return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (software && code==EXCEPTION_BREAKPOINT) {
        for (int i=0;i<2;++i) if (sites[i] && p->ExceptionRecord->ExceptionAddress==sites[i]) {
            if (!patch(sites[i],original[i])) return EXCEPTION_CONTINUE_SEARCH;
            w.Rip=(DWORD64)(uintptr_t)sites[i]; call_win(w,i);
            stepping=i; w.EFlags|=0x100; return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}
static void call_mid(safetyhook::Context &w,int index) {
    probe_context c{};
#define COPY(a,b) c.regs.a=w.a;
    PROBE_GPRS(COPY)
#undef COPY
    c.regs.rsp=w.rsp; c.regs.flags=w.rflags; c.regs.pc=(uint64_t)(uintptr_t)sites[index];
    c.site=(uint32_t)(index+1); c.tid=GetCurrentThreadId(); c.ops=&local_ops;
    example_callback(&c,&config,&stats);
#define COPY(a,b) w.a=c.regs.a;
    PROBE_GPRS(COPY)
#undef COPY
}
extern "C" __declspec(dllexport) int probe_agent_stop(probe_stats *out) {
    int ok=1;
    if (software) { for (int i=0;i<2;++i) if (sites[i] && !patch(sites[i],original[i])) ok=0; }
    for (auto &hook:hooks) hook.reset();
    if (veh) {if (!RemoveVectoredExceptionHandler(veh)) ok=0; veh=nullptr;}
    software=false; stepping=-1;
    if (out) *out=stats;
    sites[0]=sites[1]=nullptr; return ok?0:1;
}
extern "C" __declspec(dllexport) int probe_agent_start(const char *mode,void *flag,void *read,const probe_config *cfg) {
    if (sites[0] || !cfg || !flag) return 1;
    config=*cfg; stats={}; owner=GetCurrentThreadId(); sites[0]=flag; sites[1]=read;
    for (int i=0;i<2;++i) if (sites[i] && !report_entry(&local_ops,nullptr,(uint64_t)(uintptr_t)sites[i],i?"read":"flag")) {
        sites[0]=sites[1]=nullptr; return 1;
    }
    if (!std::strcmp(mode,"inline")) {
        hooks[0]=safetyhook::create_mid(flag,[](safetyhook::Context &c){call_mid(c,0);});
        if (read) hooks[1]=safetyhook::create_mid(read,[](safetyhook::Context &c){call_mid(c,1);});
        if (!hooks[0] || (read && !hooks[1])) {probe_agent_stop(nullptr); return 1;}
        return 0;
    }
    if (!std::strcmp(mode,"veh-sw")) {
        /* Single-thread fixture: restore original byte, step one instruction,
           re-arm. This also preserves a pre-existing JMP at the site. */
        for (int i=0;i<2;++i) if (sites[i]) {
            size_t done{};
            if (!local_read(nullptr,(uint64_t)(uintptr_t)sites[i],&original[i],1,&done) || original[i]==0xcc) {
                sites[0]=sites[1]=nullptr; return 1;
            }
        }
        veh=AddVectoredExceptionHandler(1,handler);
        if (!veh) {sites[0]=sites[1]=nullptr; return 1;}
        software=true;
        for (int i=0;i<2;++i) if (sites[i] && !patch(sites[i],0xcc)) {probe_agent_stop(nullptr); return 1;}
        return 0;
    }
    sites[0]=sites[1]=nullptr; return 1;
}
