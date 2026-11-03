#include "win_common.hpp"
#include "agent.h"
#include <vector>
#include <safetyhook.hpp>
using NtRead = LONG (NTAPI *)(HANDLE, const void *, void *, SIZE_T, SIZE_T *);
extern "C" {
    NtRead g_ntread = nullptr;
    probe_config g_config{};
    int FlagCheck(uint32_t *, uint64_t);
    LONG NTAPI ReadThunk(HANDLE, const void *, void *, SIZE_T, SIZE_T *);
    void FlagMemSite(); void FlagRegSite(); void ReadSite();
}
static SafetyHookInline prehook;
static uint64_t prehook_calls=0;
static LONG NTAPI pre_read(HANDLE h,const void *a,void *b,SIZE_T n,SIZE_T *done) {
    ++prehook_calls;
    return prehook.call<LONG>(h,a,b,n,done);
}
struct Hello { uint64_t address; uint32_t pid; uint32_t reserved; };
struct Child {
    PROCESS_INFORMATION pi{}; HANDLE finish{}; Hello hello{};
    ~Child() { if (finish) {SetEvent(finish); WaitForSingleObject(pi.hProcess,5000); CloseHandle(finish);}
        if (pi.hThread) CloseHandle(pi.hThread); if (pi.hProcess) CloseHandle(pi.hProcess); }
    void start() {
        SECURITY_ATTRIBUTES sa{sizeof(sa),nullptr,TRUE}; HANDLE rd{},wr{};
        require(!!CreatePipe(&rd,&wr,&sa,0),"pipe"); SetHandleInformation(rd,HANDLE_FLAG_INHERIT,0);
        finish = CreateEventA(&sa,TRUE,FALSE,nullptr); require(finish != nullptr,"event");
        STARTUPINFOA si{}; si.cb=sizeof(si); si.dwFlags=STARTF_USESTDHANDLES;
        si.hStdOutput=wr; si.hStdError=GetStdHandle(STD_ERROR_HANDLE); si.hStdInput=GetStdHandle(STD_INPUT_HANDLE);
        std::string exe=exe_directory()+"probe_target.exe";
        std::string command="\""+exe+"\" --helper "+std::to_string((uintptr_t)finish);
        BOOL ok=CreateProcessA(exe.c_str(),command.data(),nullptr,nullptr,TRUE,0,nullptr,nullptr,&si,&pi);
        CloseHandle(wr); if (!ok) {CloseHandle(rd); require(false,"helper launch");}
        DWORD got=0; BOOL read=ReadFile(rd,&hello,sizeof(hello),&got,nullptr); CloseHandle(rd);
        require(read && got==sizeof(hello),"helper handshake");
        SetHandleInformation(finish,HANDLE_FLAG_INHERIT,0);
    }
};
int main(int argc,char **argv) try {
    if (argc==3 && !std::strcmp(argv[1],"--helper")) {
        static unsigned char data[256]; for (unsigned i=0;i<256;++i) data[i]=(unsigned char)i;
        Hello h{(uint64_t)(uintptr_t)data,GetCurrentProcessId(),0}; DWORD n{};
        require(!!WriteFile(GetStdHandle(STD_OUTPUT_HANDLE),&h,sizeof(h),&n,nullptr) && n==sizeof(h),"helper write");
        return WaitForSingleObject((HANDLE)(uintptr_t)_strtoui64(argv[2],nullptr,10),120000)==WAIT_OBJECT_0 ? 0:2;
    }
    if (argc!=8) throw std::runtime_error("usage: probe_target MODE micro|reads ITERATIONS noop|filter|mutate|log register|memory WARMUP prehook|clean");
    std::string mode=argv[1], workload=argv[2];
    bool external=mode=="debug-sw" || mode=="debug-hw";
    bool disabled=mode=="disabled";
    bool instrumented=mode!="baseline" && !disabled;
    require(workload=="micro" || workload=="reads","workload");
    uint64_t n=_strtoui64(argv[3],nullptr,10), warmup=_strtoui64(argv[6],nullptr,10);
    require(n>0 && n<=1000000000ULL && warmup<=1000000,"iteration count");
    g_config.callback_kind=callback_kind(argv[4]);
    require(!std::strcmp(argv[5],"register") || !std::strcmp(argv[5],"memory"),"mutation");
    g_config.mutation=!std::strcmp(argv[5],"memory") ? MUTATE_MEMORY:MUTATE_REGISTER;
    Child selected,decoy;
    if (workload=="reads") {selected.start(); decoy.start();
        g_config.selected_handle=(uint64_t)(uintptr_t)selected.pi.hProcess;
        g_config.range_start=selected.hello.address+64; g_config.range_size=32; }
    g_ntread=(NtRead)GetProcAddress(GetModuleHandleA("ntdll.dll"),"NtReadVirtualMemory");
    require(g_ntread!=nullptr,"NtReadVirtualMemory");
    bool existing_hook=!std::strcmp(argv[7],"prehook");
    require(existing_hook || !std::strcmp(argv[7],"clean"),"prehook option");
    if (existing_hook) {
        prehook=safetyhook::create_inline((void *)&ReadThunk,(void *)&pre_read);
        require(!!prehook,"install existing hook");
    }
    HMODULE dll{}; agent_stop_fn stop{};
    if (external) OutputDebugStringA("PROBE_READY");
    else if (instrumented) {
        std::string path=exe_directory()+"probe_agent.dll";
        dll=LoadLibraryA(path.c_str()); require(dll!=nullptr,"load agent");
        auto start=(agent_start_fn)GetProcAddress(dll,"probe_agent_start");
        stop=(agent_stop_fn)GetProcAddress(dll,"probe_agent_stop"); require(start && stop,"agent exports");
        void *flag=(g_config.callback_kind==CALLBACK_MUTATE && g_config.mutation==MUTATE_MEMORY)
            ? (void *)&FlagMemSite:(void *)&FlagRegSite;
        require(start(mode.c_str(),flag,workload=="reads"?(void *)&ReadSite:nullptr,&g_config)==0,"agent install");
    }
    uint64_t enabled=0,success=0,checksum=0;
    auto iteration=[&](uint64_t i,bool measured) {
        uint32_t flag=(disabled || (g_config.callback_kind==CALLBACK_MUTATE && instrumented)) ? 0:1;
        int result=FlagCheck(&flag,i);
        if (result!=0 && result!=1) throw std::runtime_error("unexpected flag value");
        if (!result) return; // disabled execution genuinely skips the read
        if (measured) ++enabled;
        if (workload=="reads") {
            bool other=i%4==2; unsigned offset=i%4==1 ? 128 : (i%4==3 ? 80:64);
            Child &ch=other?decoy:selected; unsigned char buffer[16]{}; SIZE_T bytes=0;
            LONG status=ReadThunk(ch.pi.hProcess,(const void *)(uintptr_t)(ch.hello.address+offset),buffer,sizeof(buffer),&bytes);
            require(status>=0 && bytes==sizeof(buffer),"NtReadVirtualMemory result");
            for (unsigned j=0;j<sizeof(buffer);++j) require(buffer[j]==(unsigned char)(offset+j),"read content");
            if (measured) {++success; checksum+=buffer[0];}
        } else if (measured) checksum+=(uint64_t)result;
    };
    /* Warmup callbacks are deliberately counted; harness validates total n+warmup. */
    for (uint64_t i=0;i<warmup;++i) iteration(i,false);
    uint64_t cpu_begin=process_cpu_ns(GetCurrentProcess());
    LARGE_INTEGER f{},begin{},end{}; QueryPerformanceFrequency(&f); QueryPerformanceCounter(&begin);
    for (uint64_t i=0;i<n;++i) iteration(i,true);
    QueryPerformanceCounter(&end);
    uint64_t cpu_ns=process_cpu_ns(GetCurrentProcess())-cpu_begin;
    static probe_stats stats{};
    if (stop) require(stop(&stats)==0,"agent stop");
    if (dll) FreeLibrary(dll);
    require(enabled==(disabled?0:n),"flag modification failed");
    require(prehook_calls==(existing_hook && workload=="reads" && !disabled?n+warmup:0),"existing hook must execute exactly once per read");
    prehook.reset();
    if (instrumented && !external) {
        require(stats.errors==0,"callback errors");
        require(stats.flag_hits==n+warmup,"flag hit count");
        require(stats.read_hits==(workload=="reads"?n+warmup:0),"read hit count");
    }
    std::printf("{\"kind\":\"target\",\"mode\":\"%s\",\"workload\":\"%s\",\"iterations\":%llu,\"warmup\":%llu,\"elapsed_ns\":%.0f,\"enabled\":%llu,\"successful_reads\":%llu,\"checksum\":%llu,",
        mode.c_str(),workload.c_str(),(unsigned long long)n,(unsigned long long)warmup,
        (double)(end.QuadPart-begin.QuadPart)*1e9/(double)f.QuadPart,
        (unsigned long long)enabled,(unsigned long long)success,(unsigned long long)checksum);
    print_stats(stats);
    std::printf(",\"target_cpu_ns\":%llu",(unsigned long long)cpu_ns);
    std::printf(",\"selected_handle\":%llu,\"range_start\":%llu,\"flag_site\":%llu,",
        (unsigned long long)g_config.selected_handle,(unsigned long long)g_config.range_start,
        (unsigned long long)(uintptr_t)((g_config.callback_kind==CALLBACK_MUTATE && g_config.mutation==MUTATE_MEMORY)?&FlagMemSite:&FlagRegSite));
    std::printf("\"prehook\":%s,\"prehook_calls\":%llu}\n",existing_hook?"true":"false",(unsigned long long)prehook_calls); dump_records(stats); return 0;
} catch (const std::exception &e) {std::fprintf(stderr,"target: %s\n",e.what()); return 1;}
