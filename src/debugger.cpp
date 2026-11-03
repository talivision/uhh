#include "win_common.hpp"
#include "detect.hpp"
#include <array>
struct Site {uint64_t address{}; unsigned char original{};};
static probe_stats stats;
static bool patch(HANDLE process,uint64_t address,unsigned char byte) {
    DWORD old{},ignored{}; SIZE_T done{};
    if (!VirtualProtectEx(process,(void *)(uintptr_t)address,1,PAGE_EXECUTE_READWRITE,&old)) return false;
    BOOL ok=WriteProcessMemory(process,(void *)(uintptr_t)address,&byte,1,&done);
    BOOL flush=FlushInstructionCache(process,(void *)(uintptr_t)address,1);
    BOOL restore=VirtualProtectEx(process,(void *)(uintptr_t)address,1,old,&ignored);
    return ok && done==1 && flush && restore;
}
/* Export resolver for the controlled executable only. No PDB symbols or
   forwarded exports in this first pass. ASLR handled with remote image base. */
static uint64_t export_address(HMODULE local,uint64_t remote,const char *name) {
    auto p=GetProcAddress(local,name); require(p!=nullptr,"fixture export");
    return remote+(uint64_t)((uintptr_t)p-(uintptr_t)local);
}
int main(int argc,char **argv) {
    PROCESS_INFORMATION pi{}; HANDLE thread{}; HMODULE image{};
    try {
        if (argc!=8) throw std::runtime_error("usage: probe_debugger debug-sw|debug-hw micro|reads N CALLBACK MUTATION WARMUP prehook|clean");
        bool hw=!std::strcmp(argv[1],"debug-hw");
        require(hw || !std::strcmp(argv[1],"debug-sw"),"debugger mode");
        std::string exe=exe_directory()+"probe_target.exe", command="\""+exe+"\"";
        for (int i=1;i<argc;++i) { require(std::strpbrk(argv[i]," \"\\\t\r\n")==nullptr,"argument"); command+=" "; command+=argv[i]; }
        image=LoadLibraryExA(exe.c_str(),nullptr,DONT_RESOLVE_DLL_REFERENCES); require(image!=nullptr,"map fixture exports");
        STARTUPINFOA si{}; si.cb=sizeof(si); si.dwFlags=STARTF_USESTDHANDLES;
        si.hStdOutput=GetStdHandle(STD_OUTPUT_HANDLE); si.hStdError=GetStdHandle(STD_ERROR_HANDLE); si.hStdInput=GetStdHandle(STD_INPUT_HANDLE);
        require(!!CreateProcessA(exe.c_str(),command.data(),nullptr,nullptr,TRUE,DEBUG_ONLY_THIS_PROCESS,nullptr,nullptr,&si,&pi),"debug launch");
        uint64_t base=0; DWORD owner=0,exit_code=1;
        bool installed=false,initial_break=false; int stepping=-1;
        std::array<Site,2> sites{}; probe_config config{};
        DEBUG_EVENT e{};
        for (;;) {
            require(!!WaitForDebugEvent(&e,INFINITE),"wait debug event"); DWORD disposition=DBG_CONTINUE;
            if (e.dwDebugEventCode==CREATE_PROCESS_DEBUG_EVENT) {
                base=(uint64_t)(uintptr_t)e.u.CreateProcessInfo.lpBaseOfImage;
                if(e.u.CreateProcessInfo.hFile) CloseHandle(e.u.CreateProcessInfo.hFile);
            } else if (e.dwDebugEventCode==LOAD_DLL_DEBUG_EVENT) {
                if(e.u.LoadDll.hFile) CloseHandle(e.u.LoadDll.hFile);
            } else if (e.dwDebugEventCode==OUTPUT_DEBUG_STRING_EVENT && !installed) {
                char message[32]{}; SIZE_T got{};
                if (!e.u.DebugString.fUnicode && e.u.DebugString.nDebugStringLength<=sizeof(message)) {
                    ReadProcessMemory(pi.hProcess,e.u.DebugString.lpDebugStringData,message,sizeof(message)-1,&got);
                    if (!std::strcmp(message,"PROBE_READY")) {
                        owner=e.dwThreadId; thread=OpenThread(THREAD_GET_CONTEXT|THREAD_SET_CONTEXT,FALSE,owner);
                        require(thread!=nullptr,"open stopped thread"); size_t bytes{};
                        require(remote_read(pi.hProcess,export_address(image,base,"g_config"),&config,sizeof(config),&bytes) && bytes==sizeof(config),"read config");
                        const char *flag=config.callback_kind==CALLBACK_MUTATE && config.mutation==MUTATE_MEMORY?"FlagMemSite":"FlagRegSite";
                        sites[0].address=export_address(image,base,flag);
                        if (!std::strcmp(argv[2],"reads")) sites[1].address=export_address(image,base,"ReadSite");
                        for (int i=0;i<2;++i) if (sites[i].address) {
                            require(report_entry(&remote_ops,pi.hProcess,sites[i].address,i?"read":"flag"),"inspect site");
                            require(remote_read(pi.hProcess,sites[i].address,&sites[i].original,1,&bytes) && bytes==1,"read original byte");
                            require(sites[i].original!=0xcc,"site already has an INT3");
                        }
                        if (hw) {
                            CONTEXT c{}; c.ContextFlags=CONTEXT_DEBUG_REGISTERS;
                            require(!!GetThreadContext(thread,&c),"get debug registers");
                            require((c.Dr7 & 0xf)==0,"hardware slots 0/1 already in use");
                            c.Dr0=sites[0].address; c.Dr1=sites[1].address;
                            c.Dr7 &= ~((DWORD64)0xff<<16); c.Dr7|=1; if(sites[1].address)c.Dr7|=4;
                            c.Dr6=0; require(!!SetThreadContext(thread,&c),"arm hardware breakpoints");
                        } else for (auto &s:sites) if(s.address) require(patch(pi.hProcess,s.address,0xcc),"arm software breakpoint");
                        installed=true;
                    }
                }
            } else if (e.dwDebugEventCode==EXCEPTION_DEBUG_EVENT) {
                auto &ex=e.u.Exception.ExceptionRecord; DWORD code=ex.ExceptionCode;
                disposition=DBG_EXCEPTION_NOT_HANDLED;
                if (code==EXCEPTION_BREAKPOINT && !installed && !initial_break) {initial_break=true; disposition=DBG_CONTINUE;}
                else if(installed && e.dwThreadId==owner) {
                    CONTEXT c{}; c.ContextFlags=CONTEXT_ALL;
                    if (code==EXCEPTION_SINGLE_STEP && stepping>=0) {
                        require(!!GetThreadContext(thread,&c),"get step context");
                        require(patch(pi.hProcess,sites[stepping].address,0xcc),"re-arm software breakpoint");
                        stepping=-1; c.EFlags &= ~0x100u;
                        require(!!SetThreadContext(thread,&c),"resume after step"); disposition=DBG_CONTINUE;
                    } else if ((hw && code==EXCEPTION_SINGLE_STEP) || (!hw && code==EXCEPTION_BREAKPOINT)) {
                        require(!!GetThreadContext(thread,&c),"get breakpoint context");
                        for (int i=0;i<2;++i) if(sites[i].address &&
                            (hw?c.Rip==(DWORD64)sites[i].address && (c.Dr6 & (1ULL<<i)):
                            (uint64_t)(uintptr_t)ex.ExceptionAddress==sites[i].address)) {
                            if (!hw) {require(patch(pi.hProcess,sites[i].address,sites[i].original),"restore instruction"); c.Rip=sites[i].address;}
                            auto ctx=from_context(c,(uint32_t)(i+1),sites[i].address,&remote_ops,pi.hProcess);
                            ctx.tid=owner; example_callback(&ctx,&config,&stats); to_context(ctx,c);
                            if (hw) {c.Dr6 &= ~3ULL; c.EFlags|=0x10000u;}
                            else {stepping=i; c.EFlags|=0x100u;}
                            require(!!SetThreadContext(thread,&c),"apply callback context"); disposition=DBG_CONTINUE; break;
                        }
                    }
                }
            } else if (e.dwDebugEventCode==EXIT_PROCESS_DEBUG_EVENT) {
                exit_code=e.u.ExitProcess.dwExitCode;
                require(!!ContinueDebugEvent(e.dwProcessId,e.dwThreadId,DBG_CONTINUE),"continue exit");
                require(installed,"target exited before installing probes");
                std::printf("{\"kind\":\"controller\","); print_stats(stats); std::printf(",\"controller_cpu_ns_total\":%llu}\n",(unsigned long long)process_cpu_ns(GetCurrentProcess())); dump_records(stats);
                CloseHandle(thread); CloseHandle(pi.hThread); CloseHandle(pi.hProcess); FreeLibrary(image);
                return (exit_code || stats.errors)?1:0;
            }
            require(!!ContinueDebugEvent(e.dwProcessId,e.dwThreadId,disposition),"continue debug event");
        }
    } catch(const std::exception &e) {
        std::fprintf(stderr,"debugger: %s\n",e.what());
        /* Only this launch-owned fixture is terminated on controller failure. */
        if (pi.hProcess) {TerminateProcess(pi.hProcess,2); CloseHandle(pi.hProcess);}
        if (pi.hThread) CloseHandle(pi.hThread); if(thread)CloseHandle(thread); if(image)FreeLibrary(image);
        return 1;
    }
}
