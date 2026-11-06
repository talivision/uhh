cmake_minimum_required(VERSION 3.28)
project(uhh LANGUAGES C CXX)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
# Static CRT everywhere. probe_api_agent.dll is injected into the TARGET: with /MD it would
# bind to whatever msvcp140/vcruntime140 the target already loaded -- an older app-local
# msvcp140 crashes SafetyHook's std::mutex (constexpr mutex since VS 17.10: _Mtx_* null read).
# The agent must carry its own runtime; everything else follows so libraries link together.
option(UHH_STATIC_CRT "Link UHH's own binaries (the injected agent above all) against the static CRT" ON)
if(UHH_STATIC_CRT)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
else()
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")   # for the oldcrt repro only
endif()

if(NOT WIN32)
    message(FATAL_ERROR "UHH is a Windows user-mode instrumentation library")
endif()
# Accept x64 (-A x64) or x86 (-A Win32); reject ARM64 and non-MSVC. ARM64 is 64-bit
# too, so it is rejected by platform name, not by pointer size.
if(NOT MSVC)
    message(FATAL_ERROR "UHH requires MSVC")
endif()
if(CMAKE_GENERATOR_PLATFORM MATCHES "[Aa][Rr][Mm]" OR CMAKE_SYSTEM_PROCESSOR MATCHES "[Aa][Rr][Mm]")
    message(FATAL_ERROR "UHH supports x64 and x86 only (ARM64 rejected)")
endif()
if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8 AND NOT CMAKE_SIZEOF_VOID_P EQUAL 4)
    message(FATAL_ERROR "UHH requires an x64 or x86 (Win32) target")
endif()

# --- Build speed (no effect on generated code) ---------------------------------------
# Visual Studio generator: compile a project's sources in parallel (/MP), let MSBuild
# schedule cl.exe across projects (MultiToolTask, capped at the core count overall),
# and build independent projects in parallel even under a plain
# `cmake --build build-x64 --config Release` (MSBuild reads Directory.Build.rsp from
# the solution's directory). Ninja (scripts/build.ps1) is parallel by itself.
option(UHH_PARALLEL_MSBUILD "Parallel MSBuild/cl.exe for the Visual Studio generator" ON)
if(CMAKE_GENERATOR MATCHES "^Visual Studio" AND UHH_PARALLEL_MSBUILD)
    add_compile_options($<$<COMPILE_LANGUAGE:C,CXX>:/MP>)
    list(APPEND CMAKE_VS_GLOBALS "UseMultiToolTask=true" "EnforceProcessCountAcrossBuilds=true")
    file(WRITE "${CMAKE_BINARY_DIR}/Directory.Build.rsp" "-maxCpuCount\n")
elseif(EXISTS "${CMAKE_BINARY_DIR}/Directory.Build.rsp")
    file(REMOVE "${CMAKE_BINARY_DIR}/Directory.Build.rsp")
endif()

enable_language(ASM_MASM)
# x86 links use /SAFESEH: every object must declare its exception handlers, and MASM only
# marks an object as SAFESEH-compatible when assembled with /safeseh (LNK2026 otherwise,
# on toolchains that enforce it). Our .asm files register no handlers.
if(CMAKE_SIZEOF_VOID_P EQUAL 4)
    string(APPEND CMAKE_ASM_MASM_FLAGS " /safeseh")
endif()
# MASM dialect (ml64 vs ml) follows the generator platform automatically; only the
# fixture .asm variant is selected by pointer width (one file per arch, not IFDEF
# inside a single .asm).
if(CMAKE_SIZEOF_VOID_P EQUAL 4)
    set(READ_SITE_ASM examples/targets/probe_app/read_site_x86.asm)
    set(PARSE_ASM     examples/targets/configparse/parse_x86.asm)
    set(READ_THUNK_EXPORT "/EXPORT:ReadThunk=_ReadThunk@20" "/EXPORT:OpenThunk=_OpenThunk@16")
    set(BREAKAGE_ASM  examples/breakage/hook_edge_x86.asm)
    set(PARITY_ASM    examples/frida_parity/parity_sites_x86.asm)
    set(LOGSTREAM_EXPORT "/EXPORT:LogSite")    # the x86 linker adds the cdecl underscore itself
else()
    set(READ_SITE_ASM examples/targets/probe_app/read_site_x64.asm)
    set(PARSE_ASM     examples/targets/configparse/parse_x64.asm)
    set(READ_THUNK_EXPORT "/EXPORT:ReadThunk" "/EXPORT:OpenThunk")
    set(BREAKAGE_ASM  examples/breakage/hook_edge_x64.asm)
    set(PARITY_ASM    examples/frida_parity/parity_sites_x64.asm)
    set(LOGSTREAM_EXPORT "/EXPORT:LogSite")
endif()

include(FetchContent)
# Offline by default: SafetyHook (pre-patched) and Zydis/Zycore are vendored in third_party/
# and FetchContent is pointed at them -- no git, no network. UHH_VENDORED_DEPS=OFF fetches
# the same tags from GitHub instead (and applies the SafetyHook patch at fetch time).
option(UHH_VENDORED_DEPS "Build SafetyHook and Zydis from third_party/ (no network)" ON)
if(UHH_VENDORED_DEPS)
    if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/third_party/safetyhook/CMakeLists.txt" OR
       NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/third_party/zydis/dependencies/zycore/CMakeLists.txt")
        message(FATAL_ERROR "UHH_VENDORED_DEPS=ON but third_party/ is incomplete (see third_party/README.md)")
    endif()
    set(FETCHCONTENT_SOURCE_DIR_SAFETYHOOK "${CMAKE_CURRENT_SOURCE_DIR}/third_party/safetyhook" CACHE PATH "" FORCE)
    set(FETCHCONTENT_SOURCE_DIR_ZYDIS "${CMAKE_CURRENT_SOURCE_DIR}/third_party/zydis" CACHE PATH "" FORCE)
else()
    unset(FETCHCONTENT_SOURCE_DIR_SAFETYHOOK CACHE)
    unset(FETCHCONTENT_SOURCE_DIR_ZYDIS CACHE)
endif()
set(ZYDIS_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_MAN OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_DOXYGEN OFF CACHE BOOL "" FORCE)
set(ZYCORE_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(SAFETYHOOK_BUILD_TEST OFF CACHE BOOL "" FORCE)
set(SAFETYHOOK_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(SAFETYHOOK_BUILD_DOCS OFF CACHE BOOL "" FORCE)
set(SAFETYHOOK_FETCH_ZYDIS ON CACHE BOOL "" FORCE)
FetchContent_Declare(safetyhook GIT_REPOSITORY https://github.com/cursey/safetyhook.git GIT_TAG v0.7.0 GIT_SHALLOW TRUE
    PATCH_COMMAND ${CMAKE_COMMAND} -DSRC=<SOURCE_DIR> -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/patch_safetyhook.cmake
    UPDATE_DISCONNECTED TRUE)
FetchContent_MakeAvailable(safetyhook)

# --- Example targets (examples/targets): what gated_config and uhh_attach instrument --
# Late-loaded config library. Its flag site is configparse.dll!ParseConfig+0x16 on both
# arches (fixed by the asm); the map is kept so regress.py can cross-check that offset.
# Never a static dependency of probe_app.
add_library(configparse SHARED examples/targets/configparse/configparse.c ${PARSE_ASM})
target_link_options(configparse PRIVATE
    "/DEF:${CMAKE_CURRENT_SOURCE_DIR}/examples/targets/configparse/configparse.def"
    "/MAP:$<TARGET_FILE_DIR:configparse>/configparse.map")

# oldcrt_target: a /MD app as an OLDER toolset would have built it (no constexpr std::mutex),
# so it runs on an app-local pre-14.40 msvcp140.dll -- regress `oldcrt` (the injected agent
# must not be broken by the target's runtime).
add_executable(oldcrt_target examples/targets/oldcrt/oldcrt_target.cpp)
set_property(TARGET oldcrt_target PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
target_compile_definitions(oldcrt_target PRIVATE _DISABLE_CONSTEXPR_MUTEX_CONSTRUCTOR)

# probe_app EXPORTS its read site, so tools address it as probe_app.exe!ReadThunk.
add_executable(probe_app examples/targets/probe_app/probe_app.cpp ${READ_SITE_ASM})
target_include_directories(probe_app PRIVATE examples/targets/configparse)
target_link_libraries(probe_app PRIVATE safetyhook)
target_link_options(probe_app PRIVATE ${READ_THUNK_EXPORT} "/MAP:$<TARGET_FILE_DIR:probe_app>/probe_app.map")

# Intel CET (hardware shadow stacks): the same target linked /CETCOMPAT, so Windows gives it
# a user shadow stack on CET hardware (Tiger Lake+ / Zen 3+, x64; WoW64 is not enforced),
# and cet_probe, which reports whether this machine actually enforces one (regress `cet-*`).
add_executable(probe_app_cet examples/targets/probe_app/probe_app.cpp ${READ_SITE_ASM})
target_include_directories(probe_app_cet PRIVATE examples/targets/configparse)
target_link_libraries(probe_app_cet PRIVATE safetyhook)
target_link_options(probe_app_cet PRIVATE ${READ_THUNK_EXPORT} /CETCOMPAT)
add_dependencies(probe_app_cet configparse)
add_executable(cet_probe examples/cet/cet_probe.c)
target_link_options(cet_probe PRIVATE /CETCOMPAT)
# cet_smash: positive control for a shadow-stack checker (Intel SDE -cet, regress `cet-sde-*`).
add_executable(cet_smash examples/cet/cet_smash.c)
target_link_options(cet_smash PRIVATE /CETCOMPAT)
set_property(TARGET cet_smash PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")   # a target app

# Hostile entry sequences and a real pre-existing E9 detour for the breakage demo.
add_executable(hook_edge examples/breakage/hook_edge.c ${BREAKAGE_ASM})
target_link_options(hook_edge PRIVATE "/MAP:$<TARGET_FILE_DIR:hook_edge>/hook_edge.map")

# Frida-parity demo target: labelled sites exercised by frida_parity.
add_executable(parity_target examples/frida_parity/parity_target.c ${PARITY_ASM})
target_link_options(parity_target PRIVATE "/MAP:$<TARGET_FILE_DIR:parity_target>/parity_target.map")

# --- UHH library: the locked probe_api. External native-bitness INT3 and injected
#     SafetyHook mid-hooks. Builds for both -A x64 and -A Win32. ----------------
add_library(probe_api STATIC src/probe/session.cpp src/probe/symbols.cpp)
target_include_directories(probe_api PUBLIC include)
target_link_libraries(probe_api PRIVATE Zydis)   # decode probe sites for displaced stepping

# examples/famous: classic Frida / API Monitor / Procmon recipes. Each recipe's callbacks
# are compiled into the agent (inline) and into famous_driver (breakpoint/hw).
set(FAMOUS_CALLBACKS
    examples/famous/heap_tracker/heap_callbacks.cpp
    examples/famous/file_monitor/file_callbacks.cpp
    examples/famous/tls_capture/tls_callbacks.cpp
    examples/famous/loader_rwx/loader_callbacks.cpp
    examples/famous/retval_override/retval_callbacks.cpp)

add_library(probe_api_agent SHARED
    src/probe/agent.cpp
    examples/gated_config/callbacks.cpp
    examples/breakage/breakage_driver.cpp
    examples/frida_parity/frida_parity.cpp
    examples/dynwatch/dynwatch_callbacks.cpp
    examples/trace/trace_callback.cpp
    examples/conformance/conformance_callbacks.cpp
    examples/p2edge/p2edge_callbacks.cpp
    examples/stacks/stacks_callbacks.cpp
    examples/conformance/matrix_callbacks.cpp
    bench/hitcost/hitcost_callbacks.cpp
    examples/memstress/memstress_callbacks.cpp
    examples/sidefx/sidefx_callbacks.cpp
    ${FAMOUS_CALLBACKS}
    examples/edgehunt/edge_callbacks.cpp
    examples/famous/detours_simple/simple_callbacks.cpp
    examples/famous/detours_traceapi/traceapi_callbacks.cpp
    examples/famous/detours_retval/retval_callbacks.cpp
    examples/hunt/hunt_callbacks.cpp
    examples/hunt_callorig/co_callbacks.cpp
    examples/callconv/cc_callbacks.cpp
    examples/lifecycle/lifecycle_callbacks.cpp
    examples/blogs/blog_callbacks.cpp
    examples/latedll/latedll_callbacks.cpp
    examples/ctrlreview/ctrl_callbacks.cpp
    examples/filetrace/callbacks.cpp
    examples/flagflip/callbacks.cpp
    examples/regtrace/callbacks.cpp
    examples/logs_eval/logs_callbacks.cpp
    examples/agent_review/ar_callbacks.cpp
    examples/transparency/tp_callbacks.cpp
    examples/quickstart/my_callbacks.cpp)
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    target_sources(probe_api_agent PRIVATE src/probe/agent_x64.asm)   # uhh_orig_thunk (call_original)
endif()
target_include_directories(probe_api_agent PRIVATE include examples/gated_config examples/dynwatch examples/trace examples/memstress examples/blogs)
target_link_libraries(probe_api_agent PRIVATE safetyhook)
target_compile_definitions(probe_api_agent PRIVATE BREAKAGE_AGENT_ONLY FRIDA_PARITY_AGENT_ONLY HITCOST_SHARED)
# Undecorated names for the __stdcall agent entries (x86 would otherwise export
# _probe_agent_init@4; the controller resolves them by a fixed bare name).
target_link_options(probe_api_agent PRIVATE "/DEF:${CMAKE_CURRENT_SOURCE_DIR}/src/probe/agent.def")
target_link_options(probe_api_agent PRIVATE "/ENTRY:uhh_agent_entry")   # keeps the CRT alive at process exit (agent.cpp)
# CET shadow stacks: a process with the BlockNonCetBinaries policy maps only /CETCOMPAT images
# (no inline backend otherwise). Every `ret` in the agent's own code returns through a real
# call (audited: ROADMAP "BlockNonCetBinaries"; the hook stub ends `pop rsp; jmp`, return_from
# returns through a `ret` at the hit's own return address, relocated calls stay calls under a
# shadow stack). Regress cet-agent-*.
target_link_options(probe_api_agent PRIVATE /CETCOMPAT)
set_property(TARGET probe_api_agent APPEND PROPERTY LINK_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/src/probe/agent.def")

# --- Example: gated_config (launch) and uhh_attach (attach) -------------------------
# Both flip configparse's parsed flag with a breakpoint to enable probe_app's disabled
# read path, map handles to pids at ntdll!NtOpenProcess, and log reads. The callbacks
# (examples/gated_config/callbacks.cpp) are also built into probe_api_agent for inline.
add_executable(gated_config
    examples/gated_config/main.cpp
    examples/gated_config/callbacks.cpp)
target_include_directories(gated_config PRIVATE examples/gated_config include)
target_link_libraries(gated_config PRIVATE probe_api)
add_dependencies(gated_config probe_app configparse probe_api_agent)

# Same, but the flag is flipped in the target's MEMORY (set_mem) instead of a register.
add_executable(gated_config_mem
    examples/gated_config_mem/main.cpp
    examples/gated_config/callbacks.cpp)
target_include_directories(gated_config_mem PRIVATE examples/gated_config include)
target_link_libraries(gated_config_mem PRIVATE probe_api)
add_dependencies(gated_config_mem probe_app configparse probe_api_agent)

add_executable(uhh_attach
    examples/attach/uhh_attach.cpp
    examples/gated_config/callbacks.cpp)
target_include_directories(uhh_attach PRIVATE examples/gated_config include)
target_link_libraries(uhh_attach PRIVATE probe_api)
add_dependencies(uhh_attach probe_app configparse probe_api_agent)

# --- Example: realapps -- the gated_config callbacks on arbitrary real programs ------
add_executable(realapps_driver
    examples/realapps/realapps_driver.cpp
    examples/gated_config/callbacks.cpp)
target_include_directories(realapps_driver PRIVATE examples/gated_config include)
target_link_libraries(realapps_driver PRIVATE probe_api)
add_dependencies(realapps_driver probe_api_agent)

# --- Example: breakage --------------------------------------------------------
# One session per hostile case keeps an expected failed install/crash isolated.
add_executable(breakage_driver examples/breakage/breakage_driver.cpp)
target_include_directories(breakage_driver PRIVATE include)
target_link_libraries(breakage_driver PRIVATE probe_api)
add_dependencies(breakage_driver hook_edge probe_api_agent)

# --- Example: frida_parity (Frida introspection demos on today's API) ----------
add_executable(frida_parity examples/frida_parity/frida_parity.cpp)
target_include_directories(frida_parity PRIVATE include)
target_link_libraries(frida_parity PRIVATE probe_api)
add_dependencies(frida_parity parity_target probe_api_agent)

# --- Example: hardware data watchpoint (break on a memory WRITE; modifies no code) ---
# Demonstrates the one thing inline/trampoline hooking cannot do — observe data access.
add_executable(watch_target examples/watchpoint/watch_target.c)
target_link_options(watch_target PRIVATE "/MAP:$<TARGET_FILE_DIR:watch_target>/watch_target.map")
add_executable(watch_driver examples/watchpoint/watch_driver.cpp)
target_include_directories(watch_driver PRIVATE include)
target_link_libraries(watch_driver PRIVATE probe_api)
add_dependencies(watch_driver watch_target)

# --- Example: dynamic / data-driven watchpoint (malloc-return -> watch the buffer) ---
# A code probe reads a returned pointer and arms a watchpoint on it from inside the
# callback -- runtime composition no fixed probe list can express.
# Uses the real CRT malloc (ucrtbase.dll, dynamic CRT) -- no labels, no linker map.
add_executable(dynwatch_target examples/dynwatch/dynwatch_target.c)
# A PDB so logged stacks show function names and file:line, not just module+offset.
target_compile_options(dynwatch_target PRIVATE /Zi)
target_link_options(dynwatch_target PRIVATE /DEBUG)
add_executable(dynwatch_driver examples/dynwatch/dynwatch_driver.cpp examples/dynwatch/dynwatch_callbacks.cpp)
target_include_directories(dynwatch_driver PRIVATE include examples/dynwatch)
target_link_libraries(dynwatch_driver PRIVATE probe_api)
add_dependencies(dynwatch_driver dynwatch_target probe_api_agent)

# --- child_exp: raw Win32 measurements behind docs/child-processes.md (no UHH) ----------
add_executable(child_exp bench/child_follow/child_exp.cpp)
target_compile_definitions(child_exp PRIVATE _CRT_SECURE_NO_WARNINGS)

# --- uhh_trace: trace any export of any program (the general CLI) ---------------------
add_executable(uhh_trace examples/trace/uhh_trace.cpp examples/trace/trace_callback.cpp)
target_include_directories(uhh_trace PRIVATE include examples/trace)
target_link_libraries(uhh_trace PRIVATE probe_api)
add_dependencies(uhh_trace probe_api_agent)

# --- forwarded target stdout/stderr (ROADMAP D2/F8): partial lines vs live log records --
add_executable(stdout_target examples/targets/stdout/stdout_target.c)
target_compile_definitions(stdout_target PRIVATE _CRT_SECURE_NO_WARNINGS)
add_dependencies(uhh_trace stdout_target)

# --- conformance: every context method, identical callback, every backend -------------
if(CMAKE_SIZEOF_VOID_P EQUAL 4)
    set(CONF_SP_ASM examples/conformance/conf_sp_x86.asm)
else()
    set(CONF_SP_ASM examples/conformance/conf_sp_x64.asm)
endif()
add_executable(conformance_target examples/conformance/conformance_target.c ${CONF_SP_ASM})
target_link_options(conformance_target PRIVATE "/EXPORT:SpSite" "/EXPORT:PmRegHit" "/EXPORT:PmOther")
target_compile_options(conformance_target PRIVATE /Zi)
target_link_options(conformance_target PRIVATE /DEBUG)
add_executable(conformance_driver examples/conformance/conformance_driver.cpp examples/conformance/conformance_callbacks.cpp
               examples/conformance/matrix_callbacks.cpp)
target_include_directories(conformance_driver PRIVATE include)
target_link_libraries(conformance_driver PRIVATE probe_api)
add_dependencies(conformance_driver conformance_target probe_api_agent)
# The conformance probes attached to a running conformance_target (one Intel SDE hosts; regress `cet-sde-*`).
add_executable(cet_sde_driver examples/cet/cet_sde_driver.cpp examples/conformance/conformance_callbacks.cpp
               examples/hunt_callorig/co_callbacks.cpp)
target_include_directories(cet_sde_driver PRIVATE include)
target_link_libraries(cet_sde_driver PRIVATE probe_api)
add_dependencies(cet_sde_driver conformance_target cet_smash probe_api_agent)
target_compile_definitions(cet_sde_driver PRIVATE _CRT_SECURE_NO_WARNINGS)
target_compile_options(cet_sde_driver PRIVATE /W4)

# --- per-hit cost microbenchmark (inline state-save variants etc.) --------------------
add_executable(hitcost_target bench/hitcost/hitcost_target.c)
if(MSVC)
    target_compile_options(hitcost_target PRIVATE /arch:AVX2)
endif()
add_executable(hitcost_driver bench/hitcost/hitcost_driver.cpp bench/hitcost/hitcost_callbacks.cpp)
target_include_directories(hitcost_driver PRIVATE include)
target_link_libraries(hitcost_driver PRIVATE probe_api)
add_dependencies(hitcost_driver hitcost_target probe_api_agent)
add_executable(hitcost_driver_shared bench/hitcost/hitcost_driver.cpp bench/hitcost/hitcost_callbacks.cpp)
target_include_directories(hitcost_driver_shared PRIVATE include)
target_compile_definitions(hitcost_driver_shared PRIVATE HITCOST_SHARED)
target_link_libraries(hitcost_driver_shared PRIVATE probe_api)
add_dependencies(hitcost_driver_shared hitcost_target probe_api_agent)

# --- streaming logs: visible latency and per-thread ordering --------------------------
add_executable(logstream_target examples/targets/logstream/logstream_target.c)
target_compile_options(logstream_target PRIVATE /W4)
target_link_options(logstream_target PRIVATE ${LOGSTREAM_EXPORT})
add_dependencies(uhh_trace logstream_target)

# --- memory read/write at scale (every backend) ------------------------------------------
add_executable(memstress_target examples/memstress/memstress_target.c)
add_executable(memstress_driver examples/memstress/memstress_driver.cpp examples/memstress/memstress_callbacks.cpp)
target_include_directories(memstress_driver PRIVATE include examples/memstress)
target_link_libraries(memstress_driver PRIVATE probe_api)
add_dependencies(memstress_driver memstress_target probe_api_agent)

# --- patch race: threads inside the bytes an inline hook overwrites ----------------------
if(CMAKE_SIZEOF_VOID_P EQUAL 4)
    set(PATCHRACE_ASM examples/targets/patchrace/patchrace_sites_x86.asm)
else()
    set(PATCHRACE_ASM examples/targets/patchrace/patchrace_sites_x64.asm)
endif()
add_executable(patchrace_target examples/targets/patchrace/patchrace_target.c ${PATCHRACE_ASM})
target_link_options(patchrace_target PRIVATE "/EXPORT:RaceSite" "/EXPORT:BranchSite" "/EXPORT:PushfSite")

# --- side-effect transparency: a probe hit leaves no trace on the thread ----------------
if(CMAKE_SIZEOF_VOID_P EQUAL 4)
    set(SIDEFX_ASM examples/sidefx/sidefx_sites_x86.asm)
    set(SIDEFX_SITE_EXPORT "/EXPORT:SideFxSite")   # the x86 linker adds the cdecl underscore itself
else()
    set(SIDEFX_ASM examples/sidefx/sidefx_sites_x64.asm)
    set(SIDEFX_SITE_EXPORT "/EXPORT:SideFxSite")
endif()
add_executable(sidefx_target examples/sidefx/sidefx_target.c ${SIDEFX_ASM})
target_compile_options(sidefx_target PRIVATE $<$<COMPILE_LANGUAGE:C>:/arch:AVX2>)
target_link_options(sidefx_target PRIVATE ${SIDEFX_SITE_EXPORT} "/MAP:$<TARGET_FILE_DIR:sidefx_target>/sidefx_target.map")
add_executable(sidefx_driver examples/sidefx/sidefx_driver.cpp examples/sidefx/sidefx_callbacks.cpp)
target_include_directories(sidefx_driver PRIVATE include)
target_link_libraries(sidefx_driver PRIVATE probe_api)
add_dependencies(sidefx_driver sidefx_target probe_api_agent)

# --- real-world behaviour targets (driven by uhh_trace in the suite) --------------------
foreach(rw reentrancy_target thread_stress_target antitamper_target antidebug_target)
    add_executable(${rw} examples/realworld/${rw}.c)
endforeach()
add_executable(exceptions_target examples/realworld/exceptions_target.cpp)
target_compile_options(exceptions_target PRIVATE /EHs)   # NOT /EHsc: its extern "C" functions throw
# A PDB so stacks and symbol checks resolve these targets' functions.
foreach(rw reentrancy_target thread_stress_target antitamper_target antidebug_target exceptions_target)
    target_compile_options(${rw} PRIVATE /Zi)
    target_link_options(${rw} PRIVATE /DEBUG)
endforeach()

# --- examples/famous: classic instrumentation recipes, one callback source per recipe ------
add_executable(famous_heap_target examples/famous/heap_tracker/heap_target.c)
add_executable(famous_file_target examples/famous/file_monitor/file_target.c)
add_executable(famous_loader_target examples/famous/loader_rwx/loader_target.c)
add_executable(famous_tick_target examples/famous/retval_override/tick_target.c)
add_executable(famous_driver examples/famous/famous_driver.cpp ${FAMOUS_CALLBACKS})
target_include_directories(famous_driver PRIVATE include examples/famous)
target_link_libraries(famous_driver PRIVATE probe_api)
add_dependencies(famous_driver famous_heap_target famous_file_target famous_loader_target famous_tick_target probe_api_agent)

# --- edgehunt: unusual code shapes / argument and memory edge cases, every backend ------
set(EDGE_SITES EdgeRepSite EdgeStosSite EdgeCpuidSite EdgeRdtscSite EdgePushfSite EdgePopfSite
    EdgeRetOnlySite EdgeThunkSite EdgeJumpSite EdgeFaultMidSite EdgeX87Site EdgeLockSite EdgeDualSite
    EdgeReaddA EdgeReaddB)
if(CMAKE_SIZEOF_VOID_P EQUAL 4)
    set(EDGE_ASM examples/edgehunt/edge_sites_x86.asm)
else()
    set(EDGE_ASM examples/edgehunt/edge_sites_x64.asm)
    list(APPEND EDGE_SITES EdgeRipLoadSite EdgeRipCmpSite EdgeRipVecSite EdgeRipStoreSite EdgeSyscallSite EdgeInt2eSite)
endif()
list(TRANSFORM EDGE_SITES PREPEND "/EXPORT:" OUTPUT_VARIABLE EDGE_EXPORTS)
add_executable(edge_target examples/edgehunt/edge_target.c ${EDGE_ASM})
target_link_options(edge_target PRIVATE ${EDGE_EXPORTS} /INCREMENTAL:NO)
target_compile_options(edge_target PRIVATE $<$<COMPILE_LANGUAGE:C>:/Zi>)
target_link_options(edge_target PRIVATE /DEBUG)
add_executable(edge_driver examples/edgehunt/edge_driver.cpp examples/edgehunt/edge_callbacks.cpp)
target_include_directories(edge_driver PRIVATE include)
target_link_libraries(edge_driver PRIVATE probe_api)
add_dependencies(edge_driver edge_target probe_api_agent)

# --- edge-case hunter: concurrency / lifecycle stress under gated_config instrumentation --
add_executable(hunt_target examples/hunt/hunt_target.c)
add_library(hunt_dll SHARED examples/hunt/hunt_dll.c)
add_executable(hunt_driver examples/hunt/hunt_driver.cpp examples/hunt/hunt_callbacks.cpp examples/gated_config/callbacks.cpp)
target_include_directories(hunt_driver PRIVATE include examples/gated_config)
target_link_libraries(hunt_driver PRIVATE probe_api)
add_dependencies(hunt_driver hunt_target hunt_dll probe_api_agent)

# --- lifecycle: attach / detach / re-attach / close / Ctrl+C / controller death (regress `lifecycle-*`) --
add_executable(lifecycle_target examples/lifecycle/lifecycle_target.c)
add_executable(lifecycle_driver examples/lifecycle/lifecycle_driver.cpp examples/lifecycle/lifecycle_callbacks.cpp
    examples/hunt/hunt_callbacks.cpp examples/gated_config/callbacks.cpp)
target_include_directories(lifecycle_driver PRIVATE include examples/gated_config)
target_link_libraries(lifecycle_driver PRIVATE probe_api)
add_dependencies(lifecycle_driver lifecycle_target hunt_dll configparse probe_api_agent)

# --- call_original / return_from edge-case hunt (regress `callorig-hunt`) -----------------
if(CMAKE_SIZEOF_VOID_P EQUAL 4)
    set(CO_ASM examples/hunt_callorig/co_sites_x86.asm)
    set(CO_EXPORTS /EXPORT:CoMidPush /EXPORT:CoPrologue /EXPORT:CoCallPrologue /EXPORT:CoThis)
else()
    set(CO_ASM examples/hunt_callorig/co_sites_x64.asm)
    set(CO_EXPORTS /EXPORT:CoMidPush /EXPORT:CoPrologue /EXPORT:CoCallPrologue)
endif()
add_executable(co_target examples/hunt_callorig/co_target.cpp ${CO_ASM})
target_link_options(co_target PRIVATE ${CO_EXPORTS} /INCREMENTAL:NO)
# /EHs without c: extern "C" originals DO throw here (the caller's catch must not be elided).
target_compile_options(co_target PRIVATE $<$<COMPILE_LANGUAGE:CXX>:/EHc->)
add_executable(co_driver examples/hunt_callorig/co_driver.cpp examples/hunt_callorig/co_callbacks.cpp)
target_include_directories(co_driver PRIVATE include)
target_link_libraries(co_driver PRIVATE probe_api)
add_dependencies(co_driver co_target probe_api_agent)
# Test-only build of the controller library: UHH_TEST_HOOKS compiles in fault-injection points
# (session.cpp, e.g. the controller dying right after it writes an INT3). Linked only into
# co_driver_th (regress `cxlib-*`); nothing shipped uses it.
add_library(probe_api_testhooks STATIC src/probe/session.cpp src/probe/symbols.cpp)
target_include_directories(probe_api_testhooks PUBLIC include)
target_link_libraries(probe_api_testhooks PRIVATE Zydis)
target_compile_definitions(probe_api_testhooks PRIVATE UHH_TEST_HOOKS _CRT_SECURE_NO_WARNINGS)
target_compile_options(probe_api_testhooks PRIVATE $<$<COMPILE_LANGUAGE:CXX>:/W4>)
target_link_options(co_target PRIVATE /EXPORT:CoRepFill /EXPORT:CoRepSite)   # cxlib-reptail
add_executable(co_driver_th examples/hunt_callorig/co_driver.cpp examples/hunt_callorig/co_callbacks.cpp)
target_include_directories(co_driver_th PRIVATE include)
target_link_libraries(co_driver_th PRIVATE probe_api_testhooks)
target_compile_definitions(co_driver_th PRIVATE _CRT_SECURE_NO_WARNINGS)
add_dependencies(co_driver_th co_target probe_api_agent)
add_executable(ar_driver_th examples/agent_review/ar_driver.cpp examples/agent_review/ar_callbacks.cpp)   # regress callfunc-late-trap-*
target_include_directories(ar_driver_th PRIVATE include)
target_link_libraries(ar_driver_th PRIVATE probe_api_testhooks)
target_compile_definitions(ar_driver_th PRIVATE _CRT_SECURE_NO_WARNINGS)
add_dependencies(ar_driver_th ar_target probe_api_agent)

# --- calling conventions: get_func_arg / call_original / return_from per convention (regress `callconv`) --
# ccfix.dll exports one function per x86/x64 convention and argument/return shape (plus an
# incremental-link thunk, a tail-call jmp and an x86 hot-patch prologue); cc_target calls
# each once (x86: through cc_invoke, which measures the bytes the callee popped).
if(CMAKE_SIZEOF_VOID_P EQUAL 4)
    set(CCFIX_ASM examples/callconv/ccfix_x86.asm)
    set(CCT_ASM examples/callconv/cc_target_x86.asm)
    set(CCFIX_EXPORTS /EXPORT:CcHot /EXPORT:CcIlt /EXPORT:CcIltNext /EXPORT:CcTail /EXPORT:CcStd3T /EXPORT:CcJmpDst)
else()
    set(CCFIX_ASM examples/callconv/ccfix_x64.asm)
    set(CCT_ASM examples/callconv/cc_target_x64.asm)
    set(CCFIX_EXPORTS /EXPORT:CcIlt /EXPORT:CcIltNext /EXPORT:CcTail /EXPORT:CcStd3T /EXPORT:CcJmpDst)
endif()
add_library(ccfix SHARED examples/callconv/ccfix.cpp ${CCFIX_ASM})
target_link_options(ccfix PRIVATE ${CCFIX_EXPORTS} /INCREMENTAL:NO /OPT:NOICF)   # no folding of identical bodies (CcCdecl3/CcStd3 on x64)
add_executable(cc_target examples/callconv/cc_target.cpp ${CCT_ASM})
target_link_options(cc_target PRIVATE /EXPORT:CcImpThunk /INCREMENTAL:NO)
target_link_libraries(cc_target PRIVATE ccfix)        # a static import: mapped before the first install round
add_executable(cc_driver examples/callconv/cc_driver.cpp examples/callconv/cc_callbacks.cpp)
target_include_directories(cc_driver PRIVATE include)
target_link_libraries(cc_driver PRIVATE probe_api)
add_dependencies(cc_driver cc_target probe_api_agent)

# --- inline-agent review findings (regress `agent-*`, examples/agent_review) -------------
add_executable(ar_target examples/agent_review/ar_target.cpp)
target_link_options(ar_target PRIVATE /INCREMENTAL:NO)
# /EHs without c: the extern "C" callees DO throw (the catches must not be elided).
target_compile_options(ar_target PRIVATE /EHc-)
add_executable(ar_driver examples/agent_review/ar_driver.cpp examples/agent_review/ar_callbacks.cpp)
target_include_directories(ar_driver PRIVATE include)
target_link_libraries(ar_driver PRIVATE probe_api)
add_dependencies(ar_driver ar_target probe_api_agent)

# --- transparency: a hit is invisible to the program (regress `transparency`) ------------
if(CMAKE_SIZEOF_VOID_P EQUAL 4)
    set(TP_ASM examples/transparency/tp_sites_x86.asm)
    set(TP_EXPORTS /EXPORT:TpMidHit)              # the x86 linker adds the cdecl underscore itself
else()
    set(TP_ASM examples/transparency/tp_sites_x64.asm)
    set(TP_EXPORTS /EXPORT:TpMidHit)
endif()
add_executable(tp_target examples/transparency/tp_target.cpp ${TP_ASM})
# NOICF: every probed function has an identical unprobed twin that must stay separate.
target_link_options(tp_target PRIVATE ${TP_EXPORTS} /INCREMENTAL:NO /OPT:NOICF)
add_executable(tp_driver examples/transparency/tp_driver.cpp examples/transparency/tp_callbacks.cpp)
target_include_directories(tp_driver PRIVATE include)
target_link_libraries(tp_driver PRIVATE probe_api)
add_dependencies(tp_driver tp_target probe_api_agent)

# --- blog replicas: API-monitor scenarios from well-known write-ups (examples/blogs) ----
add_executable(blog_target examples/blogs/blog_target.c)
target_compile_options(blog_target PRIVATE /W4)
add_executable(blog_driver examples/blogs/blog_driver.cpp examples/blogs/blog_callbacks.cpp)
target_include_directories(blog_driver PRIVATE include examples/blogs)
target_link_libraries(blog_driver PRIVATE probe_api)
add_dependencies(blog_driver blog_target probe_api_agent)

# --- p2edge: lifecycle edge cases (threads born during the entry hold, a DLL loaded by a
#     worker thread, hw ONCE / slot reuse / 5th refused) -------------------------------
add_library(p2edge_early SHARED examples/p2edge/p2edge_early.c)    # static import of p2edge_target
add_library(p2edge_late SHARED examples/p2edge/p2edge_late.c)      # LoadLibrary'd by a worker thread
add_executable(p2edge_target examples/p2edge/p2edge_target.c)
target_link_libraries(p2edge_target PRIVATE p2edge_early)
add_dependencies(p2edge_target p2edge_late)
add_executable(p2edge_driver examples/p2edge/p2edge_driver.cpp examples/p2edge/p2edge_callbacks.cpp)
target_include_directories(p2edge_driver PRIVATE include)
target_link_libraries(p2edge_driver PRIVATE probe_api)
add_dependencies(p2edge_driver p2edge_target probe_api_agent)

# --- latedll: probes in DLLs LoadLibrary'd at run time (main thread, worker thread, and a
#     DllMain that loads another DLL, calls probed code and starts a thread under the loader
#     lock); every call counted and logged on every backend (regress `latedll-*`) ----------
add_library(latedll_fix SHARED examples/latedll/latedll_fix.c)
target_link_options(latedll_fix PRIVATE /OPT:NOICF)
add_library(latedll_heavy SHARED examples/latedll/latedll_heavy.c)
add_executable(latedll_target examples/latedll/latedll_target.c)
add_dependencies(latedll_target latedll_fix latedll_heavy)
add_executable(latedll_driver examples/latedll/latedll_driver.cpp examples/latedll/latedll_callbacks.cpp)
target_include_directories(latedll_driver PRIVATE include)
target_link_libraries(latedll_driver PRIVATE probe_api)
add_dependencies(latedll_driver latedll_target probe_api_agent)

# --- stacks: send_log_stack through mid-function, FPO and leaf frames, every backend ------
# Optimised C callers (/Oy on x86: frame-pointer omission) over asm sites of exact shape;
# PDBs so the controller's dbghelp walk has FPO data and frames symbolize.
if(CMAKE_SIZEOF_VOID_P EQUAL 4)
    set(STK_ASM examples/stacks/stk_sites_x86.asm)
    set(STK_OY /Oy)
else()
    set(STK_ASM examples/stacks/stk_sites_x64.asm)
    set(STK_OY "")
endif()
add_executable(stacks_target examples/stacks/stacks_target.c ${STK_ASM})
target_compile_options(stacks_target PRIVATE /Zi $<$<COMPILE_LANGUAGE:C>:/O2> $<$<COMPILE_LANGUAGE:C>:${STK_OY}>)
target_link_options(stacks_target PRIVATE /DEBUG /INCREMENTAL:NO "/MAP:$<TARGET_FILE_DIR:stacks_target>/stacks_target.map")
add_executable(stacks_driver examples/stacks/stacks_driver.cpp examples/stacks/stacks_callbacks.cpp)
target_include_directories(stacks_driver PRIVATE include)
target_link_libraries(stacks_driver PRIVATE probe_api)
add_dependencies(stacks_driver stacks_target probe_api_agent)

# --- controller review fixtures (regress `ctrl-*`, examples/ctrlreview) ------------------
# inplace-* shapes (ctrl_shapes_*.asm): each probed instruction is exported for probe_add_symbol
set(CTRL_SHAPES jmp8 jmp32 jcc8_taken jcc8_not jcc8_alt jcc32_taken call32 callmem ret loop_taken loop_not
    loopz loopnz jrcxz loop_a32 jecxz_a32 pushf pushf_guard segjmp)
if(CMAKE_SIZEOF_VOID_P EQUAL 4)
    set(CTRL_ASM examples/ctrlreview/ctrl_sites_x86.asm examples/ctrlreview/ctrl_shapes_x86.asm)
else()
    set(CTRL_ASM examples/ctrlreview/ctrl_sites_x64.asm examples/ctrlreview/ctrl_shapes_x64.asm)
    list(APPEND CTRL_SHAPES syscall)
endif()
set(CTRL_SHAPE_EXPORTS)
foreach(sh ${CTRL_SHAPES})
    list(APPEND CTRL_SHAPE_EXPORTS /EXPORT:Shape_${sh}_P_Insn)
endforeach()
add_executable(ctrl_target examples/ctrlreview/ctrl_target.cpp ${CTRL_ASM})
target_link_options(ctrl_target PRIVATE /EXPORT:CtrlLoadInsn /EXPORT:CtrlLoopInsn ${CTRL_SHAPE_EXPORTS} /INCREMENTAL:NO)
add_library(ctrl_dll SHARED examples/ctrlreview/ctrl_dll.c)
target_compile_options(ctrl_dll PRIVATE /Zi)
target_link_options(ctrl_dll PRIVATE /DEBUG /INCREMENTAL:NO)
add_executable(ctrl_driver examples/ctrlreview/ctrl_driver.cpp examples/ctrlreview/ctrl_callbacks.cpp)
target_include_directories(ctrl_driver PRIVATE include)
target_link_libraries(ctrl_driver PRIVATE probe_api)
add_dependencies(ctrl_driver ctrl_target ctrl_dll probe_api_agent)
# --- Example: the quickstart's "your own tool" (docs/quickstart.md section 4, regress
# `quickstart-*`). Its callbacks are also in probe_api_agent's source list above (inline).
add_executable(my_tool examples/quickstart/main.cpp examples/quickstart/my_callbacks.cpp)
target_include_directories(my_tool PRIVATE include)
target_link_libraries(my_tool PRIVATE probe_api)
add_dependencies(my_tool probe_api_agent probe_app configparse)

# --- New-app examples (regress `newapp-*`): a tool + its fixture each. Each tool's
# callbacks.cpp is also built into probe_api_agent (inline) -- see its list above.
add_executable(filetrace examples/filetrace/main.cpp examples/filetrace/callbacks.cpp)
add_executable(filetrace_target examples/filetrace/filetrace_target.cpp)
add_executable(flagflip examples/flagflip/main.cpp examples/flagflip/callbacks.cpp)
add_library(flagfeature SHARED examples/flagflip/flagfeature.cpp)
# The flag method is not exported: flagflip finds Feature::IsEnabled in flagfeature.pdb.
target_compile_options(flagfeature PRIVATE /Zi)
target_link_options(flagfeature PRIVATE /DEBUG /INCREMENTAL:NO)
add_executable(flagflip_target examples/flagflip/flagflip_target.cpp)
add_executable(regtrace examples/regtrace/main.cpp examples/regtrace/callbacks.cpp)
add_executable(regtrace_target examples/regtrace/regtrace_target.cpp)
foreach(d filetrace flagflip regtrace)
    target_include_directories(${d} PRIVATE include)
    target_link_libraries(${d} PRIVATE probe_api)
    add_dependencies(${d} ${d}_target probe_api_agent)
endforeach()
add_dependencies(flagflip flagfeature)

add_executable(refusal_driver examples/conformance/refusal_driver.cpp)
target_include_directories(refusal_driver PRIVATE include)
target_link_libraries(refusal_driver PRIVATE probe_api)
add_dependencies(refusal_driver hitcost_target)

# --- famous: Microsoft Detours samples replicated on UHH (examples/famous/detours_*) -----
# One target for all of them; each example's callbacks are also built into the agent DLL.
add_executable(detours_target examples/famous/detours_target.c)
target_link_libraries(detours_target PRIVATE advapi32)
add_executable(detours_simple examples/famous/detours_simple/simple_driver.cpp examples/famous/detours_simple/simple_callbacks.cpp)
add_executable(detours_traceapi examples/famous/detours_traceapi/traceapi_driver.cpp examples/famous/detours_traceapi/traceapi_callbacks.cpp)
add_executable(detours_retval examples/famous/detours_retval/retval_driver.cpp examples/famous/detours_retval/retval_callbacks.cpp)
foreach(d detours_simple detours_traceapi detours_retval)
    target_include_directories(${d} PRIVATE include)
    target_link_libraries(${d} PRIVATE probe_api)
    add_dependencies(${d} detours_target probe_api_agent)
endforeach()

foreach(t tp_target tp_driver latedll_target latedll_fix latedll_heavy latedll_driver stacks_target stacks_driver p2edge_early p2edge_late p2edge_target p2edge_driver blog_target blog_driver gated_config_mem patchrace_target refusal_driver sidefx_target sidefx_driver reentrancy_target thread_stress_target antitamper_target antidebug_target exceptions_target memstress_target memstress_driver hitcost_target hitcost_driver logstream_target conformance_target conformance_driver uhh_trace uhh_attach probe_app configparse hook_edge parity_target probe_api probe_api_agent gated_config breakage_driver frida_parity watch_target watch_driver dynwatch_target dynwatch_driver hunt_target hunt_dll hunt_driver lifecycle_target lifecycle_driver detours_target detours_simple detours_traceapi detours_retval edge_target edge_driver co_target co_driver famous_driver famous_heap_target famous_file_target famous_loader_target famous_tick_target probe_app_cet cet_probe
          filetrace filetrace_target flagflip flagfeature flagflip_target regtrace regtrace_target)
    target_compile_definitions(${t} PRIVATE _CRT_SECURE_NO_WARNINGS)
    target_compile_options(${t} PRIVATE $<$<COMPILE_LANGUAGE:CXX>:/W4>)
endforeach()

# Example TARGETS stand in for ordinary applications, so they keep the usual dynamic CRT
# (/MD: ucrtbase!malloc etc. are real imports that probes can hit). Only UHH's own
# binaries -- above all the agent injected into those targets -- carry the static CRT.
# probe_app/probe_app_cet link SafetyHook (their --existing-hook mode) and follow UHH.
foreach(t configparse cet_probe hook_edge parity_target watch_target dynwatch_target conformance_target
          hitcost_target logstream_target memstress_target patchrace_target sidefx_target
          reentrancy_target thread_stress_target antitamper_target antidebug_target exceptions_target
          famous_heap_target famous_file_target famous_loader_target famous_tick_target edge_target detours_target co_target
          hunt_target hunt_dll lifecycle_target blog_target p2edge_target p2edge_early p2edge_late
          latedll_target latedll_fix latedll_heavy
          stacks_target filetrace_target flagfeature flagflip_target regtrace_target stdout_target tp_target)
    set_property(TARGET ${t} PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
endforeach()

# --- adversarial log delivery (regress `logs-*`) --------------------------------------
add_executable(logs_target examples/logs_eval/logs_target.cpp)
target_include_directories(logs_target PRIVATE include)
target_link_options(logs_target PRIVATE /INCREMENTAL:NO)
add_executable(logs_driver examples/logs_eval/logs_driver.cpp examples/logs_eval/logs_callbacks.cpp)
target_include_directories(logs_driver PRIVATE include)
target_link_libraries(logs_driver PRIVATE probe_api)
add_dependencies(logs_driver logs_target probe_api_agent)
