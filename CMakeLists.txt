cmake_minimum_required(VERSION 3.28)
project(uhh LANGUAGES C CXX)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

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

# probe_app EXPORTS its read site, so tools address it as probe_app.exe!ReadThunk.
add_executable(probe_app examples/targets/probe_app/probe_app.cpp ${READ_SITE_ASM})
target_include_directories(probe_app PRIVATE examples/targets/configparse)
target_link_libraries(probe_app PRIVATE safetyhook)
target_link_options(probe_app PRIVATE ${READ_THUNK_EXPORT} "/MAP:$<TARGET_FILE_DIR:probe_app>/probe_app.map")

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

add_library(probe_api_agent SHARED
    src/probe/agent.cpp
    examples/gated_config/callbacks.cpp
    examples/breakage/breakage_driver.cpp
    examples/frida_parity/frida_parity.cpp
    examples/dynwatch/dynwatch_callbacks.cpp
    examples/trace/trace_callback.cpp
    examples/conformance/conformance_callbacks.cpp
    bench/hitcost/hitcost_callbacks.cpp
    examples/memstress/memstress_callbacks.cpp
    examples/sidefx/sidefx_callbacks.cpp)
target_include_directories(probe_api_agent PRIVATE include examples/gated_config examples/dynwatch examples/trace examples/memstress)
target_link_libraries(probe_api_agent PRIVATE safetyhook)
target_compile_definitions(probe_api_agent PRIVATE BREAKAGE_AGENT_ONLY FRIDA_PARITY_AGENT_ONLY HITCOST_SHARED)
# Undecorated names for the __stdcall agent entries (x86 would otherwise export
# _probe_agent_init@4; the controller resolves them by a fixed bare name).
target_link_options(probe_api_agent PRIVATE "/DEF:${CMAKE_CURRENT_SOURCE_DIR}/src/probe/agent.def")
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

# --- uhh_trace: trace any export of any program (the general CLI) ---------------------
add_executable(uhh_trace examples/trace/uhh_trace.cpp examples/trace/trace_callback.cpp)
target_include_directories(uhh_trace PRIVATE include examples/trace)
target_link_libraries(uhh_trace PRIVATE probe_api)
add_dependencies(uhh_trace probe_api_agent)

# --- conformance: every context method, identical callback, every backend -------------
if(CMAKE_SIZEOF_VOID_P EQUAL 4)
    set(CONF_SP_ASM examples/conformance/conf_sp_x86.asm)
else()
    set(CONF_SP_ASM examples/conformance/conf_sp_x64.asm)
endif()
add_executable(conformance_target examples/conformance/conformance_target.c ${CONF_SP_ASM})
target_link_options(conformance_target PRIVATE "/EXPORT:SpSite")
target_compile_options(conformance_target PRIVATE /Zi)
target_link_options(conformance_target PRIVATE /DEBUG)
add_executable(conformance_driver examples/conformance/conformance_driver.cpp examples/conformance/conformance_callbacks.cpp)
target_include_directories(conformance_driver PRIVATE include)
target_link_libraries(conformance_driver PRIVATE probe_api)
add_dependencies(conformance_driver conformance_target probe_api_agent)

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

add_executable(refusal_driver examples/conformance/refusal_driver.cpp)
target_include_directories(refusal_driver PRIVATE include)
target_link_libraries(refusal_driver PRIVATE probe_api)
add_dependencies(refusal_driver hitcost_target)

foreach(t gated_config_mem patchrace_target refusal_driver sidefx_target sidefx_driver reentrancy_target thread_stress_target antitamper_target antidebug_target exceptions_target memstress_target memstress_driver hitcost_target hitcost_driver logstream_target conformance_target conformance_driver uhh_trace uhh_attach probe_app configparse hook_edge parity_target probe_api probe_api_agent gated_config breakage_driver frida_parity watch_target watch_driver dynwatch_target dynwatch_driver)
    target_compile_definitions(${t} PRIVATE _CRT_SECURE_NO_WARNINGS)
    target_compile_options(${t} PRIVATE $<$<COMPILE_LANGUAGE:CXX>:/W4>)
endforeach()
