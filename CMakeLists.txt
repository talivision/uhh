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

enable_language(ASM_MASM)
# MASM dialect (ml64 vs ml) follows the generator platform automatically; only the
# fixture .asm variant is selected by pointer width (one file per arch, not IFDEF
# inside a single .asm).
if(CMAKE_SIZEOF_VOID_P EQUAL 4)
    set(APP_SITES_ASM src/app_sites_x86.asm)
    set(FLAG_ASM      src/configparse/flag_x86.asm)
    set(BREAKAGE_ASM  examples/breakage/hook_edge_x86.asm)
    set(PARITY_ASM    examples/frida_parity/parity_sites_x86.asm)
else()
    set(APP_SITES_ASM src/app_sites.asm)
    set(FLAG_ASM      src/configparse/flag.asm)
    set(BREAKAGE_ASM  examples/breakage/hook_edge_x64.asm)
    set(PARITY_ASM    examples/frida_parity/parity_sites_x64.asm)
endif()

include(FetchContent)
set(SAFETYHOOK_BUILD_TEST OFF CACHE BOOL "" FORCE)
set(SAFETYHOOK_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(SAFETYHOOK_BUILD_DOCS OFF CACHE BOOL "" FORCE)
set(SAFETYHOOK_FETCH_ZYDIS ON CACHE BOOL "" FORCE)
FetchContent_Declare(safetyhook GIT_REPOSITORY https://github.com/cursey/safetyhook.git GIT_TAG v0.7.0 GIT_SHALLOW TRUE)
FetchContent_MakeAvailable(safetyhook)

# --- Fixtures: the contrived target the examples instrument -------------------
# Late-loaded config library. Its mid-function flag site is found by RVA from the
# linker map, so emit one. Never a static dependency of probe_app.
add_library(configparse SHARED src/configparse/configparse.c ${FLAG_ASM})
target_include_directories(configparse PUBLIC src)
target_link_options(configparse PRIVATE "/MAP:$<TARGET_FILE_DIR:configparse>/configparse.map")

add_executable(probe_app src/app.cpp ${APP_SITES_ASM})
target_include_directories(probe_app PRIVATE src include)
target_link_libraries(probe_app PRIVATE safetyhook)
target_link_options(probe_app PRIVATE "/MAP:$<TARGET_FILE_DIR:probe_app>/probe_app.map")

# Hostile entry sequences and a real pre-existing E9 detour for the breakage demo.
add_executable(hook_edge examples/breakage/hook_edge.c ${BREAKAGE_ASM})
target_link_options(hook_edge PRIVATE "/MAP:$<TARGET_FILE_DIR:hook_edge>/hook_edge.map")

# Frida-parity demo target: labelled sites exercised by frida_parity.
add_executable(parity_target examples/frida_parity/parity_target.c ${PARITY_ASM})
target_link_options(parity_target PRIVATE "/MAP:$<TARGET_FILE_DIR:parity_target>/parity_target.map")

# --- UHH library: the locked probe_api. External native-bitness INT3 and injected
#     SafetyHook mid-hooks. Builds for both -A x64 and -A Win32. ----------------
add_library(probe_api STATIC src/probe/session.cpp)
target_include_directories(probe_api PUBLIC include)
target_link_libraries(probe_api PRIVATE Zydis)   # decode probe sites for displaced stepping

add_library(probe_api_agent SHARED
    src/probe/agent.cpp
    examples/gated_config/callbacks.cpp
    examples/breakage/breakage_driver.cpp
    examples/frida_parity/frida_parity.cpp
    examples/dynwatch/dynwatch_callbacks.cpp
    examples/trace/trace_callback.cpp)
target_include_directories(probe_api_agent PRIVATE include examples/gated_config examples/dynwatch examples/trace)
target_link_libraries(probe_api_agent PRIVATE safetyhook)
target_compile_definitions(probe_api_agent PRIVATE BREAKAGE_AGENT_ONLY FRIDA_PARITY_AGENT_ONLY)
# Undecorated names for the __stdcall agent entries (x86 would otherwise export
# _probe_agent_init@4; the controller resolves them by a fixed bare name).
target_link_options(probe_api_agent PRIVATE "/DEF:${CMAKE_CURRENT_SOURCE_DIR}/src/probe/agent.def")
set_property(TARGET probe_api_agent APPEND PROPERTY LINK_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/src/probe/agent.def")

# --- Example: gated_config -----------------------------------------------------
# Deferred flag probe (software breakpoint, fires once, flips the parsed flag) mixed
# with an inline read-log probe (SafetyHook mid-hook, millions of hits). Run on
# demand via scripts/check_scenario.py (a heavyweight end-to-end demo, not a CI gate).
add_executable(gated_config
    examples/gated_config/main.cpp
    examples/gated_config/callbacks.cpp)
target_include_directories(gated_config PRIVATE examples/gated_config include)
target_link_libraries(gated_config PRIVATE probe_api)
add_dependencies(gated_config probe_app configparse probe_api_agent)

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

foreach(t uhh_trace probe_app configparse hook_edge parity_target probe_api probe_api_agent gated_config breakage_driver frida_parity watch_target watch_driver dynwatch_target dynwatch_driver)
    target_compile_definitions(${t} PRIVATE _CRT_SECURE_NO_WARNINGS)
    target_compile_options(${t} PRIVATE $<$<COMPILE_LANGUAGE:CXX>:/W4>)
endforeach()
