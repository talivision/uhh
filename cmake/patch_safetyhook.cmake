# Applied to the fetched SafetyHook v0.7.0 source (FetchContent PATCH_COMMAND). Idempotent.
#
# 1. A process-wide switch, uhh_safetyhook_frozen. While the UHH controller (a debugger)
#    holds every other thread of the target suspended, the agent sets it and trap_threads
#    patches with the page kept EXECUTABLE (RWX) and no thread trap. The stock path makes
#    the page non-executable and traps threads that fault on it, which (a) faults on the
#    installer itself when the site shares a page with the routines it calls (ntdll
#    syscall stubs: NtProtectVirtualMemory sits next to NtReadVirtualMemory), and (b)
#    raises access violations a target's own exception handlers can observe.
# 2. MidHook::uhh_trampoline(): the inner inline hook's trampoline (relocated copies of
#    the overwritten instructions), so the controller can move a frozen thread that
#    stopped inside the patch range to the equivalent instruction there.
set(os "${SRC}/src/os.windows.cpp")
file(READ "${os}" text)
if(NOT text MATCHES "uhh_safetyhook_frozen")
  string(REPLACE
"void trap_threads(uint8_t* from, uint8_t* to, size_t len, const std::function<void()>& run_fn) {
"
"} // namespace safetyhook
extern \"C\" volatile long uhh_safetyhook_frozen = 0;
namespace safetyhook {
void trap_threads(uint8_t* from, uint8_t* to, size_t len, const std::function<void()>& run_fn) {
    if (uhh_safetyhook_frozen) {   // UHH: every other thread is suspended by the debugger
        DWORD from_protect = 0, to_protect = 0;
        VirtualProtect(from, len, PAGE_EXECUTE_READWRITE, &from_protect);
        VirtualProtect(to, len, PAGE_EXECUTE_READWRITE, &to_protect);
        if (run_fn) { run_fn(); }
        VirtualProtect(to, len, to_protect, &to_protect);
        VirtualProtect(from, len, from_protect, &from_protect);
        FlushInstructionCache(GetCurrentProcess(), from, len);
        return;
    }
" text "${text}")
  if(NOT text MATCHES "uhh_safetyhook_frozen")
    message(FATAL_ERROR "patch_safetyhook: trap_threads anchor not found")
  endif()
  file(WRITE "${os}" "${text}")
endif()
set(mh "${SRC}/include/safetyhook/mid_hook.hpp")
file(READ "${mh}" text)
if(NOT text MATCHES "uhh_trampoline")
  string(REPLACE
"    [[nodiscard]] const auto& original_bytes() const { return m_hook.m_original_bytes; }"
"    [[nodiscard]] const auto& original_bytes() const { return m_hook.m_original_bytes; }
    [[nodiscard]] uintptr_t uhh_trampoline() const { return m_hook.trampoline().address(); }" text "${text}")
  if(NOT text MATCHES "uhh_trampoline")
    message(FATAL_ERROR "patch_safetyhook: mid_hook.hpp anchor not found")
  endif()
  file(WRITE "${mh}" "${text}")
endif()
