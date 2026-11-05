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
# 3. Mid-hook resume without `ret` (Intel CET shadow stacks + a writable context rsp).
#    The stock stub ends `lea rsp,[rsp+8]; pop rsp; ret`: it returns to the trampoline
#    through an address it PUSHED (never CALLed), which is a shadow-stack violation (#CP)
#    on every hit in a /CETCOMPAT process, and the only way to move the stack pointer was
#    to plant that address below the new sp (trampoline_rsp), which overwrote the saved
#    registers when sp moved down. Patched stub ends `pop rsp; jmp [trampoline]`: rsp is
#    loaded from the context's rsp slot (so Context::rsp / esp is WRITABLE and is the sp
#    the hooked code resumes with) and control reaches the trampoline by a jump, which the
#    shadow stack does not track. x64: same 7 bytes (jmp [rip+8] -> the trampoline slot).
#    x86: one byte longer (jmp [abs32], relocated like the stub's other absolute operands).
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
set(mc "${SRC}/src/mid_hook.cpp")
file(READ "${mc}" text)
if(NOT text MATCHES "uhh_resume_jmp")
  # x64 (Windows and Linux variants): lea rsp,[rsp+8]; pop rsp; ret -> pop rsp; jmp [rip+8]
  string(REPLACE "0x5D, 0x48, 0x8D, 0x64, 0x24, 0x08,\n    0x5C, 0xC3,"
                 "0x5D, 0x5C, 0xFF, 0x25, 0x08, 0x00,\n    0x00, 0x00," text "${text}")
  # x86: lea esp,[esp+4]; pop esp; ret -> pop esp; jmp [abs32]  (171 -> 172 bytes)
  string(REPLACE "0x5D, 0x8D, 0x64, 0x24, 0x04, 0x5C, 0xC3, 0x00,\n    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};"
                 "0x5D, 0x5C, 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,\n    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};" text "${text}")
  string(REPLACE "constexpr std::array<uint8_t, 171> asm_data" "constexpr std::array<uint8_t, 172> asm_data" text "${text}")
  string(REPLACE "    store(m_stub.data() + 0x59, m_stub.data() + m_stub.size() - 8);\n"
"    store(m_stub.data() + 0x59, m_stub.data() + m_stub.size() - 8);
    store(m_stub.data() + sizeof(asm_data) - 12, m_stub.data() + m_stub.size() - 4); // uhh_resume_jmp: jmp [trampoline]
" text "${text}")
  string(REPLACE "namespace safetyhook {\n\n#if SAFETYHOOK_ARCH_X86_64"
"namespace safetyhook {

// UHH (uhh_resume_jmp): the stubs below resume with `pop rsp; jmp [trampoline]` instead of
// `lea rsp,[rsp+8]; pop rsp; ret` -- no ret to a pushed address (CET shadow stacks), and the
// context's rsp/esp is the stack pointer the hooked code resumes with.
#if SAFETYHOOK_ARCH_X86_64" text "${text}")
  string(REGEX MATCHALL "0x5C, 0xFF, 0x25" n "${text}")
  list(LENGTH n count)
  if(NOT count EQUAL 3 OR NOT text MATCHES "uhh_resume_jmp: jmp" OR NOT text MATCHES "uint8_t, 172>" OR NOT text MATCHES "UHH \\(uhh_resume_jmp\\)")
    message(FATAL_ERROR "patch_safetyhook: mid_hook.cpp resume-stub anchors not found (${count}/3)")
  endif()
  file(WRITE "${mc}" "${text}")
endif()
set(ctx "${SRC}/include/safetyhook/context.hpp")
file(READ "${ctx}" text)
if(NOT text MATCHES "UHH: writable")
  string(REPLACE "/// @note rsp is read-only. Modifying it will have no effect. Use trampoline_rsp to modify rsp if needed but make sure\n/// the top of the stack is the rip you want to resume at."
                 "/// @note UHH: writable. rsp is the stack pointer the hooked code resumes with (the stub ends\n/// `pop rsp; jmp [trampoline]`); trampoline_rsp and rip are not used to resume." text "${text}")
  string(REPLACE "/// @note esp is read-only. Modifying it will have no effect. Use trampoline_esp to modify esp if needed but make sure\n/// the top of the stack is the eip you want to resume at."
                 "/// @note UHH: writable. esp is the stack pointer the hooked code resumes with (the stub ends\n/// `pop esp; jmp [trampoline]`); trampoline_esp and eip are not used to resume." text "${text}")
  if(NOT text MATCHES "UHH: writable. rsp" OR NOT text MATCHES "UHH: writable. esp")
    message(FATAL_ERROR "patch_safetyhook: context.hpp anchors not found")
  endif()
  file(WRITE "${ctx}" "${text}")
endif()
# The .asm files are the documented source of the byte arrays (not assembled by the build).
foreach(pair "x86_64-windows.asm|rsp|qword|8|rel " "x86_64-linux.asm|rsp|qword|8|rel " "x86_32.asm|esp|dword|4|")
  string(REPLACE "|" ";" pair "${pair}")
  list(GET pair 0 f)
  list(GET pair 1 r)
  list(GET pair 2 w)
  list(GET pair 3 k)
  list(LENGTH pair plen)
  set(rel "")
  if(plen GREATER 4)
    list(GET pair 4 rel)
  endif()
  set(af "${SRC}/src/mid_hook.${f}")
  if(EXISTS "${af}")
    file(READ "${af}" text)
    if(NOT text MATCHES "uhh_resume_jmp")
      string(REPLACE "lea ${r}, [${r}+${k}] ; skip original ${r}\npop ${r}\nret\n"
                     "pop ${r} ; uhh_resume_jmp: the context's ${r} (writable)\njmp ${w} [${rel}trampoline] ; no ret: CET shadow stacks\n" text "${text}")
      if(NOT text MATCHES "uhh_resume_jmp")
        message(FATAL_ERROR "patch_safetyhook: ${f} anchor not found")
      endif()
      file(WRITE "${af}" "${text}")
    endif()
  endif()
endforeach()
