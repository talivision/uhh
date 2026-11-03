# x86 (32-bit) and WoW64 support plan

Status: plan only, 2026-11-04. Drives the port; builds nothing.

Goal: the gated scenario from `plan-v2.md` (deferred breakpoint at
`configparse.dll` `ParsedFlagSite` that flips `reads_enabled` 0->1; inline logging
of multithreaded `NtReadVirtualMemory` through `ReadSite`; `NtOpenProcess`
handle->pid map) must **build and be verified on BOTH x86 and x64**. The LOCKED
API in `docs/api-sketch.md` is gospel: `probe_arg(c,i)`, `probe_reg`/`probe_set_reg`
with `PROBE_REG_*` ids, `probe_retval`, `probe_read`/`probe_write`, the single
`void callback(probe_context *c)` shape, and config-copy semantics do not change.
Only the *implementation under* that API becomes arch-parameterized.

---

## 0. Two cases, kept strictly separate

We implement and verify in this order. Do **not** conflate a Windows `CONTEXT`
(one thread's register image) with "a CPU image across the WoW64 boundary".

### Case (a) — 32-bit-native: x86 controller debugging an x86 target. FIRST.

Everything is one bitness. The controller (`probe_debugger`/`probe_session`), the
agent DLL (`probe_agent`), and the target (`probe_target`/`probe_app`,
`configparse.dll`) are all **x86**.

Why (a) is simpler:
- The debugger uses the ordinary `GetThreadContext`/`SetThreadContext` with the
  **32-bit `CONTEXT`** (it has `Eax..Edi`, `Eip`, `Esp`, `EFlags`, `Dr0..Dr7`).
  No `Wow64*` calls, no second ntdll.
- `ReadProcessMemory`/`WriteProcessMemory` operate in a flat 32-bit address space;
  pointer width matches on both sides.
- Breakpoint exceptions arrive as the normal `EXCEPTION_BREAKPOINT` (0x80000003)
  and `EXCEPTION_SINGLE_STEP` (0x80000004) — *no* `STATUS_WX86_*` codes.
- The injected agent is an x86 DLL inside an x86 process — SafetyHook's `Context32`
  applies directly.
- `ntdll.dll` is the single, native, 32-bit `C:\Windows\System32\ntdll.dll`
  (from the 32-bit process's view). One module to resolve.

### Case (b) — true WoW64: x64 controller debugging a 32-bit (WoW64) target. SECOND.

The **controller is x64**; the **target is 32-bit** running under WoW64. What (b)
adds on top of (a):
- **Context access must use `Wow64GetThreadContext`/`Wow64SetThreadContext`** with
  a `WOW64_CONTEXT` (the 32-bit register image). The *native* `GetThreadContext`
  on a WoW64 thread returns the 64-bit wow64cpu transition state, **not** the
  32-bit app registers — using it is the classic "CONTEXT struct confusion" bug.
- **WoW64 debug-event codes**: a 64-bit debugger receives `STATUS_WX86_BREAKPOINT`
  (0x4000001F) instead of `EXCEPTION_BREAKPOINT`, and `STATUS_WX86_SINGLE_STEP`
  (0x4000001E) instead of `EXCEPTION_SINGLE_STEP`, for exceptions raised by 32-bit
  code. Our exception dispatch must accept **both** the native and the WX86 codes.
- **Two ntdlls, two breakpoints at startup**: the WoW64 process maps both the
  64-bit `System32\ntdll.dll` and the 32-bit `SysWOW64\ntdll.dll`. At startup the
  64-bit ntdll raises one normal breakpoint, then the 32-bit ntdll raises a
  `STATUS_WX86_BREAKPOINT`. The `NtReadVirtualMemory`/`NtOpenProcess` the 32-bit
  app calls live in **`SysWOW64\ntdll.dll`** — location resolution MUST pick that
  image, not `System32\ntdll.dll`.
- **Hardware DR registers** must be programmed through `WOW64_CONTEXT.Dr0..Dr7`,
  not the native 64-bit `CONTEXT.Dr*` of the same thread.
- Addresses are 32-bit values carried in 64-bit fields (`ExceptionAddress`,
  `lpBaseOfImage` are `PVOID`/64-bit but hold `<= 0xFFFFFFFF`). `ReadProcessMemory`
  from the x64 controller reads the 32-bit space fine (truncate/zero-extend
  deliberately, never sign-extend).

**Key framing that collapses (b)'s scope:** a 64-bit DLL **cannot** be loaded into
a 32-bit process, so the *inline* agent for a WoW64 target is itself a **32-bit
DLL** — byte-for-byte the same agent as case (a). Therefore WoW64 adds complexity
**only to the external-debugger path** (the x64 controller reading/writing a 32-bit
thread's context). The inline path is shared between (a) and (b). Build the 32-bit
agent once in (a); reuse it in (b).

---

## 1. Register ABI: arch-parameterized `probe_regs`

Current `probe.h` hardcodes x64:

```c
typedef struct probe_regs {
    uint64_t rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp;
    uint64_t r8, r9, r10, r11, r12, r13, r14, r15, pc, flags;
} probe_regs;
```

### 1a. New shape

Keep the callback source identical across arches by exposing **logical register
ids** and a flat, zero-extended `uint64_t` store, plus an arch tag and an
availability mask. This satisfies the LOCKED `probe_reg(c, PROBE_REG_*)` API and
the Codex review item #4 ("logical overlapping IDs such as `PROBE_REG_AX`, checked
reads/writes, explicit x86/x64 width semantics").

```c
typedef enum probe_arch { PROBE_ARCH_X86 = 1, PROBE_ARCH_X64 = 2 } probe_arch;

typedef enum probe_reg_id {
    PROBE_REG_AX, PROBE_REG_BX, PROBE_REG_CX, PROBE_REG_DX,
    PROBE_REG_SI, PROBE_REG_DI, PROBE_REG_BP, PROBE_REG_SP,
    PROBE_REG_PC, PROBE_REG_FLAGS,                 /* available on both arches */
    PROBE_REG_R8,  PROBE_REG_R9,  PROBE_REG_R10, PROBE_REG_R11,
    PROBE_REG_R12, PROBE_REG_R13, PROBE_REG_R14, PROBE_REG_R15, /* x64 only   */
    PROBE_REG_COUNT
} probe_reg_id;

typedef struct probe_regs {
    uint64_t v[PROBE_REG_COUNT]; /* zero-extended values, indexed by probe_reg_id */
} probe_regs;

struct probe_context {
    probe_regs  regs;
    const probe_ops *ops;
    void       *backend;
    uint32_t    tid, site;
    uint8_t     arch;          /* probe_arch */
    uint8_t     reg_width;     /* 4 on x86, 8 on x64 (GPR width)              */
    uint32_t    reg_avail;     /* bitmask over probe_reg_id of valid regs     */
    /* entry-arg cache for PROBE_AT_RETURN probes (see section 3)             */
    uint64_t    entry_args[8];
    uint8_t     entry_argc;
};
```

`probe_reg(c,id)`: `if (!(c->reg_avail & (1u<<id))) return UNSUPPORTED/0;` else
return `c->regs.v[id]` (already zero-extended on x86). `probe_set_reg` writes
`c->regs.v[id]` and, on x86, masks to 32 bits; writing `PROBE_REG_R8..R15` on x86
returns UNSUPPORTED and mutates nothing. `PROBE_REG_AX` therefore reads `RAX`
(64-bit) on x64 and `EAX` (32-bit, zero-extended) on x86 from the *same callback
source* — which is exactly why the gospel `enable_reads` callback
(`probe_reg(c, PROBE_REG_AX)` / `probe_set_reg(c, PROBE_REG_AX, 1)`) works
unchanged on both. The x86 fixture `flag.asm` variant MUST keep the parsed value
in `EAX` at `ParsedFlagSite` to preserve that (section 7).

`PROBE_REG_PC`/`PROBE_REG_SP`/`PROBE_REG_FLAGS` map to `Rip/Rsp/EFlags` vs
`Eip/Esp/EFlags`. Keep the current contract that PC/SP are observational
(read-only) unless a backend explicitly supports relocation.

### 1b. `from_context` / `to_context` become arch-parameterized

`win_common.hpp` currently has one macro and two functions bound to x64 `CONTEXT`.
Replace the single `PROBE_GPRS` with per-arch mapping macros and overloads keyed
by the register-image type:

```c
/* x64: Windows CONTEXT -> logical ids */
#define PROBE_MAP_X64(X) \
    X(PROBE_REG_AX,Rax) X(PROBE_REG_BX,Rbx) X(PROBE_REG_CX,Rcx) X(PROBE_REG_DX,Rdx) \
    X(PROBE_REG_SI,Rsi) X(PROBE_REG_DI,Rdi) X(PROBE_REG_BP,Rbp) X(PROBE_REG_SP,Rsp) \
    X(PROBE_REG_R8,R8) X(PROBE_REG_R9,R9) X(PROBE_REG_R10,R10) X(PROBE_REG_R11,R11) \
    X(PROBE_REG_R12,R12) X(PROBE_REG_R13,R13) X(PROBE_REG_R14,R14) X(PROBE_REG_R15,R15)

/* x86: 32-bit CONTEXT or WOW64_CONTEXT -> logical ids (SAME field names) */
#define PROBE_MAP_X86(X) \
    X(PROBE_REG_AX,Eax) X(PROBE_REG_BX,Ebx) X(PROBE_REG_CX,Ecx) X(PROBE_REG_DX,Edx) \
    X(PROBE_REG_SI,Esi) X(PROBE_REG_DI,Edi) X(PROBE_REG_BP,Ebp) X(PROBE_REG_SP,Esp)
```

- `from_context(CONTEXT&, ...)` compiled for **x86** uses `PROBE_MAP_X86`, sets
  `pc = Eip`, `flags = EFlags`, `arch=PROBE_ARCH_X86`, `reg_width=4`,
  `reg_avail` = the 10 common ids only.
- `from_context(CONTEXT&, ...)` compiled for **x64** uses `PROBE_MAP_X64`, `pc=Rip`,
  `arch=PROBE_ARCH_X64`, `reg_width=8`, all 18 ids available.
- Add `from_context(WOW64_CONTEXT&, ...)` / `to_context(..., WOW64_CONTEXT&)`
  (x64 build only), identical field names to the 32-bit `CONTEXT`, producing an
  `arch=PROBE_ARCH_X86` context. This is what the x64 controller uses for a WoW64
  target. Note `WOW64_CONTEXT` is available regardless of controller bitness in
  the SDK, but the `Wow64*ThreadContext` APIs exist only in a 64-bit process.

Because the 32-bit `CONTEXT` and `WOW64_CONTEXT` share member names (`Eax`,
`Eip`, `Esp`, `Dr0`...), the x86-native path and the WoW64 path reuse
`PROBE_MAP_X86` — only the SDK type and the Get/Set call differ.

---

## 2. `probe_arg(c, i)`: calling conventions

`probe_arg` is arch-neutral at the callback source; the backend fills it per ABI.

### 2a. x64 (already in use) — register-based

ntdll `Nt*` stubs use the standard x64 convention: integer args in
`RCX, RDX, R8, R9`, then the stack. At function entry
(`[RSP]` = return address, `[RSP+0x08..0x20]` = 32-byte caller shadow space):

| i | reg/slot |
|---|----------|
| 0 | RCX |
| 1 | RDX |
| 2 | R8 |
| 3 | R9 |
| 4 | `[RSP+0x28]` |
| 5 | `[RSP+0x30]` |

So `probe_arg(c,i)` on x64 for `i<4` returns `probe_reg(c, PROBE_REG_CX/DX/R8/R9)`;
for `i>=4` reads 8 bytes at `RSP + 0x28 + 8*(i-4)` via `probe_read`.

### 2b. x86 — `__stdcall`, ALL args on the stack

Windows `Nt*` stubs are `__stdcall`. At function entry
(`[ESP]` = return address, args pushed right-to-left so arg0 is lowest):

| slot | contents |
|------|----------|
| `[ESP+0x00]` | return address |
| `[ESP+0x04]` | arg0 |
| `[ESP+0x08]` | arg1 |
| `[ESP+0x0C]` | arg2 |
| `[ESP+0x10]` | arg3 |
| `[ESP+0x14]` | arg4 |

`probe_arg(c,i)` on x86 = read **4 bytes** (never 8 — reading 8 straddles into the
next arg; see risks) at `ESP + 4 + 4*i`, via `probe_read(c, sp+4+4*i, &u32, 4)`,
zero-extended into `uint64_t`. `ESP` comes from `PROBE_REG_SP`.

**Critical: this offset is only valid at the *untouched* call frame** — i.e. at
true function entry before any prologue adjusts ESP, or at a site reached with the
frame still pristine. Our fixture `ReadSite`/`ReadThunk` is a thunk whose sled sits
*before* any stack manipulation and *before* the `jmp`, so `ESP` is pristine and
`[ESP+4+4*i]` holds the forwarded args — correct. For a SafetyHook mid-hook, use
`Context32.esp` (the captured target ESP), not the trampoline ESP.

### 2c. Exact target signatures and x86 slots

`NtReadVirtualMemory` (5 args, `__stdcall`, args pop = 20 bytes -> `@20`):

```c
NTSTATUS NtReadVirtualMemory(
    HANDLE  ProcessHandle,    /* arg0 */
    PVOID   BaseAddress,      /* arg1 */
    PVOID   Buffer,           /* arg2 */
    SIZE_T  NumberOfBytes,    /* arg3  (SIZE_T = 4 bytes on x86, 8 on x64) */
    PSIZE_T NumberOfBytesRead /* arg4 */
);
```

x86 slots: ProcessHandle `[ESP+0x04]`, BaseAddress `[ESP+0x08]`, Buffer
`[ESP+0x0C]`, NumberOfBytes `[ESP+0x10]`, NumberOfBytesRead `[ESP+0x14]`. The
gospel `log_read` uses `probe_arg(c,0)` (handle) and `probe_arg(c,3)` (size) —
these map to `[ESP+4]` and `[ESP+0x10]` on x86, and to `RCX`/`R9` on x64.

`NtOpenProcess` (4 args, `__stdcall`, `@16`):

```c
NTSTATUS NtOpenProcess(
    PHANDLE            ProcessHandle,   /* arg0  OUT */
    ACCESS_MASK        DesiredAccess,   /* arg1 */
    POBJECT_ATTRIBUTES ObjectAttributes,/* arg2 */
    PCLIENT_ID         ClientId         /* arg3 */
);
```

x86 slots: `[ESP+0x04]`, `[ESP+0x08]`, `[ESP+0x0C]`, `[ESP+0x10]`. The gospel
`note_open` reads `probe_arg(c,0)` (PHANDLE out ptr) and `probe_arg(c,3)`
(PCLIENT_ID); on return it dereferences them with `probe_read`. `CLIENT_ID` is
`{ HANDLE UniqueProcess; HANDLE UniqueThread; }` — `UniqueProcess` is the pid,
4 bytes on x86, 8 on x64. The callback already reads `sizeof(uint64_t)` into `pid`
from `pclient`; on x86 read **4 bytes** then zero-extend (do not read 8, which
would pull in `UniqueThread`).

### 2d. Return probes (`PROBE_AT_RETURN`) — entry-arg capture, both arches

At function return the argument registers (x64 `RCX/RDX/R8/R9`) are clobbered and
the x86 stack args are **already popped** by `ret N` (`__stdcall` is callee-clean).
So `probe_arg(c,i)` on a return probe MUST read from a **cached snapshot taken at
entry**, not from live registers/stack. The backend captures `entry_args[0..argc]`
when the entry fires and surfaces them through `probe_arg` at return;
`probe_retval(c)` returns `PROBE_REG_AX` (`EAX`/`RAX`, NTSTATUS in the low 32
bits). This is what `note_open` relies on ("entry args are captured and readable,
retval is the NTSTATUS"). The entry-capture count comes from the probe
registration (how many args the callback will ask for).

---

## 3. CONTEXT handling per case

| aspect | (a) x86-native | (b) WoW64 (x64 controller) |
|---|---|---|
| register image type | 32-bit `CONTEXT` | `WOW64_CONTEXT` |
| get/set | `GetThreadContext`/`SetThreadContext` | `Wow64GetThreadContext`/`Wow64SetThreadContext` |
| control-flags const | `CONTEXT_ALL`/`CONTEXT_CONTROL` (i386) | `WOW64_CONTEXT_ALL`/`WOW64_CONTEXT_CONTROL` |
| debug regs | `CONTEXT_DEBUG_REGISTERS`, `Dr0..Dr7` (DWORD) | `WOW64_CONTEXT_DEBUG_REGISTERS`, `WOW64_CONTEXT.Dr0..Dr7` |
| PC / SP fields | `Eip` / `Esp` | `Eip` / `Esp` |
| bp exception code | `EXCEPTION_BREAKPOINT` | `STATUS_WX86_BREAKPOINT` (0x4000001F) |
| single-step code | `EXCEPTION_SINGLE_STEP` | `STATUS_WX86_SINGLE_STEP` (0x4000001E) |
| image base (from `CREATE_PROCESS_DEBUG_EVENT`) | 32-bit base, 32-bit value | 32-bit base in a 64-bit `lpBaseOfImage` field |
| memory | `RPM`/`WPM`, 32-bit addrs | `RPM`/`WPM` from x64 handle, 32-bit addrs (zero-extend) |

Code-level changes to `debugger.cpp`:
- Replace the x64-only `CONTEXT c; c.ContextFlags=CONTEXT_...; GetThreadContext`
  and all `c.Rip`/`c.Rsp`/`c.Dr*` accesses with an arch abstraction:
  a small `struct ThreadCtx` that wraps either (a) a 32-bit `CONTEXT` + the normal
  Get/Set, or (b) a `WOW64_CONTEXT` + `Wow64*ThreadContext`, exposing `pc()`,
  `set_pc()`, `sp()`, `flags()`, `set_tf()`, `dr(i)`, `set_dr7()`. For x64-native
  targets keep the existing 64-bit `CONTEXT` path.
- Detect the target bitness once at `CREATE_PROCESS_DEBUG_EVENT`:
  `IsWow64Process2(pi.hProcess, &procMachine, &nativeMachine)` — if
  `procMachine == IMAGE_FILE_MACHINE_I386` the target is 32-bit (WoW64 when the
  controller is x64). Choose the `ThreadCtx` variant from that.
- In the exception handler, accept the WX86 codes:
  `code==EXCEPTION_BREAKPOINT || code==STATUS_WX86_BREAKPOINT` for INT3 hits, and
  `code==EXCEPTION_SINGLE_STEP || code==STATUS_WX86_SINGLE_STEP` for the re-arm
  step. Compare `ExceptionAddress` as the pointer-sized value it is (32-bit value
  on a WoW64 target).
- Swallow the extra startup breakpoint: on a WoW64 target expect the native
  `EXCEPTION_BREAKPOINT` from 64-bit ntdll **and** the `STATUS_WX86_BREAKPOINT`
  from 32-bit ntdll before installing probes; treat the WX86 initial breakpoint as
  the "ready" point for 32-bit code, not the 64-bit one.

For the x86-native controller (case a), none of the `Wow64*` machinery exists or
is needed — compile that path out; the 32-bit `CONTEXT` is the whole story.

---

## 4. Breakpoint backend (INT3 + single-step re-arm; hardware DR)

- **INT3 is one byte (0xCC) on both arches** — `patch()` in `debugger.cpp` and
  `agent.cpp` is byte-accurate and unchanged. `0xCC` detection
  (`original != 0xcc`) unchanged.
- **Single-step re-arm** uses the trap flag `EFlags |= 0x100` / `&= ~0x100` —
  identical bit on x86, x64, and WoW64. The restore-byte → set-TF → re-patch dance
  is arch-identical; only the context get/set wrapper differs (section 3).
- **Hardware breakpoints (DR0..DR3 + DR7)**: layout and semantics are identical
  (DR7 enable bits, the LEN/RW fields at `<<16`). Differences:
  - x86-native: `CONTEXT.Dr0..Dr7` are `DWORD` (32-bit); current code writes
    `c.Dr0=address` with `DWORD64` math — on x86 the field is 32-bit, which is
    fine since addresses are 32-bit. The `c.Dr7 &= ~((DWORD64)0xff<<16)` mask must
    use a 32-bit-safe literal on the x86 build.
  - WoW64: program `WOW64_CONTEXT.Dr0..Dr7` via `Wow64SetThreadContext`. The
    native 64-bit `CONTEXT.Dr*` of the same thread are a **different** register
    set (the wow64cpu host) and must not be used — doing so arms nothing the
    32-bit code will hit.
  - In-process VEH hardware path (`agent.cpp`) uses the same DR slots; the
    debugger-vs-agent DR contention noted in the design review still applies and
    is unchanged by arch.
- 4 DR slots on both arches; no x86-specific limit.

---

## 5. Inline backend (SafetyHook) on x86

SafetyHook v0.7.0 selects `Context` = `Context64` when `SAFETYHOOK_ARCH_X86_64`
and `Context` = `Context32` when `SAFETYHOOK_ARCH_X86_32`. `Context32` members
(declaration order): `xmm0..xmm7`, `eflags`, `edi`, `esi`, `edx`, `ecx`, `ebx`,
`eax`, `ebp`, `esp`, `trampoline_esp`, `eip`. `create_mid` works on x86.

Changes to the agent's `call_mid` adapter (currently hardcoded to the x64
`PROBE_GPRS` + `w.rsp`/`w.rflags`):

```cpp
static void call_mid(safetyhook::Context &w, int index) {
    probe_context c{};
#if defined(_M_IX86)
    c.regs.v[PROBE_REG_AX]=w.eax; c.regs.v[PROBE_REG_BX]=w.ebx;
    c.regs.v[PROBE_REG_CX]=w.ecx; c.regs.v[PROBE_REG_DX]=w.edx;
    c.regs.v[PROBE_REG_SI]=w.esi; c.regs.v[PROBE_REG_DI]=w.edi;
    c.regs.v[PROBE_REG_BP]=w.ebp; c.regs.v[PROBE_REG_SP]=w.esp;
    c.regs.v[PROBE_REG_FLAGS]=w.eflags; c.regs.v[PROBE_REG_PC]=w.eip;
    c.arch=PROBE_ARCH_X86; c.reg_width=4; c.reg_avail=PROBE_AVAIL_X86;
#else
    /* existing x64 copy via PROBE_MAP_X64, w.rsp, w.rflags */
#endif
    c.site=(uint32_t)(index+1); c.tid=GetCurrentThreadId(); c.ops=&local_ops;
    example_callback(&c,&config,&stats);
    /* write back the writable subset (AX for the flag flip; args via esp) */
}
```

Use `w.esp` (captured target ESP) for `probe_arg` stack reads — **not**
`trampoline_esp`. Write-back must honor x86 availability: writing `PROBE_REG_AX`
updates `w.eax` (the flag flip), and `PROBE_REG_R8..R15` are no-ops.

x86 trampoline / relocation caveats:
- The min inline patch is a 5-byte near jump (`E9 rel32`) — same 5 bytes as x64's
  typical patch, but x86 has no RIP-relative addressing, so the relocation set is
  **relative control-flow**: `E8 call rel32`, `E9 jmp rel32`, `Jcc rel8/rel32`,
  `LOOP`/`JECXZ`. SafetyHook+Zydis relocate these; the 16-NOP sleds in
  `sites.asm`/`app_sites.asm` guarantee enough stealable bytes on both arches.
- `ParsedFlagSite` in `flag.asm` is deliberately a 2-byte store
  (`mov [rcx],eax` / x86 `mov [ecx],eax`) + `ret` — **too short for a 5-byte jmp**.
  Inline is impossible there by design on **both** arches, so that site uses the
  breakpoint backend (which the gospel example already does:
  `probe_add(... enable_reads, PROBE_BREAKPOINT)`). This is unchanged by the port.
- x86 lacks the 32-byte shadow space — irrelevant to the inline NOP-sled thunks,
  but it changes the `probe_arg` stack math (section 2), which is the real
  arch-sensitive part.

---

## 6. MASM: 32-bit assembly (ml.exe), name decoration, CMake selection

The three fixtures (`sites.asm`, `app_sites.asm`, `flag.asm`) are ml64 (64-bit):
`QWORD` externs, `rax/rcx` registers, no `.model`. Provide **x86 variants**
assembled by `ml.exe` (CMake picks `ml` for `-A Win32`, `ml64` for `-A x64`
automatically for the `ASM_MASM` language).

x86 MASM differences:
- Header: `.586` + `.model flat, C` (or `.model flat, stdcall` where stdcall
  decoration is wanted), then `.code`. ml64 needs none of this.
- Registers: `eax/ebx/ecx/edx/esi/edi/ebp/esp/eip`; `DWORD PTR` for the pointer
  deref; `EXTERN g_ntread:DWORD` (not `QWORD`).
- The forwarding thunk becomes `jmp DWORD PTR [g_ntread]`.
- **Name decoration** (flat model): `__cdecl` -> leading underscore `_Name`;
  `__stdcall` -> `_Name@N` where `N` = total arg bytes; `__fastcall` -> `@Name@N`.
  With `.model flat, C` MASM adds the leading underscore automatically for `PROC`
  symbols; with explicit control use `OPTION` or decorate `PUBLIC` names by hand so
  they match what the C/C++ side imports/looks up.
- Our fixture labels (`ReadSite`, `FlagRegSite`, `FlagMemSite`, `ParsedFlagSite`)
  are **found by RVA (linker `.map`) or PDB public**, not called directly — but the
  32-bit `.map` lists them **decorated** (e.g. `_ReadThunk`, `_StoreParsedFlag`),
  so the RVA-extraction tooling must strip/accept the leading underscore and the
  `@N` suffix. `g_ntread` likewise is `_g_ntread` on x86.
- Keep the value the probe reads in the **right register for cross-arch parity**:
  x86 `flag.asm` must have `EAX` hold the parsed `reads_enabled` at `ParsedFlagSite`
  (so `PROBE_REG_AX` works on both — section 1a). The pointer can be `ECX`
  (fastcall) or a stack arg; the probe only needs `EAX`.

CMake selection — add per-arch source lists:

```cmake
if(CMAKE_SIZEOF_VOID_P EQUAL 4)        # -A Win32
    set(SITES_ASM      src/sites_x86.asm)
    set(APP_SITES_ASM  src/app_sites_x86.asm)
    set(FLAG_ASM       src/configparse/flag_x86.asm)
else()                                  # -A x64
    set(SITES_ASM      src/sites.asm)
    set(APP_SITES_ASM  src/app_sites.asm)
    set(FLAG_ASM       src/configparse/flag.asm)
endif()
```

and use `${SITES_ASM}` etc. in the `add_executable`/`add_library` calls. CMake
drives `ml64 /c` vs `ml /c` from the generator platform; no manual compiler path.
(Alternatively a single `.asm` with `IFDEF RAX`/arch `IF` blocks, but two files are
clearer and match the existing style.)

---

## 7. CMake / build strategy on one machine (both arches)

1. **Relax the FATAL_ERROR.** Current block hard-rejects anything but MSVC x64:
   ```cmake
   if(NOT MSVC OR NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
       message(FATAL_ERROR "Windows prototype requires MSVC x64 ...")
   endif()
   ```
   Replace with: require MSVC; accept x64 (`CMAKE_SIZEOF_VOID_P EQUAL 8`) **or**
   x86 (`EQUAL 4`); still reject ARM64 explicitly
   (`CMAKE_SYSTEM_PROCESSOR`/`CMAKE_GENERATOR_PLATFORM MATCHES ARM64`). Define an
   `PROBE_ARCH_BITS` cache/computed var for the `.asm` selection and any
   `target_compile_definitions`.
2. **Two out-of-source build dirs, one source tree:**
   ```
   cmake -S . -B build-x64 -A x64
   cmake --build build-x64 --config RelWithDebInfo
   cmake -S . -B build-x86 -A Win32
   cmake --build build-x86 --config RelWithDebInfo
   ```
   `-A x64`/`-A Win32` is the VS-generator platform switch. Each dir gets its own
   SafetyHook/Zydis FetchContent build at the matching bitness automatically
   (they are add_subdirectory sub-projects and inherit the platform).
3. **MASM dialect** follows the platform (ml64 vs ml) via `enable_language(ASM_MASM)`
   — no extra config beyond the per-arch source selection in section 6.
4. **Agent/target/controller bitness must match within a build dir.** In
   `build-x86` everything is x86 → covers **case (a)** end-to-end and produces the
   32-bit agent reused by case (b). The x64 controller debugging a 32-bit target
   (**case b**) is a cross-bitness run: use the **`build-x64`** `probe_debugger`
   against the **`build-x86`** `probe_target`/`probe_app`. The check script must be
   able to pair an x64 controller with an x86 target path.
5. `check_scenario.py` gains an `--arch {x86,x64,wow64}` axis: `x86` uses
   `build-x86` for all parts; `x64` uses `build-x64` for all parts; `wow64` uses
   `build-x64` controller + `build-x86` target/agent.
6. Keep the fast policy unit tests (`policy_tests`) building on both; they are
   arch-neutral C.

---

## 8. dbghelp symbol resolution for 32-bit modules

- The dbghelp API (`SymInitialize`, `SymLoadModuleEx`, `SymFromName`,
  `SymFromAddr`, `SymEnumSymbols`) is the same. `SymInitialize(hProcess,...)`
  operates on the **target** handle, so an x64 controller's dbghelp can enumerate a
  WoW64 target's **32-bit** module symbols; module bases are 32-bit values in
  `DWORD64` fields (fine).
- **Name decoration**: 32-bit PDB publics for `__stdcall`/`__cdecl` are decorated
  (`_NtReadVirtualMemory@20`, `_ReadThunk`, `_g_ntread`). Set
  `SymSetOptions(SYMOPT_UNDNAME | SYMOPT_LOAD_LINES | ...)` and/or query with the
  decorated name; the `module!symbol` resolver must try both decorated and
  undecorated forms on x86. x64 `__fastcall`/system-v-ish names are undecorated, so
  today's lookups "just work" — x86 needs the decoration fallback.
- **Which ntdll**: for a WoW64 target, resolve `ntdll.dll!NtReadVirtualMemory`
  against the module whose path is `...\SysWOW64\ntdll.dll` (the 32-bit one),
  identified from `LOAD_DLL_DEBUG_EVENT` / `SymGetModuleInfo` by path, not by the
  bare name "ntdll.dll" (both are loaded). For x86-native there is only the one
  32-bit ntdll.
- **dbghelp.dll bitness**: load the dbghelp matching the controller process (x86
  controller → x86 dbghelp; x64 controller → x64 dbghelp). The x64 dbghelp handles
  32-bit target modules; do not try to load an x86 dbghelp into the x64 controller.
- `_NT_SYMBOL_PATH` / symsrv behavior is arch-agnostic; the server returns the
  correct-arch PDB keyed by the module's signature/age.

---

## 9. Sharp gotchas / risks

- **CONTEXT struct confusion (highest risk).** Calling native
  `GetThreadContext`/`CONTEXT` on a WoW64 thread yields the 64-bit wow64cpu state,
  not the 32-bit app registers. Must use `Wow64GetThreadContext`/`WOW64_CONTEXT`
  for case (b). Symmetric for Set and for DR registers.
- **WoW64 double breakpoint & WX86 codes.** Two startup breakpoints (64-bit then
  `STATUS_WX86_BREAKPOINT`); must not install probes on the wrong one, and must
  accept `STATUS_WX86_BREAKPOINT`/`STATUS_WX86_SINGLE_STEP` everywhere the x64
  codes are matched. Missing this = probes never fire / single-step re-arm hangs.
- **Two ntdlls.** The 32-bit app's `Nt*` are in `SysWOW64\ntdll.dll`. Resolving to
  `System32\ntdll.dll` points the hook at 64-bit code the app never executes.
- **Stack-arg width on x86 (the "handle on the stack" trap).** `probe_arg` on x86
  must read exactly **4 bytes** per slot. Reading 8 bytes (copy-pasted from the x64
  path) pulls the *next* argument into the high dword — e.g. `probe_arg(c,0)` for
  the `NtReadVirtualMemory` HANDLE would smear `BaseAddress` into bits 32..63 and
  break the handle->pid lookup. Same for dereferencing `CLIENT_ID.UniqueProcess`
  (read 4, not 8) and `*PHANDLE` in `note_open`.
- **`__stdcall` callee-clean return probes.** At return the x86 args are already
  popped (`ret N`) and x64 arg registers are clobbered; `probe_arg` on a
  `PROBE_AT_RETURN` probe MUST serve cached entry args, never live
  stack/registers.
- **`SIZE_T` width.** `NumberOfBytes` is 4 bytes on x86, 8 on x64; the log format
  and any comparisons must use the context's `reg_width`, not a fixed 8.
- **Pristine-frame assumption.** x86 `[ESP+4+4*i]` is only valid where ESP is the
  untouched call frame (our thunks, and true entry). At arbitrary mid-function
  sites the offsets are wrong — `probe_arg` at a non-entry site is UNSUPPORTED, as
  the design review recommends.
- **Address zero/sign-extension across the boundary.** 32-bit addresses live in
  64-bit debug-event fields; always zero-extend. Never sign-extend a 32-bit
  address or handle.
- **SafetyHook write-back subset on x86.** Only write registers that exist; the
  flag flip writes `eax`. Do not touch r8-r15.
- **x86 min-patch vs tiny sites.** `ParsedFlagSite` (2-byte store) can't take a
  5-byte inline jump on either arch — keep it breakpoint-only; do not "fix" it by
  widening the fixture.
- **DR slot contention** (debugger vs in-process VEH) is unchanged by arch but
  still real; the compatibility matrix from the design review applies to both.
- **Agent bitness.** Never attempt to inject the x64 agent into a 32-bit target;
  the WoW64 inline path is a 32-bit agent (= the case-(a) agent).

---

## 10. Ordered task list

**Phase A — shared ABI (prereq for everything):**
1. `probe.h`: replace the x64 `probe_regs` with the logical-id layout (`v[]`,
   `probe_arch`, `reg_avail`, `reg_width`, `entry_args`) from section 1a. Add
   `PROBE_REG_*`, `probe_arch`, and the availability masks `PROBE_AVAIL_X86` /
   `PROBE_AVAIL_X64`. Keep `probe_read`/`probe_write`/`probe_context` shape.
2. `win_common.hpp`: split `PROBE_GPRS` into `PROBE_MAP_X86`/`PROBE_MAP_X64`; add
   arch-switched `from_context(CONTEXT&)`/`to_context(...)` and (x64 build only)
   `from_context(WOW64_CONTEXT&)`/`to_context(...)`. Set `arch/reg_width/reg_avail`.
3. Implement `probe_arg`, `probe_reg`/`probe_set_reg`, `probe_retval` in the
   library over the new context + `probe_ops`, with the x86 stack math (2b) and x64
   register/stack math (2a), width-correct reads, and entry-arg caching (2d).

**Phase B — case (a), 32-bit native, end-to-end:**
4. CMake: relax the FATAL_ERROR (section 7.1); add the per-arch `.asm` selection
   (section 6); keep ARM64 rejected.
5. Author `sites_x86.asm`, `app_sites_x86.asm`, `flag_x86.asm` (`.model flat`,
   `DWORD` externs, `EAX`-holds-flag, decorated publics).
6. `agent.cpp`: `#if _M_IX86` branch of `call_mid` using `Context32`; VEH INT3 path
   uses `Eip`/`Esp` and the common exception codes (already arch-neutral once PC is
   abstracted).
7. `debugger.cpp`: introduce the `ThreadCtx` wrapper; x86-native path uses 32-bit
   `CONTEXT` + normal Get/Set, `Eip`/`Esp`, 32-bit `Dr*` mask.
8. dbghelp resolver: decorated-name fallback for x86 (section 8).
9. Configure/build `build-x86` (`-A Win32`); run `check_scenario.py --arch x86`:
   verify flag flip, multithreaded `NtReadVirtualMemory` logging, and the
   `NtOpenProcess` handle->pid map — the full gated scenario, including the
   `watch_new`-style attach required by plan-v2.

**Phase C — case (b), WoW64, x64 controller + 32-bit target:**
10. `debugger.cpp`: add the `WOW64_CONTEXT` variant of `ThreadCtx`
    (`Wow64Get/SetThreadContext`, `WOW64_CONTEXT_*` flags); bitness detection via
    `IsWow64Process2`; accept `STATUS_WX86_BREAKPOINT`/`STATUS_WX86_SINGLE_STEP`;
    handle the double startup breakpoint.
11. Location resolver: pick `SysWOW64\ntdll.dll` for a WoW64 target (section 8).
12. `check_scenario.py --arch wow64`: `build-x64` controller against `build-x86`
    target/agent (the 32-bit agent from Phase B is reused). Verify the same three
    behaviors across the boundary; confirm addresses/handles are zero-extended and
    correct.

**Phase D — verification & close-out:**
13. Cross-backend matrix on both arches (breakpoint @ `ParsedFlagSite`, inline @
    `ReadSite`, HW fallback); existing-hook detection still mandatory.
14. Record Windows validation results for x86 and x64 (and WoW64) per plan-v2's
    checkpoint requirement — verified, not assumed.

---

### API facts cited (exact names)

`GetThreadContext`, `SetThreadContext`, `Wow64GetThreadContext`,
`Wow64SetThreadContext`, `CONTEXT`, `WOW64_CONTEXT`, `IsWow64Process2`,
`CONTEXT_ALL`/`CONTEXT_CONTROL`/`CONTEXT_DEBUG_REGISTERS`,
`WOW64_CONTEXT_ALL`/`WOW64_CONTEXT_CONTROL`/`WOW64_CONTEXT_DEBUG_REGISTERS`,
`WaitForDebugEvent`/`ContinueDebugEvent`, `CREATE_PROCESS_DEBUG_EVENT`/
`LOAD_DLL_DEBUG_EVENT`/`EXCEPTION_DEBUG_EVENT`, `EXCEPTION_BREAKPOINT`
(0x80000003), `EXCEPTION_SINGLE_STEP` (0x80000004), `STATUS_WX86_BREAKPOINT`
(0x4000001F), `STATUS_WX86_SINGLE_STEP` (0x4000001E), `ReadProcessMemory`/
`WriteProcessMemory`, `VirtualProtectEx`/`FlushInstructionCache`,
`NtReadVirtualMemory`, `NtOpenProcess`, `CLIENT_ID`, `SymInitialize`/
`SymFromName`/`SymFromAddr`/`SymSetOptions` (`SYMOPT_UNDNAME`),
`safetyhook::create_mid` / `safetyhook::Context32`.
