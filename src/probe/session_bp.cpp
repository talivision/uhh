// The software-breakpoint backend: INT3 patching, emulated sites, displaced stepping and its
// trampolines, adopted relocated copies, the in-place window.
#include "session_internal.hpp"

namespace uhh_session {

bool patch(HANDLE process, uint64_t address, unsigned char byte) {
    DWORD old{}, ignored{}; SIZE_T done{};
    if (!VirtualProtectEx(process, (void *)(uintptr_t)address, 1, PAGE_EXECUTE_READWRITE, &old)) return false;
    BOOL wrote = WriteProcessMemory(process, (void *)(uintptr_t)address, &byte, 1, &done);
    BOOL flushed = FlushInstructionCache(process, (void *)(uintptr_t)address, 1);
    BOOL restored = VirtualProtectEx(process, (void *)(uintptr_t)address, 1, old, &ignored);
    return wrote && done == 1 && flushed && restored;
}

// Put a breakpoint probe's original byte back -- only if our INT3 is still there. Another
// hooking tool may have rewritten the site since (e.g. Frida/Detours writing their jump over
// it): restoring our byte then would corrupt THEIR hook.
void restore_original(HANDLE process, uint64_t address, unsigned char original) {
    unsigned char now = 0; SIZE_T got = 0;
    if (ReadProcessMemory(process, (void *)(uintptr_t)address, &now, 1, &got) && got == 1 && now == 0xcc)
        patch(process, address, original);
}

// Re-arm our INT3 after an in-place step -- only if the site still holds the byte we lifted.
// Anything else means another hooking tool wrote there meanwhile: leave its bytes alone.
static bool rearm_breakpoint(HANDLE process, uint64_t address, unsigned char original) {
    unsigned char now = 0; SIZE_T got = 0;
    if (!ReadProcessMemory(process, (void *)(uintptr_t)address, &now, 1, &got) || got != 1) return false;
    if (now == 0xcc) return true;                         // already armed
    return now == original && patch(process, address, 0xcc);
}

// ---- Emulated sites ---------------------------------------------------------------------
// Instructions that cannot run out-of-line (relative/indirect branches, call, ret, loop,
// pushf/popf) used to be stepped IN PLACE: the INT3 was lifted for the step, so another
// thread could cross the site unseen (inexact), and TF leaked into a pushf'd flags image
// (RtlCaptureContext starts with pushfq). They are now executed by the controller on the
// stopped thread's context: the INT3 never leaves, no single-step, no trap flag. Anything
// not understood here (or a memory access that fails, which must fault for real) still
// takes the in-place path.
static bool emu_reg(const CONTEXT &c, ZydisRegister r, uint64_t next_ip, uint64_t &v) {
    if (r == ZYDIS_REGISTER_NONE) { v = 0; return true; }
    if (r == ZYDIS_REGISTER_RIP || r == ZYDIS_REGISTER_EIP) { v = next_ip; return true; }
    ZydisRegister full = ZydisRegisterGetLargestEnclosing(
#if defined(_WIN64)
        ZYDIS_MACHINE_MODE_LONG_64,
#else
        ZYDIS_MACHINE_MODE_LONG_COMPAT_32,
#endif
        r);
    uint64_t x;
    switch (full) {
#if defined(_WIN64)
        case ZYDIS_REGISTER_RAX: x = c.Rax; break; case ZYDIS_REGISTER_RCX: x = c.Rcx; break;
        case ZYDIS_REGISTER_RDX: x = c.Rdx; break; case ZYDIS_REGISTER_RBX: x = c.Rbx; break;
        case ZYDIS_REGISTER_RSP: x = c.Rsp; break; case ZYDIS_REGISTER_RBP: x = c.Rbp; break;
        case ZYDIS_REGISTER_RSI: x = c.Rsi; break; case ZYDIS_REGISTER_RDI: x = c.Rdi; break;
        case ZYDIS_REGISTER_R8:  x = c.R8;  break; case ZYDIS_REGISTER_R9:  x = c.R9;  break;
        case ZYDIS_REGISTER_R10: x = c.R10; break; case ZYDIS_REGISTER_R11: x = c.R11; break;
        case ZYDIS_REGISTER_R12: x = c.R12; break; case ZYDIS_REGISTER_R13: x = c.R13; break;
        case ZYDIS_REGISTER_R14: x = c.R14; break; case ZYDIS_REGISTER_R15: x = c.R15; break;
#else
        case ZYDIS_REGISTER_EAX: x = c.Eax; break; case ZYDIS_REGISTER_ECX: x = c.Ecx; break;
        case ZYDIS_REGISTER_EDX: x = c.Edx; break; case ZYDIS_REGISTER_EBX: x = c.Ebx; break;
        case ZYDIS_REGISTER_ESP: x = c.Esp; break; case ZYDIS_REGISTER_EBP: x = c.Ebp; break;
        case ZYDIS_REGISTER_ESI: x = c.Esi; break; case ZYDIS_REGISTER_EDI: x = c.Edi; break;
#endif
        default: return false;
    }
    const ZyanU16 width = ZydisRegisterGetWidth(
#if defined(_WIN64)
        ZYDIS_MACHINE_MODE_LONG_64,
#else
        ZYDIS_MACHINE_MODE_LONG_COMPAT_32,
#endif
        r);
    if (width == 64) v = x;
    else if (width == 32) v = (uint32_t)x;
    else return false;                                   // 16/8-bit addressing: not emulated
    return true;
}

static bool emu_cond(ZydisMnemonic m, DWORD f) {
    const bool cf = f & 0x1, pf = f & 0x4, zf = f & 0x40, sf = f & 0x80, of = f & 0x800;
    switch (m) {
        case ZYDIS_MNEMONIC_JO: return of;           case ZYDIS_MNEMONIC_JNO: return !of;
        case ZYDIS_MNEMONIC_JB: return cf;           case ZYDIS_MNEMONIC_JNB: return !cf;
        case ZYDIS_MNEMONIC_JZ: return zf;           case ZYDIS_MNEMONIC_JNZ: return !zf;
        case ZYDIS_MNEMONIC_JBE: return cf || zf;    case ZYDIS_MNEMONIC_JNBE: return !cf && !zf;
        case ZYDIS_MNEMONIC_JS: return sf;           case ZYDIS_MNEMONIC_JNS: return !sf;
        case ZYDIS_MNEMONIC_JP: return pf;           case ZYDIS_MNEMONIC_JNP: return !pf;
        case ZYDIS_MNEMONIC_JL: return sf != of;     case ZYDIS_MNEMONIC_JNL: return sf == of;
        case ZYDIS_MNEMONIC_JLE: return zf || sf != of; case ZYDIS_MNEMONIC_JNLE: return !zf && sf == of;
        default: return false;
    }
}

// Executes the instruction at `site` on `c`. Returns true when emulated (c updated,
// memory written); false = not handled, take the stepping path instead.
// Hardware-enforced shadow stacks (Intel CET, /CETCOMPAT): an emulated CALL/RET would move
// the normal stack but not the shadow stack, so the target would fault at its next real ret.
// Such targets get CALL/RET stepped by the CPU (in-place path) instead.
// The thread is exiting (or gone): Get/SetThreadContext on it fail with ERROR_ACCESS_DENIED
// (STATUS_THREAD_IS_TERMINATING) while GetExitCodeThread can still say STILL_ACTIVE.
bool thread_terminating(HANDLE thread) {
    using QueryFn = LONG(NTAPI *)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    static auto query = reinterpret_cast<QueryFn>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationThread"));
    ULONG terminated = 0;
    DWORD code = 0;
    if (GetExitCodeThread(thread, &code) && code != STILL_ACTIVE) return true;
    return query && query(thread, 20 /* ThreadIsTerminated */, &terminated, sizeof(terminated), nullptr) >= 0 && terminated;
}

bool target_has_shadow_stack(probe_session *s) {
    if (s->shadow_stack < 0) {
        s->shadow_stack = 0;
        PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY pol{};
        using GetPolicyFn = BOOL(WINAPI *)(HANDLE, PROCESS_MITIGATION_POLICY, PVOID, SIZE_T);
        auto get = reinterpret_cast<GetPolicyFn>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetProcessMitigationPolicy"));
        if (get && s->pi.hProcess && get(s->pi.hProcess, ProcessUserShadowStackPolicy, &pol, sizeof(pol)))
            s->shadow_stack = pol.EnableUserShadowStack ? 1 : 0;
    }
    return s->shadow_stack == 1;
}
bool emulate_site(probe_session *s, const Probe &p, CONTEXT &c) {
    if (p.orig_insn.empty()) return false;
    ZydisDecoder dec;
#if defined(_WIN64)
    ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    const uint32_t ptr = 8;
#else
    ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_STACK_WIDTH_32);
    const uint32_t ptr = 4;
#endif
    ZydisDecodedInstruction in;
    ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, p.orig_insn.data(), p.orig_insn.size(), &in, ops))) return false;
    const uint64_t site = p.address, next = site + in.length;
    HANDLE h = s->pi.hProcess;
    // Every memory access is checked against the CPU's view first (committed, not PAGE_GUARD,
    // readable / writable): Read/WriteProcessMemory would consume a guard page (the stack's own
    // guard -> no stack growth, the next overflow an access violation) or write through a
    // read-only page. Anything that would fault is left to the CPU (in-place step).
    auto push = [&](uint64_t v, uint32_t size) {
        uint64_t sp = (uint64_t)EMU_SP(c) - size; size_t n = 0;
        if (!remote_range_ok(h, sp, size, true)) return false;
        if (!remote_write(h, sp, &v, size, &n) || n != size) return false;
        EMU_SP(c) = (decltype(EMU_SP(c)))sp; return true;
    };
    auto pop = [&](uint64_t &v, uint32_t size) {
        v = 0; size_t n = 0;
        if (!remote_range_ok(h, (uint64_t)EMU_SP(c), size, false)) return false;
        if (!remote_read(h, (uint64_t)EMU_SP(c), &v, size, &n) || n != size) return false;
        EMU_SP(c) = (decltype(EMU_SP(c)))((uint64_t)EMU_SP(c) + size); return true;
    };
    // The branch target of operand 0 (relative immediate, register, or memory pointer).
    auto target = [&](uint64_t &t) {
        const ZydisDecodedOperand &o = ops[0];
        if (o.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && o.imm.is_relative) {
            t = next + (uint64_t)o.imm.value.s;
#if !defined(_WIN64)
            t = (uint32_t)t;
#endif
            return true;
        }
        if (o.type == ZYDIS_OPERAND_TYPE_REGISTER) return emu_reg(c, o.reg.value, next, t) && o.size == ptr * 8;
        if (o.type == ZYDIS_OPERAND_TYPE_MEMORY) {
            if (o.mem.segment == ZYDIS_REGISTER_FS || o.mem.segment == ZYDIS_REGISTER_GS) return false;
            if (o.size != ptr * 8) return false;                       // far pointers etc.
            uint64_t base = 0, index = 0;
            if (!emu_reg(c, o.mem.base, next, base) || !emu_reg(c, o.mem.index, next, index)) return false;
            uint64_t a = base + index * o.mem.scale + (uint64_t)o.mem.disp.value;
#if !defined(_WIN64)
            a = (uint32_t)a;
#endif
            t = 0; size_t n = 0;
            return remote_range_ok(h, a, ptr, false) && remote_read(h, a, &t, ptr, &n) && n == ptr;
        }
        return false;
    };
    if (in.operand_width != 0 && in.operand_width != 64 && in.operand_width != 32) return false;
    uint64_t t = 0, v = 0;
    const CONTEXT before = c;
    bool ok = false;
    switch (in.mnemonic) {
        case ZYDIS_MNEMONIC_JMP:
            ok = target(t); if (ok) EMU_IP(c) = (decltype(EMU_IP(c)))t; break;
        case ZYDIS_MNEMONIC_CALL:
            if (target_has_shadow_stack(s)) break;          // the CPU must push the shadow stack itself
            ok = target(t) && push(next, ptr); if (ok) EMU_IP(c) = (decltype(EMU_IP(c)))t; break;
        case ZYDIS_MNEMONIC_RET:
            if (target_has_shadow_stack(s)) break;          // ... and pop it
            if (in.operand_count_visible > 1) break;
            ok = pop(v, ptr);
            if (ok && in.operand_count_visible == 1 && ops[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                EMU_SP(c) = (decltype(EMU_SP(c)))((uint64_t)EMU_SP(c) + ops[0].imm.value.u);
            if (ok) EMU_IP(c) = (decltype(EMU_IP(c)))v;
            break;
        case ZYDIS_MNEMONIC_JO: case ZYDIS_MNEMONIC_JNO: case ZYDIS_MNEMONIC_JB: case ZYDIS_MNEMONIC_JNB:
        case ZYDIS_MNEMONIC_JZ: case ZYDIS_MNEMONIC_JNZ: case ZYDIS_MNEMONIC_JBE: case ZYDIS_MNEMONIC_JNBE:
        case ZYDIS_MNEMONIC_JS: case ZYDIS_MNEMONIC_JNS: case ZYDIS_MNEMONIC_JP: case ZYDIS_MNEMONIC_JNP:
        case ZYDIS_MNEMONIC_JL: case ZYDIS_MNEMONIC_JNL: case ZYDIS_MNEMONIC_JLE: case ZYDIS_MNEMONIC_JNLE:
            ok = target(t); if (ok) EMU_IP(c) = (decltype(EMU_IP(c)))(emu_cond(in.mnemonic, c.EFlags) ? t : next); break;
        case ZYDIS_MNEMONIC_JRCXZ: case ZYDIS_MNEMONIC_JECXZ: case ZYDIS_MNEMONIC_JCXZ: {
            // The counter width is the ADDRESS size: jrcxz (x64), jecxz (x86, or 67h on x64),
            // jcxz (67h on x86).
            uint64_t cx = 0;
            ok = target(t);
            if (ok && in.mnemonic == ZYDIS_MNEMONIC_JCXZ) cx = (uint64_t)(EMU_CX(c) & 0xFFFFu);
            else if (ok) ok = emu_reg(c, in.mnemonic == ZYDIS_MNEMONIC_JRCXZ ? ZYDIS_REGISTER_RCX : ZYDIS_REGISTER_ECX, next, cx);
            if (ok) EMU_IP(c) = (decltype(EMU_IP(c)))(cx == 0 ? t : next);
            break;
        }
        case ZYDIS_MNEMONIC_LOOP: case ZYDIS_MNEMONIC_LOOPE: case ZYDIS_MNEMONIC_LOOPNE: {
            // The counter is rcx / ecx / cx by ADDRESS size (67h selects ecx on x64, cx on x86).
            if (!target(t)) break;
            bool nz;
#if defined(_WIN64)
            if (in.address_width == 64) { --c.Rcx; nz = c.Rcx != 0; }
            else if (in.address_width == 32) {          // a 32-bit counter write zero-extends, as
                const uint32_t e = (uint32_t)c.Rcx - 1;  // the CPU does (inplace-loop_a32 compares)
                c.Rcx = e; nz = e != 0;
            } else break;
#else
            if (in.address_width == 32) { --c.Ecx; nz = c.Ecx != 0; }
            else if (in.address_width == 16) {         // cx only; the upper half of ecx is kept
                const WORD cx = (WORD)(c.Ecx - 1);
                c.Ecx = (c.Ecx & 0xFFFF0000u) | cx; nz = cx != 0;
            } else break;
#endif
            const bool zf = c.EFlags & 0x40;
            const bool take = nz && (in.mnemonic == ZYDIS_MNEMONIC_LOOP ||
                                          (in.mnemonic == ZYDIS_MNEMONIC_LOOPE && zf) ||
                                          (in.mnemonic == ZYDIS_MNEMONIC_LOOPNE && !zf));
            EMU_IP(c) = (decltype(EMU_IP(c)))(take ? t : next); ok = true;
            break;
        }
        case ZYDIS_MNEMONIC_PUSHFQ: case ZYDIS_MNEMONIC_PUSHFD:
            // The image the CPU pushes: RF and VM read as 0. TF as the TARGET has it (ours
            // is never set here: there is no single-step).
            ok = push((uint64_t)(c.EFlags & ~0x30000u), ptr); if (ok) EMU_IP(c) = (decltype(EMU_IP(c)))next; break;
        case ZYDIS_MNEMONIC_POPFQ: case ZYDIS_MNEMONIC_POPFD: {
            // CPL 3: CF PF AF ZF SF TF DF OF NT AC ID change; IF/IOPL/VM/RF do not.
            const DWORD mask = 0x1 | 0x4 | 0x10 | 0x40 | 0x80 | 0x100 | 0x400 | 0x800 | 0x4000 | 0x40000 | 0x200000;
            ok = pop(v, ptr);
            if (ok) { c.EFlags = (c.EFlags & ~mask) | ((DWORD)v & mask); EMU_IP(c) = (decltype(EMU_IP(c)))next; }
            break;
        }
        default: break;
    }
    if (!ok) { c = before; return false; }
    // Undo a partial write is not needed: push writes only below SP, which the CPU would
    // have written as well; on any failure c is restored and the real instruction runs.
    return true;
}

// Decode the site instruction to plan the single-step. Fills its length, whether it
// may be stepped out-of-line (not a relative branch / call / ret), and the offset of a
// RIP-relative disp32 to retarget in the out-of-line copy. Control-flow instructions
// return displaced_ok=false so the caller uses the in-place fallback.
static bool decode_site(const unsigned char *bytes, size_t n, uint32_t &len,
                        bool &displaced_ok, int &riprel_off, bool *rep_string = nullptr) {
    ZydisDecoder dec;
#if defined(_WIN64)
    ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
#else
    ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_STACK_WIDTH_32);
#endif
    ZydisDecodedInstruction insn;
    ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, bytes, n, &insn, ops))) return false;
    len = insn.length; riprel_off = -1; displaced_ok = true;
    if (rep_string) *rep_string = false;
    if (insn.meta.branch_type != ZYDIS_BRANCH_TYPE_NONE ||
        insn.meta.category == ZYDIS_CATEGORY_CALL || insn.meta.category == ZYDIS_CATEGORY_RET ||
        insn.meta.category == ZYDIS_CATEGORY_COND_BR || insn.meta.category == ZYDIS_CATEGORY_UNCOND_BR) {
        displaced_ok = false; return true;            // control flow -> in-place fallback
    }
    // Flags-image / trap / privileged instructions can clear or expose the trap flag,
    // or raise their own exception instead of the single-step, so out-of-line stepping
    // misbehaves; route them to the in-place fallback.
    switch (insn.mnemonic) {
        case ZYDIS_MNEMONIC_POPF:  case ZYDIS_MNEMONIC_POPFD:  case ZYDIS_MNEMONIC_POPFQ:
        case ZYDIS_MNEMONIC_PUSHF: case ZYDIS_MNEMONIC_PUSHFD: case ZYDIS_MNEMONIC_PUSHFQ:
        case ZYDIS_MNEMONIC_STI:   case ZYDIS_MNEMONIC_CLI:
        case ZYDIS_MNEMONIC_INT:   case ZYDIS_MNEMONIC_INT3:   case ZYDIS_MNEMONIC_INT1:
        case ZYDIS_MNEMONIC_SYSCALL: case ZYDIS_MNEMONIC_SYSENTER:
            displaced_ok = false; return true;
        default: break;
    }
    // REP/REPE/REPNE string ops: the trap flag fires after EACH iteration, so neither a
    // trap-flag step out-of-line (truncates the operation) nor in place (the re-armed INT3
    // fires the callback again for every remaining iteration, with RCX counting down) is
    // right. The caller runs them out-of-line to completion, ended by a trailing INT3.
    if (insn.attributes & (ZYDIS_ATTRIB_HAS_REP | ZYDIS_ATTRIB_HAS_REPE | ZYDIS_ATTRIB_HAS_REPNE)) {
        if (rep_string) *rep_string = true; else displaced_ok = false;
        return true;
    }
    // RIP-relative memory operand (x64): record the disp32 so the copy can be retargeted.
    for (int i = 0; i < insn.operand_count; ++i) {
        if (ops[i].type == ZYDIS_OPERAND_TYPE_MEMORY && ops[i].mem.base == ZYDIS_REGISTER_RIP) {
            if (insn.raw.disp.size == 32 && insn.raw.disp.offset) riprel_off = insn.raw.disp.offset;
            else displaced_ok = false;                // RIP-relative but not a disp32 we can retarget
            break;
        }
    }
    return true;
}
// Armed software breakpoints: the entries of the agent's INT3 table (probe_agent_shared::int3).
static bool int3_entry(const Probe &p) {
    return p.active && (p.flags & PROBE_BREAKPOINT) && !p.orig_insn.empty() && p.address;
}
size_t int3_armed(const probe_session *s) {
    size_t n = 0;
    for (const auto &p : s->probes) n += int3_entry(*p);
    return n;
}
bool arm_breakpoint(probe_session *s, Probe &p, uint64_t base) {
    if (p.rva > UINT64_MAX - base) { set_error(s, "probe address overflow"); return false; }
    uint64_t address = base + p.rva; size_t got{};
    unsigned char buf[16];
    if (!remote_read(s->pi.hProcess, address, buf, sizeof(buf), &got) || got != sizeof(buf)) {
        set_error(s, win_error("read original probe bytes")); return false;
    }
    if (buf[0] == 0xcc) {
        Probe *owner = probe_at(s, address);
        if (owner && owner->internal && !owner->orig_insn.empty()) {
            // Take over the library's own entry INT3: reuse its saved original bytes; the
            // re-apply still happens (entry_reapply) when this probe first fires.
            std::memcpy(buf, owner->orig_insn.data(), owner->orig_insn.size());
            owner->active = false; owner->retired = true;
            uint32_t len = 0; bool disp_ok = false, rep_str = false; int riprel = -1;
            if (!decode_site(buf, sizeof(buf), len, disp_ok, riprel, &rep_str) || len == 0 || len > sizeof(buf)) {
                set_error(s, "could not decode probe site instruction"); return false;
            }
            p.original = buf[0]; p.orig_insn.assign(buf, buf + len);
            p.insn_len = len; p.displaced_ok = disp_ok; p.riprel_disp_off = riprel; p.rep_string = rep_str;
            p.base = base; p.address = address; p.active = true;
            s->retired_bps.erase(address);
            sync_int3_table(s);
            return true;
        }
        set_error(s, "pre-hooked INT3 sites are unsupported by this breakpoint backend"); return false;
    }
    uint32_t len = 0; bool disp_ok = false, rep_str = false; int riprel = -1;
    if (!decode_site(buf, sizeof(buf), len, disp_ok, riprel, &rep_str) || len == 0 || len > sizeof(buf)) {
        set_error(s, "could not decode probe site instruction"); return false;
    }
    // The agent's copy must hold every one (an inline get_mem masks them). Without inline
    // probes there is no agent and no limit.
    if (s->shared && has_inline(s) && int3_armed(s) >= PROBE_AGENT_INT3_CAP) {
        set_error(s, "too many software breakpoints armed alongside inline probes (max " +
                     std::to_string(PROBE_AGENT_INT3_CAP) + ")");
        return false;
    }
    p.original = buf[0];
    p.orig_insn.assign(buf, buf + len);
    p.follow.assign(buf + 1, buf + sizeof(buf));
    p.insn_len = len; p.displaced_ok = disp_ok; p.riprel_disp_off = riprel; p.rep_string = rep_str;
    // Published to the agent's INT3 table (the controller-death guard) BEFORE the byte is
    // written: a controller killed right after the write left an INT3 neither the guard's VEH
    // nor its cleanup knew -- the target died at its next execution (unhandled breakpoint).
    // An entry whose byte is not (yet) 0xCC is harmless: the cleanup writes back the byte that
    // is already there, an inline get_mem overlays only a 0xCC.
    const uint64_t old_base = p.base, old_address = p.address;
    const bool old_active = p.active;
    p.base = base; p.address = address; p.active = true;
    sync_int3_table(s);
    guard_sync(s);
    if (!patch(s->pi.hProcess, address, 0xcc)) {
        p.base = old_base; p.address = old_address; p.active = old_active;
        sync_int3_table(s);
        set_error(s, win_error("arm software breakpoint")); return false;
    }
#if defined(UHH_TEST_HOOKS)
    if (!p.internal) test_die_after_arm();
#endif
    s->retired_bps.erase(address);
    if (!p.internal || trace_enabled())       // library-owned probes are not the user's to see
        std::fprintf(stderr, "%s %s -> base=0x%llx addr=0x%llx (was 0x%02x, len=%u, %s)\n",
                     p.internal ? "  internal" : "probe: active", p.location.c_str(), (unsigned long long)base,
                     (unsigned long long)address, p.original, len, disp_ok ? "displaced" : "in-place");
    return true;
}

// A lifted (in-place) breakpoint byte may only be re-armed while a breakpoint probe is
// still active at exactly that site: after detach, PROBE_ONCE retirement or an unload
// (where another module may now live at the address) the original byte must stay.
// Is `copy` (read at `at`, starting with an INT3) the other tool's relocation of probe p's
// site? Its bytes after the INT3 must be the site's own following bytes, verbatim, up to a
// jump back into the original function at exactly the offset reached (the shape every
// trampoline has: relocated prologue + jmp site+n); or, without such a jump in view, at
// least 8 matching bytes.
static bool is_relocated_copy(const unsigned char *copy, size_t got, uint64_t at, const Probe &p) {
    ZydisDecoder dec; zydis_init(dec);
    size_t k = 1;
    while (k < got) {
        ZydisDecodedInstruction insn; ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, copy + k, got - k, &insn, ops))) break;
        if (insn.mnemonic == ZYDIS_MNEMONIC_JMP && insn.operand_count_visible >= 1 && k >= 2) {
            ZyanU64 target = 0;
            if (ops[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&insn, &ops[0], at + k, &target)))
                return target == p.address + k;                 // back to the same offset: our site's copy
            if (ops[0].type == ZYDIS_OPERAND_TYPE_MEMORY && insn.length == 6 && k + 6 + sizeof(void *) <= got &&
                ops[0].mem.base == ZYDIS_REGISTER_RIP && ops[0].mem.disp.value == 0) {   // jmp [rip+0]; dq target
                uint64_t dest = 0; std::memcpy(&dest, copy + k + 6, sizeof(void *));
                return dest == p.address + k;
            }
            return false;
        }
        if (k - 1 + insn.length > p.follow.size() || std::memcmp(copy + k, p.follow.data() + (k - 1), insn.length) != 0)
            return false;                                       // not the site's bytes, verbatim
        k += insn.length;
        if (k > 8) return true;                                 // long verbatim run: same code
    }
    return false;
}

// A hit on an adopted copy (see adopt_relocated_breakpoint) counts for the probe it stands in for.
void count_hit(Probe *p) {
    ++p->hits;
    if (p->alias_of) ++p->alias_of->hits;
}

// Another hooking tool installed its inline hook on top of one of our breakpoint probes
// AFTER us (seen: Frida's Interceptor on a site UHH already holds): it read our 0xCC as part
// of the function, wrote its jump over the site, and copied the INT3 -- followed by the
// site's real bytes -- into its trampoline. That copy now traps at an address we do not own.
// Recognise it -- an INT3 in private executable memory, followed by exactly the bytes that
// followed our site, where our own site no longer holds our INT3 -- and adopt it: put the
// real byte back (the other tool's trampoline is then exactly what it meant to build) and
// arm our breakpoint THERE, same callback and config. Both tools keep seeing every call.
Probe *adopt_relocated_breakpoint(probe_session *s, uint64_t at) {
    MEMORY_BASIC_INFORMATION m{};
    if (!VirtualQueryEx(s->pi.hProcess, (void *)(uintptr_t)at, &m, sizeof(m)) || m.State != MEM_COMMIT ||
        m.Type == MEM_IMAGE ||
        !(m.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
        return nullptr;
    unsigned char copy[16]; size_t got = 0;
    if (!remote_read(s->pi.hProcess, at, copy, sizeof(copy), &got) || got < 5 || copy[0] != 0xcc) return nullptr;
    for (auto &up : s->probes) {
        Probe &p = *up;
        if (!p.active || !(p.flags & PROBE_BREAKPOINT) || p.alias_of || p.internal || p.follow.size() < 4) continue;
        unsigned char now = 0; size_t one = 0;
        if (!remote_read(s->pi.hProcess, p.address, &now, 1, &one) || one != 1 || now == 0xcc) continue;   // still ours
        if (trace_enabled())
            std::fprintf(stderr, "  relocated? %s site_now=0x%02x copy=%s follow=%s\n", p.location.c_str(), now,
                         hex_bytes(copy, got).c_str(), hex_bytes(p.follow.data(), p.follow.size()).c_str());
        if (!is_relocated_copy(copy, got, at, p)) continue;
        auto a = std::make_unique<Probe>();
        a->location = p.location + " (relocated copy)";
        a->flags = p.flags & ~PROBE_ONCE; a->callback = p.callback; a->callback_export = p.callback_export;
        a->config = p.config;
        a->rva = at; a->internal = true; a->alias_of = &p;
        if (!patch(s->pi.hProcess, at, p.original)) return nullptr;    // the copy now runs the real code
        Probe *raw = a.get();
        { std::lock_guard<std::mutex> lock(s->probes_mu); s->probes.push_back(std::move(a)); }                              // returns before the loop goes on
        std::string saved = s->error;
        if (!arm_breakpoint(s, *raw, 0)) {                   // the copy now holds the real byte:
            raw->retired = true; s->error = saved;               // rewind onto it (stale-INT3 path)
            s->retired_bps.insert(at);
            return nullptr;
        }
        std::fprintf(stderr, "probe: %s was re-hooked by another tool that relocated our breakpoint to 0x%llx; "
                             "following it there\n", p.location.c_str(), (unsigned long long)at);
        return raw;
    }
    return nullptr;
}

bool still_armed(probe_session *s, uint64_t site) {
    Probe *p = probe_at(s, site);
    return p && (p->flags & PROBE_BREAKPOINT);
}

// An in-place step at site is over: re-arm the INT3 (see the re-lift in handle_exception
// for a second thread that is still mid in-place step there).
void end_inplace_step(probe_session *s, DWORD tid, uint64_t site) {
    (void)tid;
    if (still_armed(s, site)) rearm_breakpoint(s->pi.hProcess, site, probe_at(s, site)->original);
}

// ---- In-place window -------------------------------------------------------------------
// The few sites that are neither displaced nor emulated (see emulate_site: segment-relative or
// 16-bit branches, an access the CPU must fault on, CALL/RET under CET shadow stacks, a REP
// string op without scratch, ...) are stepped IN PLACE: our INT3 is lifted for one trap-flag
// step. While it is lifted, every OTHER thread of the target is suspended by us, so none can
// run through the site uncounted; a hit another thread raised just before (its event was
// already queued) is rewound onto the INT3 and replays after the window (handle_exception).
// No deadlock: the window covers exactly one instruction of the stepping thread (one REP
// iteration at a time for a string op), which reports its trap or its fault to us before any
// other code of the target runs -- it cannot wait for a suspended thread. The instructions
// that can block in the kernel (SYSCALL / INT 2E run from a trampoline instead; SYSENTER,
// INT 2B, far transfers that may switch to 64-bit code) never get a window, and a window not
// closed within 2 s (the target suspended the stepping thread itself) is released with a
// warning. Our agent's threads are never suspended (an entry hold waits for them).
bool inplace_exempt(probe_session *s, DWORD tid) {
    if (s->remote_tid && tid == s->remote_tid) return true;
    if (!s->remote_agent) return false;
    if (auto it = s->agent_tid_cache.find(tid); it != s->agent_tid_cache.end()) return it->second;
    const bool a = agent_thread(s, tid);
    s->agent_tid_cache[tid] = a;
    return a;
}
static void inplace_suspend(probe_session *s, DWORD tid) {
    if (tid == s->inplace_owner || inplace_exempt(s, tid)) return;
    for (auto &e : s->inplace_suspended) if (e.first == tid) return;
    HANDLE t = OpenThread(THREAD_SUSPEND_RESUME, FALSE, tid);
    if (!t) return;
    guard_note_hold(s, tid);
    if (SuspendThread(t) == (DWORD)-1) { CloseHandle(t); return; }
    try { s->inplace_suspended.emplace_back(tid, t); } catch (...) { ResumeThread(t); CloseHandle(t); }
}
void inplace_begin(probe_session *s, DWORD tid) {
    if (s->inplace_owner) return;            // ours already, or tid is held in another thread's
                                             // window and gets it handed over (inplace_sync)
    s->inplace_owner = tid; s->inplace_since = GetTickCount64();
    for (DWORD o : s->threads) if (o != tid) inplace_suspend(s, o);
}
void inplace_release_all(probe_session *s) {
    const bool any = !s->inplace_suspended.empty();
    for (auto &e : s->inplace_suspended) { ResumeThread(e.second); CloseHandle(e.second); }
    s->inplace_suspended.clear();
    s->inplace_owner = 0;
    if (any) guard_resync(s);                                // our suspensions are over: off the list
}
void inplace_watchdog(probe_session *s) {
    if (!s->inplace_owner || GetTickCount64() - s->inplace_since < 2000) return;
    if (!s->inplace_warned) {
        s->inplace_warned = true;
        std::fprintf(stderr, "probe: warning: in-place step on thread %lu not done within 2 s: other threads released "
                             "(a call through that site meanwhile may be missed). Further cases are not reported.\n",
                     (unsigned long)s->inplace_owner);
    }
    if (auto it = s->stepping.find(s->inplace_owner); it != s->stepping.end()) {
        if (it->second.refire) {
            // A faulted instruction re-run without our trap flag did not fault again (the memory
            // changed meanwhile): it ran on with the byte lifted. Arm the site again.
            end_inplace_step(s, it->first, it->second.site);
            s->stepping.erase(it);
        } else {
            it->second.windowed = false;
        }
    }
    inplace_release_all(s);
}
// After every debug event: the window lasts exactly as long as its owner's in-place step.
void inplace_sync(probe_session *s, const DEBUG_EVENT &ev) {
    if (ev.dwDebugEventCode == EXIT_THREAD_DEBUG_EVENT) s->agent_tid_cache.erase(ev.dwThreadId);
    if (!s->inplace_owner) return;
    if (ev.dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT) inplace_suspend(s, ev.dwThreadId);   // born in the window
    auto pending = [&](DWORD tid) {
        auto it = s->stepping.find(tid);
        return it != s->stepping.end() && !it->second.displaced && it->second.windowed;
    };
    if (pending(s->inplace_owner)) { inplace_watchdog(s); return; }
    // Hand the window to another thread whose own in-place step is pending (it is held in
    // this window) without letting any other thread run in between.
    DWORD next = 0;
    for (auto &kv : s->stepping) if (kv.first != s->inplace_owner && pending(kv.first)) { next = kv.first; break; }
    if (!next) { inplace_release_all(s); return; }
    const DWORD prev = s->inplace_owner;
    s->inplace_owner = next; s->inplace_since = GetTickCount64();
    for (auto it = s->inplace_suspended.begin(); it != s->inplace_suspended.end(); ++it)
        if (it->first == next) { ResumeThread(it->second); CloseHandle(it->second); s->inplace_suspended.erase(it); break; }
    if (s->threads.count(prev)) inplace_suspend(s, prev);
}

// What an in-place step of the site needs: a pushed flags image to correct (PUSHF), and
// whether the instruction may block in the kernel or leave 32-bit code (then no window).
void site_traits(const Probe &p, bool &pushf, bool &may_block) {
    pushf = false; may_block = false;
    ZydisDecoder dec;
#if defined(_WIN64)
    ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
#else
    ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_STACK_WIDTH_32);
#endif
    ZydisDecodedInstruction in; ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
    if (p.orig_insn.empty() || !ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, p.orig_insn.data(), p.orig_insn.size(), &in, ops))) {
        may_block = true; return;                           // unknown: stay as before (no window)
    }
    switch (in.mnemonic) {
        case ZYDIS_MNEMONIC_PUSHF: case ZYDIS_MNEMONIC_PUSHFD: case ZYDIS_MNEMONIC_PUSHFQ: pushf = true; break;
        case ZYDIS_MNEMONIC_SYSCALL: case ZYDIS_MNEMONIC_SYSENTER: case ZYDIS_MNEMONIC_IRET:
        case ZYDIS_MNEMONIC_IRETD: case ZYDIS_MNEMONIC_IRETQ: may_block = true; break;
        case ZYDIS_MNEMONIC_INT:
            may_block = ops[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && (ops[0].imm.value.u == 0x2E || ops[0].imm.value.u == 0x2B);
            break;
        default: break;
    }
    if (in.meta.branch_type == ZYDIS_BRANCH_TYPE_FAR) may_block = true;
}

// Per-thread out-of-line step buffer in the target (executable), allocated on demand.

// Reserve+commit one 64 KiB block as close as possible to `site` (within +-2 GiB on x64).
static uint64_t alloc_block_near(probe_session *s, uint64_t site) {
#if defined(_WIN64)
    const uint64_t gran = 0x10000, span = 0x7FF00000ull;
    uint64_t lo = site > span ? site - span : gran, hi = site + span;
    for (int dir = 0; dir < 2; ++dir) {                  // search down from the site, then up
        uint64_t a = (site & ~(gran - 1));
        for (int steps = 0; steps < 4096; ++steps) {
            a = dir == 0 ? a - gran : a + gran;
            if (a < lo || a > hi) break;
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQueryEx(s->pi.hProcess, (void *)(uintptr_t)a, &mbi, sizeof(mbi))) continue;
            if (mbi.State != MEM_FREE) {                   // skip the whole occupied region
                uint64_t rb = (uint64_t)(uintptr_t)mbi.BaseAddress, rs = mbi.RegionSize;
                a = dir == 0 ? (rb & ~(gran - 1)) : ((rb + rs + gran - 1) & ~(gran - 1)) - gran;
                continue;
            }
            void *m = VirtualAllocEx(s->pi.hProcess, (void *)(uintptr_t)a, gran, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (m) return (uint64_t)(uintptr_t)m;
        }
    }
#endif
    (void)site;
    void *m = VirtualAllocEx(s->pi.hProcess, nullptr, 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    return m ? (uint64_t)(uintptr_t)m : 0;
}

#if defined(_WIN64)
// Per-site trampoline for an x64 SYSCALL / INT 2E site: `insn; mov rcx, site+len (SYSCALL
// only: the CPU leaves the return address there); jmp [rip+0]; dq site+len`. Shared by every
// thread and every nesting level (it holds no per-execution state), never freed (a thread may
// be blocked inside its syscall across a detach). 0 = not such a site / no memory.
uint64_t syscall_trampoline(probe_session *s, Probe &p) {
    if (p.tramp) return p.tramp;
    if (p.insn_len != 2 || p.orig_insn.size() != 2) return 0;
    const bool sc = p.orig_insn[0] == 0x0F && p.orig_insn[1] == 0x05, i2e = p.orig_insn[0] == 0xCD && p.orig_insn[1] == 0x2E;
    if (!sc && !i2e) return 0;
    if (s->tramp_next + 32 > s->tramp_end) {
        void *m = VirtualAllocEx(s->pi.hProcess, nullptr, 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!m) return 0;
        s->tramp_next = (uint64_t)(uintptr_t)m; s->tramp_end = s->tramp_next + 0x10000;
    }
    const uint64_t back = p.address + 2;
    std::vector<unsigned char> code(p.orig_insn.begin(), p.orig_insn.end());
    if (sc) { code.push_back(0x48); code.push_back(0xB9); for (int b = 0; b < 8; ++b) code.push_back((unsigned char)(back >> (8 * b))); }
    const unsigned char jmp[6] = {0xFF, 0x25, 0, 0, 0, 0};
    code.insert(code.end(), jmp, jmp + 6);
    for (int b = 0; b < 8; ++b) code.push_back((unsigned char)(back >> (8 * b)));
    size_t wrote = 0;
    if (!remote_write(s->pi.hProcess, s->tramp_next, code.data(), code.size(), &wrote) || wrote != code.size()) return 0;
    FlushInstructionCache(s->pi.hProcess, (void *)(uintptr_t)s->tramp_next, code.size());
    p.tramp = s->tramp_next; s->tramp_next += 32;
    return p.tramp;
}
#endif

uint64_t thread_scratch(probe_session *s, DWORD tid, uint64_t site) {
    uint64_t region = site >> 30;
    auto key = std::make_pair(tid, region);
    auto it = s->scratch.find(key);
    if (it != s->scratch.end()) return it->second;
    auto &pool = s->scratch_free[region];
    if (pool.empty()) {
        uint64_t block = alloc_block_near(s, site);
        if (!block) return 0;
        s->scratch_blocks.push_back(block);
        for (uint64_t off = 0x10000; off >= 64; off -= 64) pool.push_back(block + off - 64);
    }
    uint64_t slot = pool.back(); pool.pop_back();
    s->scratch[key] = slot;
    return slot;
}

// The out-of-line copy of a displaced breakpoint site: `insn (RIP-relative operand retargeted);
// jmp site+len`, one per site, shared by every thread (it holds no per-execution state). A hit
// resumes the thread there with NO trap flag: the copy runs and jumps back by itself, so a hit
// costs ONE debug event, not two (INT3 + single-step) -- every event freezes the whole target,
// and the second one doubled that (ROADMAP A5). A REP string op runs to completion in it. A
// fault in the copy is mapped back to the real instruction (handle_exception: re-run in place),
// as are a watch hit in it (handle_hw) and a thread inside it at a detach. 0 = cannot build one
// (the caller takes the stepping path).
uint64_t displaced_trampoline(probe_session *s, Probe &p) {
    // Reused only for the same instruction at the same address: a module reloaded at the same
    // base may hold different code there (another build of the DLL), re-read by arm_breakpoint.
    if (p.dtramp && p.dtramp_site == p.address && p.dtramp_insn == p.orig_insn) return p.dtramp;
    if (!p.displaced_ok || p.orig_insn.empty() || !p.address || p.insn_len != p.orig_insn.size()) return 0;
    auto &pool = s->dtramp_pool[p.address >> 30];
    if (pool.first + 64 > pool.second) {
        const uint64_t block = alloc_block_near(s, p.address);
        if (!block) return 0;
        s->scratch_blocks.push_back(block);            // the guard's list of our code; freed at close
        pool = {block, block + 0x10000};
        guard_sync(s);
    }
    const uint64_t at = pool.first, back = p.address + p.insn_len;
    std::vector<unsigned char> code = p.orig_insn;
    if (p.riprel_disp_off >= 0) {
        int32_t disp; std::memcpy(&disp, code.data() + p.riprel_disp_off, sizeof(disp));
        const int64_t nd = (int64_t)disp + (int64_t)(p.address - at);
        if (nd < INT32_MIN || nd > INT32_MAX) return 0;
        const int32_t v = (int32_t)nd; std::memcpy(code.data() + p.riprel_disp_off, &v, sizeof(v));
    }
#if defined(_WIN64)
    const unsigned char jmp[6] = {0xFF, 0x25, 0, 0, 0, 0};    // jmp [rip+0]; dq back
    code.insert(code.end(), jmp, jmp + 6);
    for (int b = 0; b < 8; ++b) code.push_back((unsigned char)(back >> (8 * b)));
#else
    const uint32_t rel = (uint32_t)(back - (at + code.size() + 5));
    code.push_back(0xE9);                                       // jmp rel32
    for (int b = 0; b < 4; ++b) code.push_back((unsigned char)(rel >> (8 * b)));
#endif
    if (code.size() > 64) return 0;
    size_t wrote = 0;
    if (!remote_write(s->pi.hProcess, at, code.data(), code.size(), &wrote) || wrote != code.size()) return 0;
    FlushInstructionCache(s->pi.hProcess, (void *)(uintptr_t)at, code.size());
    pool.first += 64;
    p.dtramp = at; p.dtramp_site = p.address; p.dtramp_insn = p.orig_insn;
    probe_session::DTramp d; d.site = p.address; d.len = p.insn_len; d.probe = &p;
    s->dtramps[at] = d;
    return at;
}
// set_mem changed writable code. Retain old trampoline allocations for threads already
// executing them, but decode the program's new bytes before the current hit resumes.
bool refresh_breakpoint(probe_session *s, Probe &p) {
    unsigned char buf[16]; size_t got = 0;
    if (!remote_read(s->pi.hProcess, p.address, buf, sizeof(buf), &got) || got != sizeof(buf)) return false;
    for (const auto &q : s->probes)
        if (q->active && (q->flags & PROBE_BREAKPOINT) && q->address >= p.address &&
            q->address - p.address < sizeof(buf) && buf[q->address - p.address] == 0xcc)
            buf[q->address - p.address] = q->original;
    uint32_t len = 0; bool disp = false, rep = false; int riprel = -1;
    if (!decode_site(buf, sizeof(buf), len, disp, riprel, &rep) || !len) return false;
    p.orig_insn.assign(buf, buf + len); p.follow.assign(buf + 1, buf + sizeof(buf));
    p.insn_len = len; p.displaced_ok = disp; p.riprel_disp_off = riprel; p.rep_string = rep;
    p.tramp = 0; p.dtramp = 0; p.dtramp_site = 0;
    return true;
}
// A hardware execute probe's site as a displaced trampoline: an execute hit resumes there
// instead of at the site with RF. RF lives only until the instruction runs; a context the
// target captures in between (Suspend + Get/SetThreadContext, ROADMAP A4) comes back with RF
// clear, and the same call was reported twice. Rebuilt whenever the code at the site is not
// what the copy holds (the program may patch its own code: hardware probes never do).
// 0 = not displaceable (the caller sets RF as before).
uint64_t hw_trampoline(probe_session *s, Probe &p) {
    if (!(p.flags & PROBE_HW) || (p.flags & (PROBE_WATCH_WRITE | PROBE_WATCH_RW)) || !p.address) return 0;
    unsigned char buf[16]; size_t got = 0;
    if (!remote_read(s->pi.hProcess, p.address, buf, sizeof(buf), &got) || got != sizeof(buf) || buf[0] == 0xcc) return 0;
    if (p.dtramp && p.dtramp_site == p.address && p.insn_len && p.insn_len <= sizeof(buf) &&
        p.orig_insn.size() == p.insn_len && !std::memcmp(buf, p.orig_insn.data(), p.insn_len))
        return p.dtramp;
    uint32_t len = 0; bool disp_ok = false, rep_str = false; int riprel = -1;
    if (!decode_site(buf, sizeof(buf), len, disp_ok, riprel, &rep_str) || !len || len > sizeof(buf) || !disp_ok) return 0;
    p.orig_insn.assign(buf, buf + len); p.insn_len = len; p.displaced_ok = true; p.riprel_disp_off = riprel;
    p.rep_string = rep_str;
    p.dtramp = 0; p.dtramp_site = 0;                       // the old copy (if any) stays for threads inside it
    return displaced_trampoline(s, p);
}
// The displaced trampoline `a` lies in (its copy or the jump right after it), if any.
const probe_session::DTramp *dtramp_at(const probe_session *s, uint64_t a, uint64_t *start) {
    auto it = s->dtramps.upper_bound(a);
    if (it == s->dtramps.begin()) return nullptr;
    --it;
    if (a < it->first || a > it->first + it->second.len) return nullptr;
    if (start) *start = it->first;
    return &it->second;
}
// The agent's copy of the armed INT3s (probe_agent_shared::int3): rewritten whole after any
// breakpoint probe is armed or disarmed.
void sync_int3_table(probe_session *s) {
    if (!s->shared) return;
    auto *sh = s->shared;
    InterlockedIncrement(&sh->int3_seq);                // odd: being rewritten
    MemoryBarrier();
    LONG n = 0;
    for (auto &p : s->probes)
        if (int3_entry(*p) && n < (LONG)PROBE_AGENT_INT3_CAP) {
            sh->int3[n].address = p->address; sh->int3[n].original = p->original; ++n;
        }
    // Sorted by address: the agent finds the entries in a read's range by binary search.
    std::sort(sh->int3, sh->int3 + n, [](const probe_agent_int3 &x, const probe_agent_int3 &y) { return x.address < y.address; });
    sh->int3_count = n;
    MemoryBarrier();
    InterlockedIncrement(&sh->int3_seq);
}

} // namespace uhh_session
