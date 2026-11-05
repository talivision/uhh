; GENERATED shape fixtures for regress `inplace-*` (see ctrl_target.cpp, run_shape).
; Every shape exists twice: Shape_<name>_P (probed at Shape_<name>_P_Insn) and Shape_<name>_R
; (never probed, the reference): the target compares their results call by call.
; At the probed instruction EDX holds the call's unique tag (the callback logs it).
OPTION CASEMAP:NONE
EXTERN g_tls_off:QWORD
EXTERN g_ssn:DWORD
PUBLIC Shape_jmp8_P
PUBLIC Shape_jmp8_P_Insn
PUBLIC Shape_jmp8_R
PUBLIC Shape_jmp8_R_Insn
PUBLIC Shape_jmp32_P
PUBLIC Shape_jmp32_P_Insn
PUBLIC Shape_jmp32_R
PUBLIC Shape_jmp32_R_Insn
PUBLIC Shape_jcc8_taken_P
PUBLIC Shape_jcc8_taken_P_Insn
PUBLIC Shape_jcc8_taken_R
PUBLIC Shape_jcc8_taken_R_Insn
PUBLIC Shape_jcc8_not_P
PUBLIC Shape_jcc8_not_P_Insn
PUBLIC Shape_jcc8_not_R
PUBLIC Shape_jcc8_not_R_Insn
PUBLIC Shape_jcc8_alt_P
PUBLIC Shape_jcc8_alt_P_Insn
PUBLIC Shape_jcc8_alt_R
PUBLIC Shape_jcc8_alt_R_Insn
PUBLIC Shape_jcc32_taken_P
PUBLIC Shape_jcc32_taken_P_Insn
PUBLIC Shape_jcc32_taken_R
PUBLIC Shape_jcc32_taken_R_Insn
PUBLIC Shape_call32_P
PUBLIC Shape_call32_P_Insn
PUBLIC Shape_call32_R
PUBLIC Shape_call32_R_Insn
PUBLIC Shape_callmem_P
PUBLIC Shape_callmem_P_Insn
PUBLIC Shape_callmem_R
PUBLIC Shape_callmem_R_Insn
PUBLIC Shape_ret_P
PUBLIC Shape_ret_P_Insn
PUBLIC Shape_ret_R
PUBLIC Shape_ret_R_Insn
PUBLIC Shape_loop_taken_P
PUBLIC Shape_loop_taken_P_Insn
PUBLIC Shape_loop_taken_R
PUBLIC Shape_loop_taken_R_Insn
PUBLIC Shape_loop_not_P
PUBLIC Shape_loop_not_P_Insn
PUBLIC Shape_loop_not_R
PUBLIC Shape_loop_not_R_Insn
PUBLIC Shape_loopz_P
PUBLIC Shape_loopz_P_Insn
PUBLIC Shape_loopz_R
PUBLIC Shape_loopz_R_Insn
PUBLIC Shape_loopnz_P
PUBLIC Shape_loopnz_P_Insn
PUBLIC Shape_loopnz_R
PUBLIC Shape_loopnz_R_Insn
PUBLIC Shape_jrcxz_P
PUBLIC Shape_jrcxz_P_Insn
PUBLIC Shape_jrcxz_R
PUBLIC Shape_jrcxz_R_Insn
PUBLIC Shape_loop_a32_P
PUBLIC Shape_loop_a32_P_Insn
PUBLIC Shape_loop_a32_R
PUBLIC Shape_loop_a32_R_Insn
PUBLIC Shape_jecxz_a32_P
PUBLIC Shape_jecxz_a32_P_Insn
PUBLIC Shape_jecxz_a32_R
PUBLIC Shape_jecxz_a32_R_Insn
PUBLIC Shape_pushf_P
PUBLIC Shape_pushf_P_Insn
PUBLIC Shape_pushf_R
PUBLIC Shape_pushf_R_Insn
PUBLIC Shape_pushf_guard_P
PUBLIC Shape_pushf_guard_P_Insn
PUBLIC Shape_pushf_guard_R
PUBLIC Shape_pushf_guard_R_Insn
PUBLIC Shape_segjmp_P
PUBLIC Shape_segjmp_P_Insn
PUBLIC Shape_segjmp_R
PUBLIC Shape_segjmp_R_Insn
PUBLIC Shape_syscall_P
PUBLIC Shape_syscall_P_Insn
PUBLIC Shape_syscall_R
PUBLIC Shape_syscall_R_Insn
.data
Shape_callmem_P_Ptr DQ Shape_callmem_P_Callee
Shape_callmem_R_Ptr DQ Shape_callmem_R_Callee
.code
Shape_jmp8_P PROC
    mov edx, ecx
    xor eax, eax
Shape_jmp8_P_Insn::
    DB 0EBh, 05h                  ; jmp rel8 +5
    DB 05h, 63h, 0, 0, 0          ; add eax, 99 (only on the not-taken path)
    add eax, edx
    ret
Shape_jmp8_P ENDP
Shape_jmp8_R PROC
    mov edx, ecx
    xor eax, eax
Shape_jmp8_R_Insn::
    DB 0EBh, 05h                  ; jmp rel8 +5
    DB 05h, 63h, 0, 0, 0          ; add eax, 99 (only on the not-taken path)
    add eax, edx
    ret
Shape_jmp8_R ENDP
Shape_jmp32_P PROC
    mov edx, ecx
    xor eax, eax
Shape_jmp32_P_Insn::
    DB 0E9h
    DD 5                          ; jmp rel32 +5
    DB 05h, 63h, 0, 0, 0          ; add eax, 99 (only on the not-taken path)
    add eax, edx
    ret
Shape_jmp32_P ENDP
Shape_jmp32_R PROC
    mov edx, ecx
    xor eax, eax
Shape_jmp32_R_Insn::
    DB 0E9h
    DD 5                          ; jmp rel32 +5
    DB 05h, 63h, 0, 0, 0          ; add eax, 99 (only on the not-taken path)
    add eax, edx
    ret
Shape_jmp32_R ENDP
Shape_jcc8_taken_P PROC
    mov edx, ecx
    xor eax, eax
    cmp edx, edx
Shape_jcc8_taken_P_Insn::
    DB 74h, 05h                   ; jz rel8 (taken)
    DB 05h, 63h, 0, 0, 0          ; add eax, 99 (only on the not-taken path)
    add eax, edx
    ret
Shape_jcc8_taken_P ENDP
Shape_jcc8_taken_R PROC
    mov edx, ecx
    xor eax, eax
    cmp edx, edx
Shape_jcc8_taken_R_Insn::
    DB 74h, 05h                   ; jz rel8 (taken)
    DB 05h, 63h, 0, 0, 0          ; add eax, 99 (only on the not-taken path)
    add eax, edx
    ret
Shape_jcc8_taken_R ENDP
Shape_jcc8_not_P PROC
    mov edx, ecx
    xor eax, eax
    cmp edx, edx
Shape_jcc8_not_P_Insn::
    DB 75h, 05h                   ; jnz rel8 (not taken)
    DB 05h, 63h, 0, 0, 0          ; add eax, 99 (only on the not-taken path)
    add eax, edx
    ret
Shape_jcc8_not_P ENDP
Shape_jcc8_not_R PROC
    mov edx, ecx
    xor eax, eax
    cmp edx, edx
Shape_jcc8_not_R_Insn::
    DB 75h, 05h                   ; jnz rel8 (not taken)
    DB 05h, 63h, 0, 0, 0          ; add eax, 99 (only on the not-taken path)
    add eax, edx
    ret
Shape_jcc8_not_R ENDP
Shape_jcc8_alt_P PROC
    mov edx, ecx
    xor eax, eax
    test dl, 1
Shape_jcc8_alt_P_Insn::
    DB 74h, 05h                   ; jz rel8: taken for even tags
    DB 05h, 63h, 0, 0, 0          ; add eax, 99 (only on the not-taken path)
    add eax, edx
    ret
Shape_jcc8_alt_P ENDP
Shape_jcc8_alt_R PROC
    mov edx, ecx
    xor eax, eax
    test dl, 1
Shape_jcc8_alt_R_Insn::
    DB 74h, 05h                   ; jz rel8: taken for even tags
    DB 05h, 63h, 0, 0, 0          ; add eax, 99 (only on the not-taken path)
    add eax, edx
    ret
Shape_jcc8_alt_R ENDP
Shape_jcc32_taken_P PROC
    mov edx, ecx
    xor eax, eax
    cmp edx, edx
Shape_jcc32_taken_P_Insn::
    DB 0Fh, 84h
    DD 5                          ; jz rel32 (taken)
    DB 05h, 63h, 0, 0, 0          ; add eax, 99 (only on the not-taken path)
    add eax, edx
    ret
Shape_jcc32_taken_P ENDP
Shape_jcc32_taken_R PROC
    mov edx, ecx
    xor eax, eax
    cmp edx, edx
Shape_jcc32_taken_R_Insn::
    DB 0Fh, 84h
    DD 5                          ; jz rel32 (taken)
    DB 05h, 63h, 0, 0, 0          ; add eax, 99 (only on the not-taken path)
    add eax, edx
    ret
Shape_jcc32_taken_R ENDP
Shape_call32_P PROC
    mov edx, ecx
Shape_call32_P_Insn::
    call Shape_call32_P_Callee
Shape_call32_P_After::
    add rax, rdx
    ret
Shape_call32_P_Callee::
    mov rax, qword ptr [rsp]
    lea r8, Shape_call32_P_After
    sub rax, r8                   ; 0 when the pushed return address is right
    ret
Shape_call32_P ENDP
Shape_call32_R PROC
    mov edx, ecx
Shape_call32_R_Insn::
    call Shape_call32_R_Callee
Shape_call32_R_After::
    add rax, rdx
    ret
Shape_call32_R_Callee::
    mov rax, qword ptr [rsp]
    lea r8, Shape_call32_R_After
    sub rax, r8                   ; 0 when the pushed return address is right
    ret
Shape_call32_R ENDP
Shape_callmem_P PROC
    mov edx, ecx
Shape_callmem_P_Insn::
    call qword ptr [Shape_callmem_P_Ptr]
Shape_callmem_P_After::
    add rax, rdx
    ret
Shape_callmem_P_Callee::
    mov rax, qword ptr [rsp]
    lea r8, Shape_callmem_P_After
    sub rax, r8
    ret
Shape_callmem_P ENDP
Shape_callmem_R PROC
    mov edx, ecx
Shape_callmem_R_Insn::
    call qword ptr [Shape_callmem_R_Ptr]
Shape_callmem_R_After::
    add rax, rdx
    ret
Shape_callmem_R_Callee::
    mov rax, qword ptr [rsp]
    lea r8, Shape_callmem_R_After
    sub rax, r8
    ret
Shape_callmem_R ENDP
Shape_ret_P PROC
    mov edx, ecx
    call Shape_ret_P_Callee
    add rax, rdx
    ret
Shape_ret_P_Callee::
    mov eax, 5
Shape_ret_P_Insn::
    ret
Shape_ret_P ENDP
Shape_ret_R PROC
    mov edx, ecx
    call Shape_ret_R_Callee
    add rax, rdx
    ret
Shape_ret_R_Callee::
    mov eax, 5
Shape_ret_R_Insn::
    ret
Shape_ret_R ENDP
Shape_loop_taken_P PROC
    mov edx, ecx
    xor eax, eax
    mov rcx, 100000002h
Shape_loop_taken_P_Insn::
    DB 0E2h, 05h                  ; loop (rcx 0x100000002 -> taken)
    DB 05h, 63h, 0, 0, 0          ; add eax, 99 (only on the not-taken path)
    add rax, rcx
    add rax, rdx
    ret
Shape_loop_taken_P ENDP
Shape_loop_taken_R PROC
    mov edx, ecx
    xor eax, eax
    mov rcx, 100000002h
Shape_loop_taken_R_Insn::
    DB 0E2h, 05h                  ; loop (rcx 0x100000002 -> taken)
    DB 05h, 63h, 0, 0, 0          ; add eax, 99 (only on the not-taken path)
    add rax, rcx
    add rax, rdx
    ret
Shape_loop_taken_R ENDP
Shape_loop_not_P PROC
    mov edx, ecx
    xor eax, eax
    mov ecx, 1
Shape_loop_not_P_Insn::
    DB 0E2h, 05h                  ; loop (rcx 1 -> not taken)
    DB 05h, 63h, 0, 0, 0          ; add eax, 99 (only on the not-taken path)
    add rax, rcx
    add rax, rdx
    ret
Shape_loop_not_P ENDP
Shape_loop_not_R PROC
    mov edx, ecx
    xor eax, eax
    mov ecx, 1
Shape_loop_not_R_Insn::
    DB 0E2h, 05h                  ; loop (rcx 1 -> not taken)
    DB 05h, 63h, 0, 0, 0          ; add eax, 99 (only on the not-taken path)
    add rax, rcx
    add rax, rdx
    ret
Shape_loop_not_R ENDP
Shape_loopz_P PROC
    mov edx, ecx
    mov ecx, 3
    xor eax, eax
Shape_loopz_P_Insn::
    DB 0E1h, 05h                  ; loopz (ZF=1, rcx 3 -> taken)
    DB 05h, 63h, 0, 0, 0          ; add eax, 99 (only on the not-taken path)
    add rax, rcx
    add rax, rdx
    ret
Shape_loopz_P ENDP
Shape_loopz_R PROC
    mov edx, ecx
    mov ecx, 3
    xor eax, eax
Shape_loopz_R_Insn::
    DB 0E1h, 05h                  ; loopz (ZF=1, rcx 3 -> taken)
    DB 05h, 63h, 0, 0, 0          ; add eax, 99 (only on the not-taken path)
    add rax, rcx
    add rax, rdx
    ret
Shape_loopz_R ENDP
Shape_loopnz_P PROC
    mov edx, ecx
    mov ecx, 3
    xor eax, eax
Shape_loopnz_P_Insn::
    DB 0E0h, 05h                  ; loopnz (ZF=1 -> not taken)
    DB 05h, 63h, 0, 0, 0          ; add eax, 99 (only on the not-taken path)
    add rax, rcx
    add rax, rdx
    ret
Shape_loopnz_P ENDP
Shape_loopnz_R PROC
    mov edx, ecx
    mov ecx, 3
    xor eax, eax
Shape_loopnz_R_Insn::
    DB 0E0h, 05h                  ; loopnz (ZF=1 -> not taken)
    DB 05h, 63h, 0, 0, 0          ; add eax, 99 (only on the not-taken path)
    add rax, rcx
    add rax, rdx
    ret
Shape_loopnz_R ENDP
Shape_jrcxz_P PROC
    mov edx, ecx
    mov ecx, edx
    and ecx, 1
    xor eax, eax
Shape_jrcxz_P_Insn::
    DB 0E3h, 05h                  ; jrcxz: taken for even tags
    DB 05h, 63h, 0, 0, 0          ; add eax, 99 (only on the not-taken path)
    add rax, rcx
    add rax, rdx
    ret
Shape_jrcxz_P ENDP
Shape_jrcxz_R PROC
    mov edx, ecx
    mov ecx, edx
    and ecx, 1
    xor eax, eax
Shape_jrcxz_R_Insn::
    DB 0E3h, 05h                  ; jrcxz: taken for even tags
    DB 05h, 63h, 0, 0, 0          ; add eax, 99 (only on the not-taken path)
    add rax, rcx
    add rax, rdx
    ret
Shape_jrcxz_R ENDP
Shape_loop_a32_P PROC
    mov edx, ecx
    mov rcx, 0FFFFFFFF00000001h
    mov r8d, edx
    and r8d, 1
    add rcx, r8
    xor eax, eax
Shape_loop_a32_P_Insn::
    DB 67h, 0E2h, 05h             ; addr32 loop (ecx 2 -> taken, 1 -> not; upper rcx as the CPU leaves it)
    DB 05h, 63h, 0, 0, 0          ; add eax, 99 (only on the not-taken path)
    add rax, rcx
    add rax, rdx
    ret
Shape_loop_a32_P ENDP
Shape_loop_a32_R PROC
    mov edx, ecx
    mov rcx, 0FFFFFFFF00000001h
    mov r8d, edx
    and r8d, 1
    add rcx, r8
    xor eax, eax
Shape_loop_a32_R_Insn::
    DB 67h, 0E2h, 05h             ; addr32 loop (ecx 2 -> taken, 1 -> not; upper rcx as the CPU leaves it)
    DB 05h, 63h, 0, 0, 0          ; add eax, 99 (only on the not-taken path)
    add rax, rcx
    add rax, rdx
    ret
Shape_loop_a32_R ENDP
Shape_jecxz_a32_P PROC
    mov edx, ecx
    mov rcx, 100000000h
    mov r8d, edx
    and r8d, 1
    add rcx, r8
    xor eax, eax
Shape_jecxz_a32_P_Insn::
    DB 67h, 0E3h, 05h             ; jecxz: taken for even tags (rcx != 0)
    DB 05h, 63h, 0, 0, 0          ; add eax, 99 (only on the not-taken path)
    add rax, rcx
    add rax, rdx
    ret
Shape_jecxz_a32_P ENDP
Shape_jecxz_a32_R PROC
    mov edx, ecx
    mov rcx, 100000000h
    mov r8d, edx
    and r8d, 1
    add rcx, r8
    xor eax, eax
Shape_jecxz_a32_R_Insn::
    DB 67h, 0E3h, 05h             ; jecxz: taken for even tags (rcx != 0)
    DB 05h, 63h, 0, 0, 0          ; add eax, 99 (only on the not-taken path)
    add rax, rcx
    add rax, rdx
    ret
Shape_jecxz_a32_R ENDP
Shape_pushf_P PROC
    mov edx, ecx
    xor eax, eax
Shape_pushf_P_Insn::
    pushfq
    pop rax
    mov r8d, edx
    shl r8, 32
    or rax, r8
    ret
Shape_pushf_P ENDP
Shape_pushf_R PROC
    mov edx, ecx
    xor eax, eax
Shape_pushf_R_Insn::
    pushfq
    pop rax
    mov r8d, edx
    shl r8, 32
    or rax, r8
    ret
Shape_pushf_R ENDP
Shape_pushf_guard_P PROC
    mov edx, ecx
    mov r9, rsp
    mov rsp, qword ptr gs:[10h]  ; NT_TIB.StackLimit: the push lands in the guard page
    xor eax, eax
Shape_pushf_guard_P_Insn::
    pushfq
    pop rax
    mov rsp, r9
    mov r8d, edx
    shl r8, 32
    or rax, r8
    ret
Shape_pushf_guard_P ENDP
Shape_pushf_guard_R PROC
    mov edx, ecx
    mov r9, rsp
    mov rsp, qword ptr gs:[10h]  ; NT_TIB.StackLimit: the push lands in the guard page
    xor eax, eax
Shape_pushf_guard_R_Insn::
    pushfq
    pop rax
    mov rsp, r9
    mov r8d, edx
    shl r8, 32
    or rax, r8
    ret
Shape_pushf_guard_R ENDP
Shape_segjmp_P PROC
    mov edx, ecx
    mov r8, qword ptr [g_tls_off]
    lea rax, Shape_segjmp_P_Cont
    mov qword ptr gs:[r8], rax
    xor eax, eax
Shape_segjmp_P_Insn::
    jmp qword ptr gs:[r8]         ; segment-relative indirect jump (not emulated)
    DB 05h, 63h, 0, 0, 0          ; add eax, 99 (only on the not-taken path)
Shape_segjmp_P_Cont::
    add eax, edx
    ret
Shape_segjmp_P ENDP
Shape_segjmp_R PROC
    mov edx, ecx
    mov r8, qword ptr [g_tls_off]
    lea rax, Shape_segjmp_R_Cont
    mov qword ptr gs:[r8], rax
    xor eax, eax
Shape_segjmp_R_Insn::
    jmp qword ptr gs:[r8]         ; segment-relative indirect jump (not emulated)
    DB 05h, 63h, 0, 0, 0          ; add eax, 99 (only on the not-taken path)
Shape_segjmp_R_Cont::
    add eax, edx
    ret
Shape_segjmp_R ENDP
Shape_syscall_P PROC
    mov edx, ecx
    mov r10, rcx
    mov eax, dword ptr [g_ssn]  ; NtYieldExecution
Shape_syscall_P_Insn::
    syscall
Shape_syscall_P_Ret::
    lea r8, Shape_syscall_P_Ret
    sub rcx, r8                   ; RCX = the instruction after the syscall
    and r11d, 100h               ; TF in the saved flags image
    lea rax, [rcx + r11]          ; (RDX is not preserved by the kernel)
    ret
Shape_syscall_P ENDP
Shape_syscall_R PROC
    mov edx, ecx
    mov r10, rcx
    mov eax, dword ptr [g_ssn]  ; NtYieldExecution
Shape_syscall_R_Insn::
    syscall
Shape_syscall_R_Ret::
    lea r8, Shape_syscall_R_Ret
    sub rcx, r8                   ; RCX = the instruction after the syscall
    and r11d, 100h               ; TF in the saved flags image
    lea rax, [rcx + r11]          ; (RDX is not preserved by the kernel)
    ret
Shape_syscall_R ENDP
END
