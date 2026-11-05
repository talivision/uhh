; GENERATED shape fixtures for regress `inplace-*` (see ctrl_target.cpp, run_shape).
; Every shape exists twice: Shape_<name>_P (probed at Shape_<name>_P_Insn) and Shape_<name>_R
; (never probed, the reference): the target compares their results call by call.
; At the probed instruction EDX holds the call's unique tag (the callback logs it).
.686
.model flat, C
ASSUME FS:NOTHING
OPTION CASEMAP:NONE
EXTERN g_tls_off:DWORD
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
.data
Shape_callmem_P_Ptr DD Shape_callmem_P_Callee
Shape_callmem_R_Ptr DD Shape_callmem_R_Callee
.code
Shape_jmp8_P PROC
    mov edx, dword ptr [esp+4]
    xor eax, eax
Shape_jmp8_P_Insn::
    DB 0EBh, 05h
    DB 05h, 63h, 0, 0, 0          ; add eax, 99 (only on the not-taken path)
    add eax, edx
    ret
Shape_jmp8_P ENDP
Shape_jmp8_R PROC
    mov edx, dword ptr [esp+4]
    xor eax, eax
Shape_jmp8_R_Insn::
    DB 0EBh, 05h
    DB 05h, 63h, 0, 0, 0          ; add eax, 99 (only on the not-taken path)
    add eax, edx
    ret
Shape_jmp8_R ENDP
Shape_jmp32_P PROC
    mov edx, dword ptr [esp+4]
    xor eax, eax
Shape_jmp32_P_Insn::
    DB 0E9h
    DD 5
    DB 05h, 63h, 0, 0, 0          ; add eax, 99 (only on the not-taken path)
    add eax, edx
    ret
Shape_jmp32_P ENDP
Shape_jmp32_R PROC
    mov edx, dword ptr [esp+4]
    xor eax, eax
Shape_jmp32_R_Insn::
    DB 0E9h
    DD 5
    DB 05h, 63h, 0, 0, 0          ; add eax, 99 (only on the not-taken path)
    add eax, edx
    ret
Shape_jmp32_R ENDP
Shape_jcc8_taken_P PROC
    mov edx, dword ptr [esp+4]
    xor eax, eax
    cmp edx, edx
Shape_jcc8_taken_P_Insn::
    DB 74h, 05h
    DB 05h, 63h, 0, 0, 0          ; add eax, 99 (only on the not-taken path)
    add eax, edx
    ret
Shape_jcc8_taken_P ENDP
Shape_jcc8_taken_R PROC
    mov edx, dword ptr [esp+4]
    xor eax, eax
    cmp edx, edx
Shape_jcc8_taken_R_Insn::
    DB 74h, 05h
    DB 05h, 63h, 0, 0, 0          ; add eax, 99 (only on the not-taken path)
    add eax, edx
    ret
Shape_jcc8_taken_R ENDP
Shape_jcc8_not_P PROC
    mov edx, dword ptr [esp+4]
    xor eax, eax
    cmp edx, edx
Shape_jcc8_not_P_Insn::
    DB 75h, 05h
    DB 05h, 63h, 0, 0, 0          ; add eax, 99 (only on the not-taken path)
    add eax, edx
    ret
Shape_jcc8_not_P ENDP
Shape_jcc8_not_R PROC
    mov edx, dword ptr [esp+4]
    xor eax, eax
    cmp edx, edx
Shape_jcc8_not_R_Insn::
    DB 75h, 05h
    DB 05h, 63h, 0, 0, 0          ; add eax, 99 (only on the not-taken path)
    add eax, edx
    ret
Shape_jcc8_not_R ENDP
Shape_jcc8_alt_P PROC
    mov edx, dword ptr [esp+4]
    xor eax, eax
    test dl, 1
Shape_jcc8_alt_P_Insn::
    DB 74h, 05h
    DB 05h, 63h, 0, 0, 0          ; add eax, 99 (only on the not-taken path)
    add eax, edx
    ret
Shape_jcc8_alt_P ENDP
Shape_jcc8_alt_R PROC
    mov edx, dword ptr [esp+4]
    xor eax, eax
    test dl, 1
Shape_jcc8_alt_R_Insn::
    DB 74h, 05h
    DB 05h, 63h, 0, 0, 0          ; add eax, 99 (only on the not-taken path)
    add eax, edx
    ret
Shape_jcc8_alt_R ENDP
Shape_jcc32_taken_P PROC
    mov edx, dword ptr [esp+4]
    xor eax, eax
    cmp edx, edx
Shape_jcc32_taken_P_Insn::
    DB 0Fh, 84h
    DD 5
    DB 05h, 63h, 0, 0, 0          ; add eax, 99 (only on the not-taken path)
    add eax, edx
    ret
Shape_jcc32_taken_P ENDP
Shape_jcc32_taken_R PROC
    mov edx, dword ptr [esp+4]
    xor eax, eax
    cmp edx, edx
Shape_jcc32_taken_R_Insn::
    DB 0Fh, 84h
    DD 5
    DB 05h, 63h, 0, 0, 0          ; add eax, 99 (only on the not-taken path)
    add eax, edx
    ret
Shape_jcc32_taken_R ENDP
Shape_call32_P PROC
    mov edx, dword ptr [esp+4]
Shape_call32_P_Insn::
    call Shape_call32_P_Callee
Shape_call32_P_After::
    add eax, edx
    ret
Shape_call32_P_Callee::
    mov eax, dword ptr [esp]
    sub eax, OFFSET Shape_call32_P_After
    ret
Shape_call32_P ENDP
Shape_call32_R PROC
    mov edx, dword ptr [esp+4]
Shape_call32_R_Insn::
    call Shape_call32_R_Callee
Shape_call32_R_After::
    add eax, edx
    ret
Shape_call32_R_Callee::
    mov eax, dword ptr [esp]
    sub eax, OFFSET Shape_call32_R_After
    ret
Shape_call32_R ENDP
Shape_callmem_P PROC
    mov edx, dword ptr [esp+4]
Shape_callmem_P_Insn::
    call dword ptr [Shape_callmem_P_Ptr]
Shape_callmem_P_After::
    add eax, edx
    ret
Shape_callmem_P_Callee::
    mov eax, dword ptr [esp]
    sub eax, OFFSET Shape_callmem_P_After
    ret
Shape_callmem_P ENDP
Shape_callmem_R PROC
    mov edx, dword ptr [esp+4]
Shape_callmem_R_Insn::
    call dword ptr [Shape_callmem_R_Ptr]
Shape_callmem_R_After::
    add eax, edx
    ret
Shape_callmem_R_Callee::
    mov eax, dword ptr [esp]
    sub eax, OFFSET Shape_callmem_R_After
    ret
Shape_callmem_R ENDP
Shape_ret_P PROC
    mov edx, dword ptr [esp+4]
    call Shape_ret_P_Callee
    add eax, edx
    ret
Shape_ret_P_Callee::
    mov eax, 5
Shape_ret_P_Insn::
    ret
Shape_ret_P ENDP
Shape_ret_R PROC
    mov edx, dword ptr [esp+4]
    call Shape_ret_R_Callee
    add eax, edx
    ret
Shape_ret_R_Callee::
    mov eax, 5
Shape_ret_R_Insn::
    ret
Shape_ret_R ENDP
Shape_loop_taken_P PROC
    mov edx, dword ptr [esp+4]
    xor eax, eax
    mov ecx, 2
Shape_loop_taken_P_Insn::
    DB 0E2h, 05h
    DB 05h, 63h, 0, 0, 0          ; add eax, 99 (only on the not-taken path)
    add eax, ecx
    add eax, edx
    ret
Shape_loop_taken_P ENDP
Shape_loop_taken_R PROC
    mov edx, dword ptr [esp+4]
    xor eax, eax
    mov ecx, 2
Shape_loop_taken_R_Insn::
    DB 0E2h, 05h
    DB 05h, 63h, 0, 0, 0          ; add eax, 99 (only on the not-taken path)
    add eax, ecx
    add eax, edx
    ret
Shape_loop_taken_R ENDP
Shape_loop_not_P PROC
    mov edx, dword ptr [esp+4]
    xor eax, eax
    mov ecx, 1
Shape_loop_not_P_Insn::
    DB 0E2h, 05h
    DB 05h, 63h, 0, 0, 0          ; add eax, 99 (only on the not-taken path)
    add eax, ecx
    add eax, edx
    ret
Shape_loop_not_P ENDP
Shape_loop_not_R PROC
    mov edx, dword ptr [esp+4]
    xor eax, eax
    mov ecx, 1
Shape_loop_not_R_Insn::
    DB 0E2h, 05h
    DB 05h, 63h, 0, 0, 0          ; add eax, 99 (only on the not-taken path)
    add eax, ecx
    add eax, edx
    ret
Shape_loop_not_R ENDP
Shape_loopz_P PROC
    mov edx, dword ptr [esp+4]
    mov ecx, 3
    xor eax, eax
Shape_loopz_P_Insn::
    DB 0E1h, 05h
    DB 05h, 63h, 0, 0, 0          ; add eax, 99 (only on the not-taken path)
    add eax, ecx
    add eax, edx
    ret
Shape_loopz_P ENDP
Shape_loopz_R PROC
    mov edx, dword ptr [esp+4]
    mov ecx, 3
    xor eax, eax
Shape_loopz_R_Insn::
    DB 0E1h, 05h
    DB 05h, 63h, 0, 0, 0          ; add eax, 99 (only on the not-taken path)
    add eax, ecx
    add eax, edx
    ret
Shape_loopz_R ENDP
Shape_loopnz_P PROC
    mov edx, dword ptr [esp+4]
    mov ecx, 3
    xor eax, eax
Shape_loopnz_P_Insn::
    DB 0E0h, 05h
    DB 05h, 63h, 0, 0, 0          ; add eax, 99 (only on the not-taken path)
    add eax, ecx
    add eax, edx
    ret
Shape_loopnz_P ENDP
Shape_loopnz_R PROC
    mov edx, dword ptr [esp+4]
    mov ecx, 3
    xor eax, eax
Shape_loopnz_R_Insn::
    DB 0E0h, 05h
    DB 05h, 63h, 0, 0, 0          ; add eax, 99 (only on the not-taken path)
    add eax, ecx
    add eax, edx
    ret
Shape_loopnz_R ENDP
Shape_jrcxz_P PROC
    mov edx, dword ptr [esp+4]
    mov ecx, edx
    and ecx, 1
    xor eax, eax
Shape_jrcxz_P_Insn::
    DB 0E3h, 05h                  ; jecxz: taken for even tags
    DB 05h, 63h, 0, 0, 0          ; add eax, 99 (only on the not-taken path)
    add eax, ecx
    add eax, edx
    ret
Shape_jrcxz_P ENDP
Shape_jrcxz_R PROC
    mov edx, dword ptr [esp+4]
    mov ecx, edx
    and ecx, 1
    xor eax, eax
Shape_jrcxz_R_Insn::
    DB 0E3h, 05h                  ; jecxz: taken for even tags
    DB 05h, 63h, 0, 0, 0          ; add eax, 99 (only on the not-taken path)
    add eax, ecx
    add eax, edx
    ret
Shape_jrcxz_R ENDP
Shape_loop_a32_P PROC
    mov edx, dword ptr [esp+4]
    mov ecx, edx
    and ecx, 1
    add ecx, 0FFFF0001h
    xor eax, eax
Shape_loop_a32_P_Insn::
    DB 67h, 0E2h, 05h             ; addr16 loop (cx 2 -> taken, 1 -> not; upper ecx kept)
    DB 05h, 63h, 0, 0, 0          ; add eax, 99 (only on the not-taken path)
    add eax, ecx
    add eax, edx
    ret
Shape_loop_a32_P ENDP
Shape_loop_a32_R PROC
    mov edx, dword ptr [esp+4]
    mov ecx, edx
    and ecx, 1
    add ecx, 0FFFF0001h
    xor eax, eax
Shape_loop_a32_R_Insn::
    DB 67h, 0E2h, 05h             ; addr16 loop (cx 2 -> taken, 1 -> not; upper ecx kept)
    DB 05h, 63h, 0, 0, 0          ; add eax, 99 (only on the not-taken path)
    add eax, ecx
    add eax, edx
    ret
Shape_loop_a32_R ENDP
Shape_jecxz_a32_P PROC
    mov edx, dword ptr [esp+4]
    mov ecx, edx
    and ecx, 1
    add ecx, 10000h
    xor eax, eax
Shape_jecxz_a32_P_Insn::
    DB 67h, 0E3h, 05h             ; jcxz: taken for even tags (ecx != 0)
    DB 05h, 63h, 0, 0, 0          ; add eax, 99 (only on the not-taken path)
    add eax, ecx
    add eax, edx
    ret
Shape_jecxz_a32_P ENDP
Shape_jecxz_a32_R PROC
    mov edx, dword ptr [esp+4]
    mov ecx, edx
    and ecx, 1
    add ecx, 10000h
    xor eax, eax
Shape_jecxz_a32_R_Insn::
    DB 67h, 0E3h, 05h             ; jcxz: taken for even tags (ecx != 0)
    DB 05h, 63h, 0, 0, 0          ; add eax, 99 (only on the not-taken path)
    add eax, ecx
    add eax, edx
    ret
Shape_jecxz_a32_R ENDP
Shape_pushf_P PROC
    mov edx, dword ptr [esp+4]
    xor eax, eax
Shape_pushf_P_Insn::
    pushfd
    pop eax
    ret
Shape_pushf_P ENDP
Shape_pushf_R PROC
    mov edx, dword ptr [esp+4]
    xor eax, eax
Shape_pushf_R_Insn::
    pushfd
    pop eax
    ret
Shape_pushf_R ENDP
Shape_pushf_guard_P PROC
    mov edx, dword ptr [esp+4]
    mov ecx, esp
    mov esp, dword ptr fs:[8]     ; NT_TIB.StackLimit: the push lands in the guard page
    xor eax, eax
Shape_pushf_guard_P_Insn::
    pushfd
    pop eax
    mov esp, ecx
    ret
Shape_pushf_guard_P ENDP
Shape_pushf_guard_R PROC
    mov edx, dword ptr [esp+4]
    mov ecx, esp
    mov esp, dword ptr fs:[8]     ; NT_TIB.StackLimit: the push lands in the guard page
    xor eax, eax
Shape_pushf_guard_R_Insn::
    pushfd
    pop eax
    mov esp, ecx
    ret
Shape_pushf_guard_R ENDP
Shape_segjmp_P PROC
    mov edx, dword ptr [esp+4]
    mov ecx, dword ptr [g_tls_off]
    mov eax, OFFSET Shape_segjmp_P_Cont
    mov dword ptr fs:[ecx], eax
    xor eax, eax
Shape_segjmp_P_Insn::
    jmp dword ptr fs:[ecx]        ; segment-relative indirect jump (not emulated)
    DB 05h, 63h, 0, 0, 0          ; add eax, 99 (only on the not-taken path)
Shape_segjmp_P_Cont::
    add eax, edx
    ret
Shape_segjmp_P ENDP
Shape_segjmp_R PROC
    mov edx, dword ptr [esp+4]
    mov ecx, dword ptr [g_tls_off]
    mov eax, OFFSET Shape_segjmp_R_Cont
    mov dword ptr fs:[ecx], eax
    xor eax, eax
Shape_segjmp_R_Insn::
    jmp dword ptr fs:[ecx]        ; segment-relative indirect jump (not emulated)
    DB 05h, 63h, 0, 0, 0          ; add eax, 99 (only on the not-taken path)
Shape_segjmp_R_Cont::
    add eax, edx
    ret
Shape_segjmp_R ENDP
END
