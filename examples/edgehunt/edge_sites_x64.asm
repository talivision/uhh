; Edge-case code shapes for the edgehunt test (x64). Every *Site label is exported and
; probed by the same callback under breakpoint, hw and inline; the C target compares each
; function's result with an uninstrumented run. Each site is followed by >= 5 bytes of
; straight-line code so an inline hook has room where the shape allows it at all.
; (Test fixture; callbacks themselves are plain C.)
OPTION CASEMAP:NONE

PUBLIC EdgeRep, EdgeRepSite, EdgeStos, EdgeStosSite
PUBLIC EdgeRipLoad, EdgeRipLoadSite, EdgeRipCmp, EdgeRipCmpSite, EdgeRipVec, EdgeRipVecSite
PUBLIC EdgeRipStore, EdgeRipStoreSite
PUBLIC EdgeCpuid, EdgeCpuidSite, EdgeRdtsc, EdgeRdtscSite
PUBLIC EdgeSyscall, EdgeSyscallSite, EdgeInt2e, EdgeInt2eSite
PUBLIC EdgePushf, EdgePushfSite, EdgePopf, EdgePopfSite
PUBLIC EdgeRetOnly, EdgeRetOnlySite, EdgeThunk, EdgeThunkSite, EdgeJump, EdgeJumpSite
PUBLIC EdgeFaultMid, EdgeFaultMidSite, EdgeX87, EdgeX87Site, EdgeLock, EdgeLockSite
PUBLIC EdgeDual, EdgeDualSite, EdgeReaddA, EdgeReaddB, EdgeCodePad, EdgeRipStoreRead

.data
ALIGN 16
EdgeQ        DQ 1122334455667788h
EdgeD        DD 12345678h
EdgeD2       DD 0
EdgeLockVal  DQ 5
ALIGN 16
EdgeVec      DD 0A5A5A5A0h, 0A5A5A5A1h, 0A5A5A5A2h, 0A5A5A5A3h, 0A5A5A5A4h, 0A5A5A5A5h, 0A5A5A5A6h, 0A5A5A5A7h
EdgeThunkPtr DQ EdgeCallee
EdgeTable    DQ EdgeCase0, EdgeCase1, EdgeCase2
EdgeOneHalf      DT 3FFFC000000000000000r       ; 1.5 as an x87 80-bit value

.code
; uint64 EdgeRep(void *dst, const void *src): rep movsb of 100 bytes; returns rcx after (0).
EdgeRep PROC
    push rsi
    push rdi
    mov rdi, rcx
    mov rsi, rdx
    mov ecx, 100
EdgeRepSite::
    rep movsb
    mov rax, rcx
    pop rdi
    pop rsi
    ret
EdgeRep ENDP

; uint64 EdgeStos(void *dst): rep stosb of 64 x 3Ch; returns rcx after (0).
EdgeStos PROC
    push rdi
    mov rdi, rcx
    mov eax, 3Ch
    mov ecx, 64
EdgeStosSite::
    rep stosb
    mov rax, rcx
    pop rdi
    ret
EdgeStos ENDP

EdgeRipLoad PROC
EdgeRipLoadSite::
    mov rax, qword ptr [EdgeQ]
    nop
    ret
EdgeRipLoad ENDP

; returns 1 when [EdgeD] == 12345678h (disp32 followed by imm32)
EdgeRipCmp PROC
    xor eax, eax
EdgeRipCmpSite::
    cmp dword ptr [EdgeD], 12345678h
    sete al
    ret
EdgeRipCmp ENDP

; returns dword 5 of EdgeVec via a RIP-relative 256-bit load
EdgeRipVec PROC
EdgeRipVecSite::
    vmovdqu ymm0, ymmword ptr [EdgeVec]
    vextracti128 xmm0, ymm0, 1
    vpextrd eax, xmm0, 1
    vzeroupper
    ret
EdgeRipVec ENDP

; stores ecx to EdgeD2 RIP-relatively
EdgeRipStore PROC
EdgeRipStoreSite::
    mov dword ptr [EdgeD2], ecx
    nop
    ret
EdgeRipStore ENDP
EdgeRipStoreRead PROC
    mov eax, dword ptr [EdgeD2]
    ret
EdgeRipStoreRead ENDP

; returns ebx of cpuid leaf 0 (vendor bytes 0-3)
EdgeCpuid PROC
    push rbx
    xor eax, eax
    xor ecx, ecx
EdgeCpuidSite::
    cpuid
    mov eax, ebx
    pop rbx
    ret
EdgeCpuid ENDP

EdgeRdtsc PROC
EdgeRdtscSite::
    rdtsc
    shl rdx, 32
    or rax, rdx
    ret
EdgeRdtsc ENDP

; uint64 EdgeSyscall(service): raw syscall (no args; NtYieldExecution). Returns
; status | (r11 & (TF|RF)) << 32: r11 is the flags image the CPU saved.
EdgeSyscall PROC
    mov eax, ecx
    mov r10, rcx
EdgeSyscallSite::
    syscall
    mov edx, r11d
    and edx, 10100h
    shl rdx, 32
    mov eax, eax
    or rax, rdx
    ret
EdgeSyscall ENDP

EdgeInt2e PROC
    mov eax, ecx
    mov r10, rcx
EdgeInt2eSite::
    int 2Eh
    nop
    nop
    nop
    nop
    mov eax, eax
    ret
EdgeInt2e ENDP

; returns the flags image pushfq stored (TF/RF must read 0)
EdgePushf PROC
EdgePushfSite::
    pushfq
    pop rax
    nop
    nop
    nop
    ret
EdgePushf ENDP

; uint64 EdgePopf(flags): popfq of rcx, then returns the live flags
EdgePopf PROC
    push rcx
EdgePopfSite::
    popfq
    pushfq
    pop rax
    nop
    nop
    push 202h
    popfq
    ret
EdgePopf ENDP

EdgeRetOnly PROC
EdgeRetOnlySite::
    ret
EdgeRetOnly ENDP

EdgeCallee PROC
    mov eax, 42
    ret
EdgeCallee ENDP

; calls EdgeCallee through a pointer (an import-thunk shape)
EdgeThunk PROC
    sub rsp, 28h
EdgeThunkSite::
    call qword ptr [EdgeThunkPtr]
    add rsp, 28h
    ret
EdgeThunk ENDP

; jump table on ecx (0..2) -> 100..102
EdgeJump PROC
    mov eax, ecx
    lea rdx, EdgeTable
EdgeJumpSite::
    jmp qword ptr [rdx+rax*8]
EdgeCase0::
    mov eax, 100
    ret
EdgeCase1::
    mov eax, 101
    ret
EdgeCase2::
    mov eax, 102
    ret
EdgeJump ENDP

; int EdgeFaultMid(int *p): a framed function (unwind data) that loads [p] mid-function.
; With p == NULL it faults; the C caller's __except must catch it.
EdgeFaultMid PROC FRAME
    push rbx
    .pushreg rbx
    sub rsp, 20h
    .allocstack 20h
    .endprolog
    mov qword ptr [rsp], 0     ; no stale return address below: a leaf-style unwind from here goes nowhere
    xor eax, eax
EdgeFaultMidSite::
    mov eax, dword ptr [rcx]
    nop
    nop
    nop
    nop
    add rsp, 20h
    pop rbx
    ret
EdgeFaultMid ENDP

; x87: loads 1.5 (80-bit), multiplies by ecx, returns the integer result
EdgeX87 PROC
    sub rsp, 18h
    mov dword ptr [rsp], ecx
EdgeX87Site::
    fld tbyte ptr [EdgeOneHalf]
    fimul dword ptr [rsp]
    fistp dword ptr [rsp+8]
    mov eax, dword ptr [rsp+8]
    add rsp, 18h
    ret
EdgeX87 ENDP

; lock cmpxchg on EdgeLockVal: 5 -> ecx; returns the old value
EdgeLock PROC
    mov eax, 5
EdgeLockSite::
    lock cmpxchg qword ptr [EdgeLockVal], rcx
    nop
    mov qword ptr [EdgeLockVal], 5
    ret
EdgeLock ENDP

; probed by two backends at once
EdgeDual PROC
    xor eax, eax
EdgeDualSite::
    inc eax
    inc eax
    inc eax
    inc eax
    inc eax
    inc eax
    ret
EdgeDual ENDP

EdgeReaddA PROC
    mov eax, 1
    nop
    nop
    nop
    nop
    nop
    ret
EdgeReaddA ENDP

EdgeReaddB PROC
    mov eax, 2
    nop
    nop
    nop
    nop
    nop
    ret
EdgeReaddB ENDP

; never executed: a code byte a callback tries (and must fail) to write
EdgeCodePad PROC
    int 3
    int 3
    int 3
    int 3
    int 3
    int 3
    int 3
    int 3
EdgeCodePad ENDP
END
