; x64 state fixture. SideFxSite is a mid-function 16-byte NOP sled: every tested
; register/control value is live on entry and captured immediately after it.
OPTION CASEMAP:NONE
PUBLIC sidefx_probe_point, SideFxSite

SIDEFX_XMM       EQU 112
SIDEFX_YMM       EQU 368
SIDEFX_MXCSR_OUT EQU 624
SIDEFX_FLAGS     EQU 628
SIDEFX_X87_OUT   EQU 632
SIDEFX_BELOW_OUT EQU 636

.const
ALIGN 4
SideFxMxcsr       DWORD 07F80h
SideFxX87cw       WORD  0E7Fh
ALIGN 4
SideFxBelowDword DWORD 0D3D3D3D3h
SideFxVector0    DWORD 0A5A50000h
SideFxVector1    DWORD 0A5A50001h
SideFxVector2    DWORD 0A5A50002h
SideFxVector3    DWORD 0A5A50003h
SideFxVector4    DWORD 0A5A50004h
SideFxVector5    DWORD 0A5A50005h
SideFxVector6    DWORD 0A5A50006h
SideFxVector7    DWORD 0A5A50007h
SideFxVector8    DWORD 0A5A50008h
SideFxVector9    DWORD 0A5A50009h
SideFxVector10   DWORD 0A5A5000Ah
SideFxVector11   DWORD 0A5A5000Bh
SideFxVector12   DWORD 0A5A5000Ch
SideFxVector13   DWORD 0A5A5000Dh
SideFxVector14   DWORD 0A5A5000Eh
SideFxVector15   DWORD 0A5A5000Fh

.code
sidefx_probe_point PROC FRAME
    push rbp
    .pushreg rbp
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push r12
    .pushreg r12
    push r13
    .pushreg r13
    push r14
    .pushreg r14
    push r15
    .pushreg r15
    sub  rsp, 0A8h                 ; XMM6-15 + original MXCSR/CW + alignment
    .allocstack 0A8h
    vmovdqu XMMWORD PTR [rsp+000h], xmm6
    .savexmm128 xmm6, 000h
    vmovdqu XMMWORD PTR [rsp+010h], xmm7
    .savexmm128 xmm7, 010h
    vmovdqu XMMWORD PTR [rsp+020h], xmm8
    .savexmm128 xmm8, 020h
    vmovdqu XMMWORD PTR [rsp+030h], xmm9
    .savexmm128 xmm9, 030h
    vmovdqu XMMWORD PTR [rsp+040h], xmm10
    .savexmm128 xmm10, 040h
    vmovdqu XMMWORD PTR [rsp+050h], xmm11
    .savexmm128 xmm11, 050h
    vmovdqu XMMWORD PTR [rsp+060h], xmm12
    .savexmm128 xmm12, 060h
    vmovdqu XMMWORD PTR [rsp+070h], xmm13
    .savexmm128 xmm13, 070h
    vmovdqu XMMWORD PTR [rsp+080h], xmm14
    .savexmm128 xmm14, 080h
    vmovdqu XMMWORD PTR [rsp+090h], xmm15
    .savexmm128 xmm15, 090h
    .endprolog

    mov  rbp, rcx                  ; capture destination (BP/SP are exempt)
    stmxcsr DWORD PTR [rsp+0A0h]
    fnstcw  WORD PTR [rsp+0A4h]

    ; Seed 512 live bytes below the site SP without changing SP.
    vpbroadcastd ymm0, DWORD PTR [SideFxBelowDword]
    lea  rax, [rsp-512]
    mov  ecx, 16
sidefx_fill_below:
    vmovdqu YMMWORD PTR [rax], ymm0
    add  rax, 32
    dec  ecx
    jne  sidefx_fill_below

    vpbroadcastd ymm0,  DWORD PTR [SideFxVector0]
    vpbroadcastd ymm1,  DWORD PTR [SideFxVector1]
    vpbroadcastd ymm2,  DWORD PTR [SideFxVector2]
    vpbroadcastd ymm3,  DWORD PTR [SideFxVector3]
    vpbroadcastd ymm4,  DWORD PTR [SideFxVector4]
    vpbroadcastd ymm5,  DWORD PTR [SideFxVector5]
    vpbroadcastd ymm6,  DWORD PTR [SideFxVector6]
    vpbroadcastd ymm7,  DWORD PTR [SideFxVector7]
    vpbroadcastd ymm8,  DWORD PTR [SideFxVector8]
    vpbroadcastd ymm9,  DWORD PTR [SideFxVector9]
    vpbroadcastd ymm10, DWORD PTR [SideFxVector10]
    vpbroadcastd ymm11, DWORD PTR [SideFxVector11]
    vpbroadcastd ymm12, DWORD PTR [SideFxVector12]
    vpbroadcastd ymm13, DWORD PTR [SideFxVector13]
    vpbroadcastd ymm14, DWORD PTR [SideFxVector14]
    vpbroadcastd ymm15, DWORD PTR [SideFxVector15]
    ldmxcsr DWORD PTR [SideFxMxcsr]
    fldcw   WORD PTR [SideFxX87cw]

    mov rax, 1111111111111111h
    mov rbx, 2222222222222222h
    mov rcx, 3333333333333333h
    mov rdx, 4444444444444444h
    mov rsi, 5555555555555555h
    mov rdi, 6666666666666666h
    mov r8,  8888888888888888h
    mov r9,  9999999999999999h
    mov r10, 0AAAAAAAAAAAAAAAAh
    mov r11, 0BBBBBBBBBBBBBBBBh
    mov r12, 0CCCCCCCCCCCCCCCCh
    mov r13, 0DDDDDDDDDDDDDDDDh
    mov r14, 0EEEEEEEEEEEEEEEEh
    mov r15, 0FFFFFFFFFFFFFFFFh
    std                             ; deliberately legal only inside this function

SideFxSite LABEL BYTE
    REPT 16
        nop
    ENDM

    ; Save GPRs before borrowing any of them for capture work.
    mov QWORD PTR [rbp+000h], rax
    mov QWORD PTR [rbp+008h], rbx
    mov QWORD PTR [rbp+010h], rcx
    mov QWORD PTR [rbp+018h], rdx
    mov QWORD PTR [rbp+020h], rsi
    mov QWORD PTR [rbp+028h], rdi
    mov QWORD PTR [rbp+030h], r8
    mov QWORD PTR [rbp+038h], r9
    mov QWORD PTR [rbp+040h], r10
    mov QWORD PTR [rbp+048h], r11
    mov QWORD PTR [rbp+050h], r12
    mov QWORD PTR [rbp+058h], r13
    mov QWORD PTR [rbp+060h], r14
    mov QWORD PTR [rbp+068h], r15

    vmovdqu XMMWORD PTR [rbp+SIDEFX_XMM+000h], xmm0
    vmovdqu XMMWORD PTR [rbp+SIDEFX_XMM+010h], xmm1
    vmovdqu XMMWORD PTR [rbp+SIDEFX_XMM+020h], xmm2
    vmovdqu XMMWORD PTR [rbp+SIDEFX_XMM+030h], xmm3
    vmovdqu XMMWORD PTR [rbp+SIDEFX_XMM+040h], xmm4
    vmovdqu XMMWORD PTR [rbp+SIDEFX_XMM+050h], xmm5
    vmovdqu XMMWORD PTR [rbp+SIDEFX_XMM+060h], xmm6
    vmovdqu XMMWORD PTR [rbp+SIDEFX_XMM+070h], xmm7
    vmovdqu XMMWORD PTR [rbp+SIDEFX_XMM+080h], xmm8
    vmovdqu XMMWORD PTR [rbp+SIDEFX_XMM+090h], xmm9
    vmovdqu XMMWORD PTR [rbp+SIDEFX_XMM+0A0h], xmm10
    vmovdqu XMMWORD PTR [rbp+SIDEFX_XMM+0B0h], xmm11
    vmovdqu XMMWORD PTR [rbp+SIDEFX_XMM+0C0h], xmm12
    vmovdqu XMMWORD PTR [rbp+SIDEFX_XMM+0D0h], xmm13
    vmovdqu XMMWORD PTR [rbp+SIDEFX_XMM+0E0h], xmm14
    vmovdqu XMMWORD PTR [rbp+SIDEFX_XMM+0F0h], xmm15
    vextracti128 XMMWORD PTR [rbp+SIDEFX_YMM+000h], ymm0, 1
    vextracti128 XMMWORD PTR [rbp+SIDEFX_YMM+010h], ymm1, 1
    vextracti128 XMMWORD PTR [rbp+SIDEFX_YMM+020h], ymm2, 1
    vextracti128 XMMWORD PTR [rbp+SIDEFX_YMM+030h], ymm3, 1
    vextracti128 XMMWORD PTR [rbp+SIDEFX_YMM+040h], ymm4, 1
    vextracti128 XMMWORD PTR [rbp+SIDEFX_YMM+050h], ymm5, 1
    vextracti128 XMMWORD PTR [rbp+SIDEFX_YMM+060h], ymm6, 1
    vextracti128 XMMWORD PTR [rbp+SIDEFX_YMM+070h], ymm7, 1
    vextracti128 XMMWORD PTR [rbp+SIDEFX_YMM+080h], ymm8, 1
    vextracti128 XMMWORD PTR [rbp+SIDEFX_YMM+090h], ymm9, 1
    vextracti128 XMMWORD PTR [rbp+SIDEFX_YMM+0A0h], ymm10, 1
    vextracti128 XMMWORD PTR [rbp+SIDEFX_YMM+0B0h], ymm11, 1
    vextracti128 XMMWORD PTR [rbp+SIDEFX_YMM+0C0h], ymm12, 1
    vextracti128 XMMWORD PTR [rbp+SIDEFX_YMM+0D0h], ymm13, 1
    vextracti128 XMMWORD PTR [rbp+SIDEFX_YMM+0E0h], ymm14, 1
    vextracti128 XMMWORD PTR [rbp+SIDEFX_YMM+0F0h], ymm15, 1
    stmxcsr DWORD PTR [rbp+SIDEFX_MXCSR_OUT]
    fnstcw  WORD PTR [rbp+SIDEFX_X87_OUT]

    ; Snapshot below-SP before PUSHFQ itself writes at [rsp-8].
    lea  rax, [rsp-512]
    lea  rdx, [rbp+SIDEFX_BELOW_OUT]
    mov  ecx, 16
sidefx_copy_below:
    vmovdqu ymm0, YMMWORD PTR [rax]
    vmovdqu YMMWORD PTR [rdx], ymm0
    add  rax, 32
    add  rdx, 32
    dec  ecx
    jne  sidefx_copy_below
    pushfq
    pop  rax
    mov  DWORD PTR [rbp+SIDEFX_FLAGS], eax
    cld

    ldmxcsr DWORD PTR [rsp+0A0h]
    fldcw   WORD PTR [rsp+0A4h]
    vmovdqu xmm6,  XMMWORD PTR [rsp+000h]
    vmovdqu xmm7,  XMMWORD PTR [rsp+010h]
    vmovdqu xmm8,  XMMWORD PTR [rsp+020h]
    vmovdqu xmm9,  XMMWORD PTR [rsp+030h]
    vmovdqu xmm10, XMMWORD PTR [rsp+040h]
    vmovdqu xmm11, XMMWORD PTR [rsp+050h]
    vmovdqu xmm12, XMMWORD PTR [rsp+060h]
    vmovdqu xmm13, XMMWORD PTR [rsp+070h]
    vmovdqu xmm14, XMMWORD PTR [rsp+080h]
    vmovdqu xmm15, XMMWORD PTR [rsp+090h]
    vzeroupper
    add rsp, 0A8h
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
sidefx_probe_point ENDP
END
