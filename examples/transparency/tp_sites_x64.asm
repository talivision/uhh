; Transparency fixture (x64): the call harness and the mid-function site. See tp_target.cpp.
; Single-threaded use only (state in globals, so a broken SP after the call is measured, not
; crashed on).
;
; TpHarness(fn, const TpIn *in, TpOut *out)
;   TpIn:  a[8] +0, x0 +40h, x1 +48h            TpOut: rax +0, rdx +8, xmm0 +10h, nv[8] +20h
;          (rbx rbp rsi rdi r12-r15), xmm6-15 +60h, sp_delta +100h, flags +108h
; TpMid(TpMidOut *out) / TpMidRef: identical bodies; only TpMid has the probe site TpMidHit.
;   TpMidOut: gpr[15] +0 (rax rbx rcx rdx rsi rdi rbp r8-r15), flags +78h, xmm[16] +80h,
;             FNSAVE image +180h, YMM0-15 upper halves +1F0h
PUBLIC TpHarness, TpMid, TpMidRef, TpMidHit

.data
ALIGN 16
SentX   dq 1111111111111111h, 0A1A1A1A1A1A1A1A1h, 2222222222222222h, 0A2A2A2A2A2A2A2A2h
        dq 3333333333333333h, 0A3A3A3A3A3A3A3A3h, 4444444444444444h, 0A4A4A4A4A4A4A4A4h
        dq 5555555555555555h, 0A5A5A5A5A5A5A5A5h, 6666666666666666h, 0A6A6A6A6A6A6A6A6h
        dq 7777777777777777h, 0A7A7A7A7A7A7A7A7h, 8888888888888888h, 0A8A8A8A8A8A8A8A8h
        dq 9999999999999999h, 0A9A9A9A9A9A9A9A9h, 0AAAAAAAAAAAAAAAAh, 0BABABABABABABABAh
        dq 0BBBBBBBBBBBBBBBBh, 0CBCBCBCBCBCBCBCBh, 0CCCCCCCCCCCCCCCCh, 0DCDCDCDCDCDCDCDCh
        dq 0DDDDDDDDDDDDDDDDh, 0EDEDEDEDEDEDEDEDh, 0EEEEEEEEEEEEEEEEh, 0FEFEFEFEFEFEFEFEh
        dq 0F0F0F0F0F0F0F0Fh, 1F1F1F1F1F1F1F1Fh, 0E1E1E1E1E1E1E1E1h, 2E2E2E2E2E2E2E2Eh
SentY   dq 0D0D0D0D0D0D0D001h, 0D1D1D1D1D1D1D101h, 0D0D0D0D0D0D0D002h, 0D1D1D1D1D1D1D102h
        dq 0D0D0D0D0D0D0D003h, 0D1D1D1D1D1D1D103h, 0D0D0D0D0D0D0D004h, 0D1D1D1D1D1D1D104h
        dq 0D0D0D0D0D0D0D005h, 0D1D1D1D1D1D1D105h, 0D0D0D0D0D0D0D006h, 0D1D1D1D1D1D1D106h
        dq 0D0D0D0D0D0D0D007h, 0D1D1D1D1D1D1D107h, 0D0D0D0D0D0D0D008h, 0D1D1D1D1D1D1D108h
        dq 0D0D0D0D0D0D0D009h, 0D1D1D1D1D1D1D109h, 0D0D0D0D0D0D0D00Ah, 0D1D1D1D1D1D1D10Ah
        dq 0D0D0D0D0D0D0D00Bh, 0D1D1D1D1D1D1D10Bh, 0D0D0D0D0D0D0D00Ch, 0D1D1D1D1D1D1D10Ch
        dq 0D0D0D0D0D0D0D00Dh, 0D1D1D1D1D1D1D10Dh, 0D0D0D0D0D0D0D00Eh, 0D1D1D1D1D1D1D10Eh
        dq 0D0D0D0D0D0D0D00Fh, 0D1D1D1D1D1D1D10Fh, 0D0D0D0D0D0D0D010h, 0D1D1D1D1D1D1D110h
FpVals  dq 3FF0000000000000h, 4000000000000000h, 4008000000000000h, 4010000000000000h
        dq 4014000000000000h, 4018000000000000h, 401C000000000000h, 4020000000000000h
FpCw    dw 027Fh
FpCwMid dw 0E7Fh
ALIGN 8
g_fn    dq 0
g_in    dq 0
g_out   dq 0
g_rsp   dq 0
g_after dq 0
g_rax   dq 0
g_mout  dq 0

.code
LOADX MACRO base
    movdqu xmm0,  xmmword ptr [base+000h]
    movdqu xmm1,  xmmword ptr [base+010h]
    movdqu xmm2,  xmmword ptr [base+020h]
    movdqu xmm3,  xmmword ptr [base+030h]
    movdqu xmm4,  xmmword ptr [base+040h]
    movdqu xmm5,  xmmword ptr [base+050h]
    movdqu xmm6,  xmmword ptr [base+060h]
    movdqu xmm7,  xmmword ptr [base+070h]
    movdqu xmm8,  xmmword ptr [base+080h]
    movdqu xmm9,  xmmword ptr [base+090h]
    movdqu xmm10, xmmword ptr [base+0A0h]
    movdqu xmm11, xmmword ptr [base+0B0h]
    movdqu xmm12, xmmword ptr [base+0C0h]
    movdqu xmm13, xmmword ptr [base+0D0h]
    movdqu xmm14, xmmword ptr [base+0E0h]
    movdqu xmm15, xmmword ptr [base+0F0h]
ENDM
SAVENV MACRO
    push rbx
    push rbp
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 0A8h
    movdqu [rsp+00h], xmm6
    movdqu [rsp+10h], xmm7
    movdqu [rsp+20h], xmm8
    movdqu [rsp+30h], xmm9
    movdqu [rsp+40h], xmm10
    movdqu [rsp+50h], xmm11
    movdqu [rsp+60h], xmm12
    movdqu [rsp+70h], xmm13
    movdqu [rsp+80h], xmm14
    movdqu [rsp+90h], xmm15
ENDM
RESTNV MACRO
    movdqu xmm6,  [rsp+00h]
    movdqu xmm7,  [rsp+10h]
    movdqu xmm8,  [rsp+20h]
    movdqu xmm9,  [rsp+30h]
    movdqu xmm10, [rsp+40h]
    movdqu xmm11, [rsp+50h]
    movdqu xmm12, [rsp+60h]
    movdqu xmm13, [rsp+70h]
    movdqu xmm14, [rsp+80h]
    movdqu xmm15, [rsp+90h]
    add rsp, 0A8h
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbp
    pop rbx
ENDM

TpHarness PROC
    SAVENV
    mov [g_fn], rcx
    mov [g_in], rdx
    mov [g_out], r8
    sub rsp, 40h                        ; home space + stack args 5, 6 (rsp stays 16-aligned)
    mov rax, [rdx+20h]
    mov [rsp+20h], rax
    mov rax, [rdx+28h]
    mov [rsp+28h], rax
    mov [g_rsp], rsp
    lea rax, SentX
    LOADX rax
    movq xmm0, qword ptr [rdx+40h]
    movq xmm1, qword ptr [rdx+48h]
    mov rcx, [rdx]
    mov r8, [rdx+10h]
    mov r9, [rdx+18h]
    mov rdx, [rdx+8]
    mov rbx, 0B1B1B1B1B1B1B1B1h
    mov rbp, 0B2B2B2B2B2B2B2B2h
    mov rsi, 0B3B3B3B3B3B3B3B3h
    mov rdi, 0B4B4B4B4B4B4B4B4h
    mov r12, 0B5B5B5B5B5B5B5B5h
    mov r13, 0B6B6B6B6B6B6B6B6h
    mov r14, 0B7B7B7B7B7B7B7B7h
    mov r15, 0B8B8B8B8B8B8B8B8h
    cld
    call qword ptr [g_fn]
    mov [g_after], rsp
    mov rsp, [g_rsp]
    mov [g_rax], rax
    pushfq
    mov rax, [g_out]
    pop qword ptr [rax+108h]
    mov rcx, [g_rax]
    mov [rax], rcx
    mov [rax+8], rdx
    movdqu [rax+10h], xmm0
    mov [rax+20h], rbx
    mov [rax+28h], rbp
    mov [rax+30h], rsi
    mov [rax+38h], rdi
    mov [rax+40h], r12
    mov [rax+48h], r13
    mov [rax+50h], r14
    mov [rax+58h], r15
    movdqu [rax+60h], xmm6
    movdqu [rax+70h], xmm7
    movdqu [rax+80h], xmm8
    movdqu [rax+90h], xmm9
    movdqu [rax+0A0h], xmm10
    movdqu [rax+0B0h], xmm11
    movdqu [rax+0C0h], xmm12
    movdqu [rax+0D0h], xmm13
    movdqu [rax+0E0h], xmm14
    movdqu [rax+0F0h], xmm15
    mov rcx, [g_after]
    sub rcx, [g_rsp]
    mov [rax+100h], rcx
    fnstsw word ptr [rax+118h]
    mov dword ptr [rax+11Ch], 0
    add rsp, 40h
    RESTNV
    ret
TpHarness ENDP

; Live state at the site: every GPR but RSP, XMM0-15, a FULL x87 stack (8 values) with an
; FCOM result pending in C0/C2/C3 and a non-default control word, DF=1, and the arithmetic
; flags of a `cmp` that the snapshot consumes.
MIDBODY MACRO hit
    SAVENV
    mov [g_mout], rcx
    fninit
    fldcw word ptr [FpCwMid]
    lea rax, FpVals
    fld qword ptr [rax+00h]
    fld qword ptr [rax+08h]
    fld qword ptr [rax+10h]
    fld qword ptr [rax+18h]
    fld qword ptr [rax+20h]
    fld qword ptr [rax+28h]
    fld qword ptr [rax+30h]
    fld qword ptr [rax+38h]
    fcom st(3)
    lea rax, SentY                      ; YMM upper halves first (VEX zeroes nothing below)
    vinsertf128 ymm0,  ymm0,  xmmword ptr [rax+000h], 1
    vinsertf128 ymm1,  ymm1,  xmmword ptr [rax+010h], 1
    vinsertf128 ymm2,  ymm2,  xmmword ptr [rax+020h], 1
    vinsertf128 ymm3,  ymm3,  xmmword ptr [rax+030h], 1
    vinsertf128 ymm4,  ymm4,  xmmword ptr [rax+040h], 1
    vinsertf128 ymm5,  ymm5,  xmmword ptr [rax+050h], 1
    vinsertf128 ymm6,  ymm6,  xmmword ptr [rax+060h], 1
    vinsertf128 ymm7,  ymm7,  xmmword ptr [rax+070h], 1
    vinsertf128 ymm8,  ymm8,  xmmword ptr [rax+080h], 1
    vinsertf128 ymm9,  ymm9,  xmmword ptr [rax+090h], 1
    vinsertf128 ymm10, ymm10, xmmword ptr [rax+0A0h], 1
    vinsertf128 ymm11, ymm11, xmmword ptr [rax+0B0h], 1
    vinsertf128 ymm12, ymm12, xmmword ptr [rax+0C0h], 1
    vinsertf128 ymm13, ymm13, xmmword ptr [rax+0D0h], 1
    vinsertf128 ymm14, ymm14, xmmword ptr [rax+0E0h], 1
    vinsertf128 ymm15, ymm15, xmmword ptr [rax+0F0h], 1
    lea rax, SentX
    LOADX rax                           ; legacy-SSE loads keep the upper halves
    mov rax, 0C0C0C0C0C0C0C0C1h
    mov rbx, 0C0C0C0C0C0C0C0C2h
    mov rcx, 0C0C0C0C0C0C0C0C3h
    mov rdx, 0C0C0C0C0C0C0C0C4h
    mov rsi, 0C0C0C0C0C0C0C0C5h
    mov rdi, 0C0C0C0C0C0C0C0C6h
    mov rbp, 0C0C0C0C0C0C0C0C7h
    mov r8,  0C0C0C0C0C0C0C0C8h
    mov r9,  0C0C0C0C0C0C0C0C9h
    mov r10, 0C0C0C0C0C0C0C0CAh
    mov r11, 0C0C0C0C0C0C0C0CBh
    mov r12, 0C0C0C0C0C0C0C0CCh
    mov r13, 0C0C0C0C0C0C0C0CDh
    mov r14, 0C0C0C0C0C0C0C0CEh
    mov r15, 0C0C0C0C0C0C0C0CFh
    std
    cmp rax, rbx                        ; CF=1 SF=1 ... consumed by the snapshot below
IFNB <hit>
hit::
ENDIF
    db 0Fh, 1Fh, 84h, 00h, 00h, 00h, 00h, 00h   ; 8-byte nop: the probed instruction
    pushfq
    mov [g_rax], rax
    mov rax, [g_mout]
    pop qword ptr [rax+78h]
    cld
    mov [rax+08h], rbx
    mov [rax+10h], rcx
    mov [rax+18h], rdx
    mov [rax+20h], rsi
    mov [rax+28h], rdi
    mov [rax+30h], rbp
    mov [rax+38h], r8
    mov [rax+40h], r9
    mov [rax+48h], r10
    mov [rax+50h], r11
    mov [rax+58h], r12
    mov [rax+60h], r13
    mov [rax+68h], r14
    mov [rax+70h], r15
    mov rcx, [g_rax]
    mov [rax], rcx
    movdqu [rax+080h], xmm0
    movdqu [rax+090h], xmm1
    movdqu [rax+0A0h], xmm2
    movdqu [rax+0B0h], xmm3
    movdqu [rax+0C0h], xmm4
    movdqu [rax+0D0h], xmm5
    movdqu [rax+0E0h], xmm6
    movdqu [rax+0F0h], xmm7
    movdqu [rax+100h], xmm8
    movdqu [rax+110h], xmm9
    movdqu [rax+120h], xmm10
    movdqu [rax+130h], xmm11
    movdqu [rax+140h], xmm12
    movdqu [rax+150h], xmm13
    movdqu [rax+160h], xmm14
    movdqu [rax+170h], xmm15
    vextractf128 xmmword ptr [rax+1F0h], ymm0, 1
    vextractf128 xmmword ptr [rax+200h], ymm1, 1
    vextractf128 xmmword ptr [rax+210h], ymm2, 1
    vextractf128 xmmword ptr [rax+220h], ymm3, 1
    vextractf128 xmmword ptr [rax+230h], ymm4, 1
    vextractf128 xmmword ptr [rax+240h], ymm5, 1
    vextractf128 xmmword ptr [rax+250h], ymm6, 1
    vextractf128 xmmword ptr [rax+260h], ymm7, 1
    vextractf128 xmmword ptr [rax+270h], ymm8, 1
    vextractf128 xmmword ptr [rax+280h], ymm9, 1
    vextractf128 xmmword ptr [rax+290h], ymm10, 1
    vextractf128 xmmword ptr [rax+2A0h], ymm11, 1
    vextractf128 xmmword ptr [rax+2B0h], ymm12, 1
    vextractf128 xmmword ptr [rax+2C0h], ymm13, 1
    vextractf128 xmmword ptr [rax+2D0h], ymm14, 1
    vextractf128 xmmword ptr [rax+2E0h], ymm15, 1
    vzeroupper
    fnsave [rax+180h]                   ; also re-initialises the FPU
    fldcw word ptr [FpCw]
    RESTNV
    ret
ENDM

TpMid PROC
    MIDBODY TpMidHit
TpMid ENDP

TpMidRef PROC
    MIDBODY
TpMidRef ENDP
END
