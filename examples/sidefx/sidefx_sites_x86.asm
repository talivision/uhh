; x86 (ml.exe) twin of sidefx_sites_x64.asm. C uses __cdecl decoration; the
; linker option in README exports SideFxSite (the x86 linker decorates it to _SideFxSite).
.686
.xmm
.model flat
OPTION CASEMAP:NONE
PUBLIC _sidefx_probe_point, _SideFxSite

SIDEFX_XMM       EQU 24
SIDEFX_YMM       EQU 152
SIDEFX_MXCSR_OUT EQU 280
SIDEFX_FLAGS     EQU 284
SIDEFX_X87_OUT   EQU 288
SIDEFX_BELOW_OUT EQU 292

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

.code
_sidefx_probe_point:               ; plain labels, no PROC: 32-bit MASM scopes labels inside a PROC
    push ebp
    mov  ebp, DWORD PTR [esp+8]    ; capture destination
    push ebx
    push esi
    push edi
    sub  esp, 8                    ; original MXCSR and x87 control word
    stmxcsr DWORD PTR [esp]
    fnstcw  WORD PTR [esp+4]

    vpbroadcastd ymm0, DWORD PTR [SideFxBelowDword]
    lea  eax, [esp-512]
    mov  ecx, 16
sidefx_fill_below:
    vmovdqu YMMWORD PTR [eax], ymm0
    add  eax, 32
    dec  ecx
    jne  sidefx_fill_below

    vpbroadcastd ymm0, DWORD PTR [SideFxVector0]
    vpbroadcastd ymm1, DWORD PTR [SideFxVector1]
    vpbroadcastd ymm2, DWORD PTR [SideFxVector2]
    vpbroadcastd ymm3, DWORD PTR [SideFxVector3]
    vpbroadcastd ymm4, DWORD PTR [SideFxVector4]
    vpbroadcastd ymm5, DWORD PTR [SideFxVector5]
    vpbroadcastd ymm6, DWORD PTR [SideFxVector6]
    vpbroadcastd ymm7, DWORD PTR [SideFxVector7]
    ldmxcsr DWORD PTR [SideFxMxcsr]
    fldcw   WORD PTR [SideFxX87cw]

    mov eax, 11111111h
    mov ebx, 22222222h
    mov ecx, 33333333h
    mov edx, 44444444h
    mov esi, 55555555h
    mov edi, 66666666h
    std

_SideFxSite:
    REPT 16
        nop
    ENDM

    mov DWORD PTR [ebp+00h], eax
    mov DWORD PTR [ebp+04h], ebx
    mov DWORD PTR [ebp+08h], ecx
    mov DWORD PTR [ebp+0Ch], edx
    mov DWORD PTR [ebp+10h], esi
    mov DWORD PTR [ebp+14h], edi

    vmovdqu XMMWORD PTR [ebp+SIDEFX_XMM+00h], xmm0
    vmovdqu XMMWORD PTR [ebp+SIDEFX_XMM+10h], xmm1
    vmovdqu XMMWORD PTR [ebp+SIDEFX_XMM+20h], xmm2
    vmovdqu XMMWORD PTR [ebp+SIDEFX_XMM+30h], xmm3
    vmovdqu XMMWORD PTR [ebp+SIDEFX_XMM+40h], xmm4
    vmovdqu XMMWORD PTR [ebp+SIDEFX_XMM+50h], xmm5
    vmovdqu XMMWORD PTR [ebp+SIDEFX_XMM+60h], xmm6
    vmovdqu XMMWORD PTR [ebp+SIDEFX_XMM+70h], xmm7
    vextracti128 XMMWORD PTR [ebp+SIDEFX_YMM+00h], ymm0, 1
    vextracti128 XMMWORD PTR [ebp+SIDEFX_YMM+10h], ymm1, 1
    vextracti128 XMMWORD PTR [ebp+SIDEFX_YMM+20h], ymm2, 1
    vextracti128 XMMWORD PTR [ebp+SIDEFX_YMM+30h], ymm3, 1
    vextracti128 XMMWORD PTR [ebp+SIDEFX_YMM+40h], ymm4, 1
    vextracti128 XMMWORD PTR [ebp+SIDEFX_YMM+50h], ymm5, 1
    vextracti128 XMMWORD PTR [ebp+SIDEFX_YMM+60h], ymm6, 1
    vextracti128 XMMWORD PTR [ebp+SIDEFX_YMM+70h], ymm7, 1
    stmxcsr DWORD PTR [ebp+SIDEFX_MXCSR_OUT]
    fnstcw  WORD PTR [ebp+SIDEFX_X87_OUT]

    ; Copy before PUSHFD contaminates the first below-SP word.
    lea  eax, [esp-512]
    lea  edx, [ebp+SIDEFX_BELOW_OUT]
    mov  ecx, 16
sidefx_copy_below:
    vmovdqu ymm0, YMMWORD PTR [eax]
    vmovdqu YMMWORD PTR [edx], ymm0
    add  eax, 32
    add  edx, 32
    dec  ecx
    jne  sidefx_copy_below
    pushfd
    pop  eax
    mov  DWORD PTR [ebp+SIDEFX_FLAGS], eax
    cld

    ldmxcsr DWORD PTR [esp]
    fldcw   WORD PTR [esp+4]
    vzeroupper
    add esp, 8
    pop edi
    pop esi
    pop ebx
    pop ebp
    ret
END
