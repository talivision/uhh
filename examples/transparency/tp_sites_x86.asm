; Transparency fixture (x86 twin of tp_sites_x64.asm). See tp_target.cpp.
;   TpIn:  a[8] +0 (low dwords pushed), nargs +50h, fpret +54h
;   TpOut: rax +0, rdx +8, xmm0 +10h, nv +20h (ebx ebp esi edi as qwords), sp_delta +100h,
;          flags +108h, st0 +110h, fsw +118h, ftw +11Ch
;   TpMidOut: gpr[15] +0 (eax ebx ecx edx esi edi ebp as qwords), flags +78h, xmm[8] +80h,
;             FNSAVE image +180h, YMM0-7 upper halves +1F0h
.686
.xmm
.model flat
OPTION CASEMAP:NONE
PUBLIC _TpHarness, _TpMid, _TpMidRef, _TpMidHit

.data
ALIGN 16
SentX   dd 11111111h, 0A1A1A1A1h, 21212121h, 31313131h, 22222222h, 0A2A2A2A2h, 23232323h, 32323232h
        dd 33333333h, 0A3A3A3A3h, 34343434h, 43434343h, 44444444h, 0A4A4A4A4h, 45454545h, 54545454h
        dd 55555555h, 0A5A5A5A5h, 56565656h, 65656565h, 66666666h, 0A6A6A6A6h, 67676767h, 76767676h
        dd 77777777h, 0A7A7A7A7h, 78787878h, 87878787h, 88888888h, 0A8A8A8A8h, 89898989h, 98989898h
SentY   dd 0D0D0D001h, 0D1D1D101h, 0D2D2D201h, 0D3D3D301h, 0D0D0D002h, 0D1D1D102h, 0D2D2D202h, 0D3D3D302h
        dd 0D0D0D003h, 0D1D1D103h, 0D2D2D203h, 0D3D3D303h, 0D0D0D004h, 0D1D1D104h, 0D2D2D204h, 0D3D3D304h
        dd 0D0D0D005h, 0D1D1D105h, 0D2D2D205h, 0D3D3D305h, 0D0D0D006h, 0D1D1D106h, 0D2D2D206h, 0D3D3D306h
        dd 0D0D0D007h, 0D1D1D107h, 0D2D2D207h, 0D3D3D307h, 0D0D0D008h, 0D1D1D108h, 0D2D2D208h, 0D3D3D308h
FpVals  dq 3FF0000000000000h, 4000000000000000h, 4008000000000000h, 4010000000000000h
        dq 4014000000000000h, 4018000000000000h, 401C000000000000h, 4020000000000000h
FpCw    dw 027Fh
FpCwMid dw 0E7Fh
ALIGN 4
g_fn    dd 0
g_in    dd 0
g_out   dd 0
g_esp   dd 0
g_espc  dd 0
g_after dd 0
g_eax   dd 0
g_mout  dd 0
g_env   db 28 dup(0)

.code
_TpHarness PROC
    push ebp
    push ebx
    push esi
    push edi
    mov eax, [esp+20]
    mov [g_fn], eax
    mov edx, [esp+24]
    mov [g_in], edx
    mov eax, [esp+28]
    mov [g_out], eax
    mov [g_esp], esp
    mov ecx, [edx+50h]
push_loop:
    test ecx, ecx
    jz pushed
    dec ecx
    push dword ptr [edx+ecx*8]
    jmp push_loop
pushed:
    mov [g_espc], esp
    mov ebx, 0B1B1B1B1h
    mov ebp, 0B2B2B2B2h
    mov esi, 0B3B3B3B3h
    mov edi, 0B4B4B4B4h
    mov ecx, 0B5B5B5B5h
    mov edx, 0B6B6B6B6h
    cld
    call dword ptr [g_fn]
    mov [g_after], esp
    mov esp, [g_esp]
    mov [g_eax], eax
    pushfd
    mov eax, [g_out]
    pop dword ptr [eax+108h]
    mov dword ptr [eax+10Ch], 0
    mov ecx, [g_eax]
    mov [eax], ecx
    mov dword ptr [eax+4], 0
    mov [eax+8], edx
    mov dword ptr [eax+0Ch], 0
    movdqu [eax+10h], xmm0
    mov [eax+20h], ebx
    mov dword ptr [eax+24h], 0
    mov [eax+28h], ebp
    mov dword ptr [eax+2Ch], 0
    mov [eax+30h], esi
    mov dword ptr [eax+34h], 0
    mov [eax+38h], edi
    mov dword ptr [eax+3Ch], 0
    mov ecx, [g_after]
    sub ecx, [g_espc]
    mov [eax+100h], ecx
    sar ecx, 31
    mov [eax+104h], ecx
    fnstsw word ptr [eax+118h]
    mov word ptr [eax+11Ah], 0
    mov edx, [g_in]
    cmp dword ptr [edx+54h], 0
    je no_fp
    fstp qword ptr [eax+110h]
no_fp:
    fnstenv [g_env]
    fldenv [g_env]                      ; fnstenv masked every exception: put the CW back
    movzx ecx, word ptr [g_env+8]
    mov [eax+11Ch], ecx
    pop edi
    pop esi
    pop ebx
    pop ebp
    ret
_TpHarness ENDP

MIDPRE MACRO
    push ebp
    push ebx
    push esi
    push edi
    mov eax, [esp+20]
    mov [g_mout], eax
    fninit
    fldcw word ptr [FpCwMid]
    fld qword ptr [FpVals+00h]
    fld qword ptr [FpVals+08h]
    fld qword ptr [FpVals+10h]
    fld qword ptr [FpVals+18h]
    fld qword ptr [FpVals+20h]
    fld qword ptr [FpVals+28h]
    fld qword ptr [FpVals+30h]
    fld qword ptr [FpVals+38h]
    fcom st(3)
    vinsertf128 ymm0, ymm0, xmmword ptr [SentY+00h], 1
    vinsertf128 ymm1, ymm1, xmmword ptr [SentY+10h], 1
    vinsertf128 ymm2, ymm2, xmmword ptr [SentY+20h], 1
    vinsertf128 ymm3, ymm3, xmmword ptr [SentY+30h], 1
    vinsertf128 ymm4, ymm4, xmmword ptr [SentY+40h], 1
    vinsertf128 ymm5, ymm5, xmmword ptr [SentY+50h], 1
    vinsertf128 ymm6, ymm6, xmmword ptr [SentY+60h], 1
    vinsertf128 ymm7, ymm7, xmmword ptr [SentY+70h], 1
    movdqu xmm0, xmmword ptr [SentX+00h]
    movdqu xmm1, xmmword ptr [SentX+10h]
    movdqu xmm2, xmmword ptr [SentX+20h]
    movdqu xmm3, xmmword ptr [SentX+30h]
    movdqu xmm4, xmmword ptr [SentX+40h]
    movdqu xmm5, xmmword ptr [SentX+50h]
    movdqu xmm6, xmmword ptr [SentX+60h]
    movdqu xmm7, xmmword ptr [SentX+70h]
    mov eax, 0C0C0C0C1h
    mov ebx, 0C0C0C0C2h
    mov ecx, 0C0C0C0C3h
    mov edx, 0C0C0C0C4h
    mov esi, 0C0C0C0C5h
    mov edi, 0C0C0C0C6h
    mov ebp, 0C0C0C0C7h
    std
    cmp eax, ebx
ENDM

MIDPOST MACRO
    db 0Fh, 1Fh, 84h, 00h, 00h, 00h, 00h, 00h   ; 8-byte nop: the probed instruction
    pushfd
    mov [g_eax], eax
    mov eax, [g_mout]
    pop dword ptr [eax+78h]
    cld
    mov [eax+08h], ebx
    mov [eax+10h], ecx
    mov [eax+18h], edx
    mov [eax+20h], esi
    mov [eax+28h], edi
    mov [eax+30h], ebp
    mov ecx, [g_eax]
    mov [eax], ecx
    movdqu [eax+080h], xmm0
    movdqu [eax+090h], xmm1
    movdqu [eax+0A0h], xmm2
    movdqu [eax+0B0h], xmm3
    movdqu [eax+0C0h], xmm4
    movdqu [eax+0D0h], xmm5
    movdqu [eax+0E0h], xmm6
    movdqu [eax+0F0h], xmm7
    vextractf128 xmmword ptr [eax+1F0h], ymm0, 1
    vextractf128 xmmword ptr [eax+200h], ymm1, 1
    vextractf128 xmmword ptr [eax+210h], ymm2, 1
    vextractf128 xmmword ptr [eax+220h], ymm3, 1
    vextractf128 xmmword ptr [eax+230h], ymm4, 1
    vextractf128 xmmword ptr [eax+240h], ymm5, 1
    vextractf128 xmmword ptr [eax+250h], ymm6, 1
    vextractf128 xmmword ptr [eax+260h], ymm7, 1
    vzeroupper
    fnsave [eax+180h]
    fldcw word ptr [FpCw]
    pop edi
    pop esi
    pop ebx
    pop ebp
    ret
ENDM

; Plain labels, no PROC: 32-bit MASM scopes labels inside a PROC, and _TpMidHit must be public.
_TpMid:
    MIDPRE
_TpMidHit:
    MIDPOST

_TpMidRef:
    MIDPRE
    MIDPOST
END
