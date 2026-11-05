; x86 twin of conf_sp_x64.asm: `mov eax, esp` + nop keeps the probe at SpSite+3.
.686
.model flat
OPTION CASEMAP:NONE
PUBLIC _SpSite
.code
_SpSite PROC
    mov eax, esp
    nop
    REPT 16
        nop
    ENDM
    sub eax, esp
    add esp, eax
    ret
_SpSite ENDP

; ---- Portability matrix: x86 twin of the x64 PmRegSite / PmOther (see there) -------------
PUBLIC _PmRegSite
PUBLIC _PmRegHit
PUBLIC _PmOther
_PmRegSite PROC
    push ebx
    push ebp
    push esi
    push edi
    mov eax, 0A0A0A000h
    mov ebx, 0B1B1B101h
    mov ecx, 0C2C2C202h
    mov edx, 0D3D3D303h
    mov esi, 054545404h
    mov edi, 065656505h
    mov ebp, 076767606h
    stc
_PmRegHit::
    REPT 16
        nop
    ENDM
    push eax
    mov eax, [esp+24]
    mov [eax+88], ebx
    mov dword ptr [eax+92], 0
    mov [eax+96], ecx
    mov dword ptr [eax+100], 0
    mov [eax+104], edx
    mov dword ptr [eax+108], 0
    mov [eax+112], esi
    mov dword ptr [eax+116], 0
    mov [eax+120], edi
    mov dword ptr [eax+124], 0
    mov [eax+128], ebp
    mov dword ptr [eax+132], 0
    pop dword ptr [eax+80]
    mov dword ptr [eax+84], 0
    setc byte ptr [eax+208]
    pop edi
    pop esi
    pop ebp
    pop ebx
    ret
_PmRegSite ENDP

_PmOther PROC
    REPT 16
        nop
    ENDM
    mov eax, [esp+4]
    lea eax, [eax+eax*2+1]
    ret
_PmOther ENDP
END
