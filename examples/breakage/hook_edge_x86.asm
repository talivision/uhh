; x86 (ml.exe) variant of hook_edge_x64.asm. C functions/data use the normal
; leading underscore decoration; site_rvas.py strips it for lookup.
.686
.model flat
OPTION CASEMAP:NONE
EXTERN _ForeignReplacement:PROC
PUBLIC _ShortSite, _PrehookSite, _PrehookOriginal, _UnrelocFunction, _UnrelocSite
PUBLIC _StackSite, _StackInsideSite
.code

_ShortSite PROC
    xor eax, eax
    ret
_ShortSite ENDP

_PrehookSite PROC
    jmp _ForeignReplacement
    add eax, 9
    ret
_PrehookSite ENDP
; Four-byte load plus one-byte INC is the exact block copied by the foreign hook.
_PrehookOriginal LABEL BYTE
    mov eax, DWORD PTR [esp+4]
    inc eax

_UnrelocFunction PROC
    mov ecx, DWORD PTR [esp+4]
_UnrelocSite LABEL BYTE
    jecxz SHORT UnrelocZero
    mov eax, 0BADh
    ret
UnrelocZero:
    mov eax, 77
    ret
_UnrelocFunction ENDP

_StackSite PROC
    nop
    nop
_StackInsideSite LABEL BYTE
    REPT 14
        nop
    ENDM
    mov eax, DWORD PTR [esp+4]
    inc eax
    ret
_StackSite ENDP
END
