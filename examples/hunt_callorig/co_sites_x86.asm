; x86 twin of co_sites_x64.asm (cdecl), plus a __thiscall callee.
.686
.model flat, C
OPTION CASEMAP:NONE

PUBLIC CoMidPush, CoPrologue, CoCallPrologue, CoThis, CoRepFill, CoRepSite

EXTERN co_rettf:PROC
PUBLIC CoCallRetTf

.code
; int CoMidPush(int a) = a + 1; a probe at CoMidPush+1 is mid-function ([esp] = saved ebx).
CoMidPush PROC
    push ebx
    mov eax, [esp+8]
    inc eax
    pop ebx
    ret
CoMidPush ENDP

; int CoPrologue(int a) = 2a, behind a callee-saved prologue that clobbers them.
CoPrologue PROC
    push ebx
    push esi
    push edi
    mov ebx, 1
    mov esi, 2
    mov edi, 3
    mov eax, [esp+16]
    add eax, eax
    pop edi
    pop esi
    pop ebx
    ret
CoPrologue ENDP

; int CoCallPrologue(int a, int *out): sentinels in ebx/esi/edi/ebp across CoPrologue(a).
CoCallPrologue PROC
    push ebx
    push esi
    push edi
    push ebp
    mov ebx, 11111111h
    mov esi, 22222222h
    mov edi, 33333333h
    mov ebp, 44444444h
    push dword ptr [esp+20]
    call CoPrologue
    add esp, 4
    mov ecx, [esp+24]
    mov [ecx], eax
    xor eax, eax
    cmp ebx, 11111111h
    jne bad
    cmp esi, 22222222h
    jne bad
    cmp edi, 33333333h
    jne bad
    cmp ebp, 44444444h
    jne bad
    mov eax, 1
bad:
    pop ebp
    pop edi
    pop esi
    pop ebx
    ret
CoCallPrologue ENDP

; __thiscall int CoThis(this = ecx -> int k, int a, int b) = (k + a) * b; callee pops 8.
CoThis PROC
    mov eax, [ecx]
    add eax, [esp+4]
    imul eax, [esp+8]
    ret 8
CoThis ENDP

; void CoRepFill(void *dst, size_t n, int v): memset by `rep stosb` at CoRepSite (cxlib-reptail).
CoRepFill PROC
    push edi
    mov edi, [esp+8]
    mov ecx, [esp+12]
    mov eax, [esp+16]
CoRepSite::
    rep stosb
    pop edi
    ret
CoRepFill ENDP
; Known instruction immediately after the real return: the target's TF trap
; must reach its VEH at the NOP or immediately after it, exactly once per call.
CoCallRetTf PROC
    push dword ptr [esp+4]
    call co_rettf
    nop
    add esp, 4
    ret
CoCallRetTf ENDP
END
