; x64 probe sites for the stacks example (unwind data from PROC FRAME directives).
; int Stk*(int a) in ECX. Sites are global labels (::) so the map gives their RVAs.
OPTION CASEMAP:NONE
PUBLIC StkMid, StkMidSite, StkFpo, StkFpoSite, StkLeaf, StkLeafSite
.code

; RBP frame (.setframe), saves RSI, 30h of locals; probe mid-function.
StkMid PROC FRAME
    push rbp
    .pushreg rbp
    push rsi
    .pushreg rsi
    sub rsp, 30h
    .allocstack 30h
    lea rbp, [rsp+20h]
    .setframe rbp, 20h
    .endprolog
    mov esi, ecx
    mov dword ptr [rbp], 0
StkMidSite::
    mov eax, 1000h
    add eax, esi
    nop
    nop
    lea rsp, [rbp+10h]
    pop rsi
    pop rbp
    ret
StkMid ENDP

; No frame pointer: RBP is saved and then holds DATA at the site.
StkFpo PROC FRAME
    push rbp
    .pushreg rbp
    push rsi
    .pushreg rsi
    sub rsp, 28h
    .allocstack 28h
    .endprolog
    mov esi, ecx
    mov ebp, 0BAD0F00Dh
    mov dword ptr [rsp], esi
StkFpoSite::
    mov eax, 2000h
    add eax, esi
    nop
    nop
    add rsp, 28h
    pop rsi
    pop rbp
    ret
StkFpo ENDP

; Leaf: no unwind data, no stack adjustment; probe after the first instruction.
StkLeaf PROC
    mov eax, ecx
StkLeafSite::
    add eax, 3000h
    nop
    nop
    ret
StkLeaf ENDP
END
