; call_original / return_from hunt: exact code shapes the C compiler would not guarantee.
PUBLIC CoMidPush, CoPrologue, CoCallPrologue, CoRepFill, CoRepSite

.code
; intptr_t CoMidPush(intptr_t a) = a + 1. A probe at CoMidPush+1 is MID-function: [rsp] is
; the saved rbx, not a return address -- call_original / return_from must refuse there.
CoMidPush PROC
    push rbx
    lea rax, [rcx+1]
    pop rbx
    ret
CoMidPush ENDP

; intptr_t CoPrologue(intptr_t a) = 2a, behind a callee-saved prologue that clobbers them.
CoPrologue PROC
    push rbx
    push rsi
    push rdi
    push r12
    mov rbx, 1
    mov rsi, 2
    mov rdi, 3
    mov r12, 4
    lea rax, [rcx+rcx]
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
CoPrologue ENDP

; intptr_t CoCallPrologue(intptr_t a, intptr_t *out): calls CoPrologue(a) with sentinels in
; rbx/rsi/rdi/r12, stores its result in *out and returns 1 iff every sentinel survived.
CoCallPrologue PROC
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    sub rsp, 20h
    mov r13, rdx
    mov rbx, 11111111h
    mov rsi, 22222222h
    mov rdi, 33333333h
    mov r12, 44444444h
    call CoPrologue
    mov [r13], rax
    xor eax, eax
    cmp rbx, 11111111h
    jne bad
    cmp rsi, 22222222h
    jne bad
    cmp rdi, 33333333h
    jne bad
    cmp r12, 44444444h
    jne bad
    mov eax, 1
bad:
    add rsp, 20h
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
CoCallPrologue ENDP

; void CoRepFill(void *dst, size_t n, int v): memset by `rep stosb` at CoRepSite (cxlib-reptail:
; a breakpoint runs it out-of-line, ending at an INT3 in UHH's scratch instead of a trap flag).
CoRepFill PROC
    push rdi
    mov rdi, rcx
    mov rcx, rdx
    mov eax, r8d
CoRepSite::
    rep stosb
    pop rdi
    ret
CoRepFill ENDP
END
