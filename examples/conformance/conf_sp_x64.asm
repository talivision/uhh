; SpSite: measures how far the stack pointer moved across the probe at SpSite+3.
;   mov rax, rsp ; <probe: callback does set_reg(SP, SP - 32)> ; nops ; sub rax, rsp ; add rsp, rax ; ret
; Returns 32 when set_reg(SP) took effect (every backend must agree), 0 otherwise.
; (Test fixture; callbacks themselves are plain C.)
OPTION CASEMAP:NONE
PUBLIC SpSite
.code
SpSite PROC
    mov rax, rsp
    REPT 16
        nop
    ENDM
    sub rax, rsp
    add rsp, rax
    ret
SpSite ENDP

; ---- Portability matrix (conformance_target --matrix) -------------------------------------
; PmRegSite(pm_env *env): every GPR but RSP gets a known constant and CF is set, then the
; probe at PmRegHit (mid-function) records get_reg for each and set_regs new values; after
; the site every GPR is stored to env->out[reg] (probe_register order) and CF to env->cf.
PUBLIC PmRegSite
PUBLIC PmRegHit
PUBLIC PmOther
PmRegSite PROC
    push rbx
    push rbp
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    push rcx
    mov rax, 0A0A0A0A0A0A0A000h
    mov rbx, 0B1B1B1B1B1B1B101h
    mov rcx, 0C2C2C2C2C2C2C202h
    mov rdx, 0D3D3D3D3D3D3D303h
    mov rsi, 05454545454545404h
    mov rdi, 06565656565656505h
    mov rbp, 07676767676767606h
    mov r8,  08888888888888808h
    mov r9,  09999999999999909h
    mov r10, 0AAAAAAAAAAAAAA0Ah
    mov r11, 0BBBBBBBBBBBBBB0Bh
    mov r12, 0CCCCCCCCCCCCCC0Ch
    mov r13, 0DDDDDDDDDDDDDD0Dh
    mov r14, 0EEEEEEEEEEEEEE0Eh
    mov r15, 0FFFFFFFFFFFFFF0Fh
    stc
PmRegHit::
    REPT 16
        nop
    ENDM
    push rax
    mov rax, [rsp+8]
    mov [rax+88], rbx
    mov [rax+96], rcx
    mov [rax+104], rdx
    mov [rax+112], rsi
    mov [rax+120], rdi
    mov [rax+128], rbp
    mov [rax+144], r8
    mov [rax+152], r9
    mov [rax+160], r10
    mov [rax+168], r11
    mov [rax+176], r12
    mov [rax+184], r13
    mov [rax+192], r14
    mov [rax+200], r15
    pop qword ptr [rax+80]
    setc byte ptr [rax+208]
    pop rcx
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    ret
PmRegSite ENDP

; PmOther(x): probed by a DIFFERENT backend than the matrix run; callbacks read its bytes.
PmOther PROC
    REPT 16
        nop
    ENDM
    lea rax, [rcx+rcx*2+1]
    ret
PmOther ENDP
END
