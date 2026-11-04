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
END
