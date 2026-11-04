; Stable x64 sites for the Frida-parity fixture. The entry sleds are deliberately
; long enough for SafetyHook inline relocation; the B6 site is one arbitrary
; mid-function instruction and therefore uses a hardware execute breakpoint.
OPTION CASEMAP:NONE
EXTERN ParityObserve:PROC
PUBLIC ParityB1, ParityB1Site, ParityB2, ParityB2Site
PUBLIC ParityB4, ParityB4Site, ParityMidRegister, ParityB6Site
.code

ParityB1 PROC
ParityB1Site LABEL BYTE
    REPT 16
        nop
    ENDM
    jmp ParityObserve
ParityB1 ENDP

ParityB2 PROC
ParityB2Site LABEL BYTE
    REPT 16
        nop
    ENDM
    jmp ParityObserve
ParityB2 ENDP

ParityB4 PROC
ParityB4Site LABEL BYTE
    REPT 16
        nop
    ENDM
    jmp ParityObserve
ParityB4 ENDP

ParityMidRegister PROC
    mov eax, 7
ParityB6Site LABEL BYTE
    nop
    ret
ParityMidRegister ENDP
END
