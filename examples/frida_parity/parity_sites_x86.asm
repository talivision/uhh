; x86 (ml.exe) twin of parity_sites_x64.asm. Explicit decoration matches the C
; __stdcall declarations; site_rvas.py strips the labels' leading underscores.
.686
.model flat
OPTION CASEMAP:NONE
EXTERN _ParityObserve@12:PROC
PUBLIC _ParityB1@12, _ParityB1Site, _ParityB2@12, _ParityB2Site
PUBLIC _ParityB4@12, _ParityB4Site, _ParityMidRegister@0, _ParityB6Site
.code

_ParityB1@12:
_ParityB1Site LABEL BYTE
    REPT 16
        nop
    ENDM
    jmp _ParityObserve@12

_ParityB2@12:
_ParityB2Site LABEL BYTE
    REPT 16
        nop
    ENDM
    jmp _ParityObserve@12

_ParityB4@12:
_ParityB4Site LABEL BYTE
    REPT 16
        nop
    ENDM
    jmp _ParityObserve@12

_ParityMidRegister@0:
    mov eax, 7
_ParityB6Site LABEL BYTE
    nop
    ret
END
