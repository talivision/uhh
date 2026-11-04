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
END
