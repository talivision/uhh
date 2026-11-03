; Deliberate, stable instruction boundaries. The NOP sleds allow safe relocation
; in this fixture; they are NOT a claim about arbitrary existing instructions.
OPTION CASEMAP:NONE
EXTERN g_ntread:QWORD
PUBLIC FlagCheck, FlagMemSite, FlagRegSite, ReadThunk, ReadSite
.code
FlagCheck PROC
    lea rax, [rcx]               ; establish that FlagMemSite is mid-function
FlagMemSite LABEL BYTE
    REPT 16
        nop
    ENDM
    mov eax, DWORD PTR [rcx]
FlagRegSite LABEL BYTE
    REPT 16
        nop
    ENDM
    ret
FlagCheck ENDP
ReadThunk PROC
ReadSite LABEL BYTE
    REPT 16
        nop
    ENDM
    jmp QWORD PTR [g_ntread]     ; preserve NtReadVirtualMemory ABI and stack args
ReadThunk ENDP
END
