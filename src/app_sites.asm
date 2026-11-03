; Read forwarding site for probe_app. ReadSite is a stable mid-function boundary
; (16-NOP sled) safe for inline relocation in this fixture. ReadSite is found by
; RVA/symbol, not exported for direct call.
OPTION CASEMAP:NONE
EXTERN g_ntread:QWORD
PUBLIC ReadThunk, ReadSite
.code
ReadThunk PROC
ReadSite LABEL BYTE
    REPT 16
        nop
    ENDM
    jmp QWORD PTR [g_ntread]     ; preserve NtReadVirtualMemory ABI and stack args
ReadThunk ENDP
END
