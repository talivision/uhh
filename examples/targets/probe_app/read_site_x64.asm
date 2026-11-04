; probe_app's hookable read site (x64). Every remote read goes through ReadThunk,
; a 16-NOP sled (room for any inline hook) that tail-jumps to NtReadVirtualMemory
; with the arguments untouched. probe_app.exe EXPORTS ReadThunk (see CMakeLists.txt),
; so tools address it as "probe_app.exe!ReadThunk" -- no linker map needed.
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
