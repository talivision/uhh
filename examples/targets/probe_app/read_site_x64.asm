; probe_app's hookable read site (x64). Every remote read goes through ReadThunk,
; a 16-NOP sled (room for any inline hook) that tail-jumps to NtReadVirtualMemory
; with the arguments untouched. probe_app.exe EXPORTS ReadThunk (see CMakeLists.txt),
; so tools address it as "probe_app.exe!ReadThunk" -- no linker map needed.
OPTION CASEMAP:NONE
EXTERN g_ntread:QWORD
EXTERN g_ntopen:QWORD
PUBLIC ReadThunk, ReadSite, OpenThunk
.code
ReadThunk PROC
ReadSite LABEL BYTE
    REPT 16
        nop
    ENDM
    jmp QWORD PTR [g_ntread]     ; preserve NtReadVirtualMemory ABI and stack args
ReadThunk ENDP

; OpenThunk: the target's own open wrapper (same shape as ReadThunk) around
; NtOpenProcess(PHANDLE out, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID). Probing the
; target's wrapper rather than the ntdll syscall stub keeps the open probe on the same
; backend as the read probe (ntdll's stub pages are off-limits to inline hooks).
OpenThunk PROC
    REPT 16
        nop
    ENDM
    jmp QWORD PTR [g_ntopen]
OpenThunk ENDP
END
