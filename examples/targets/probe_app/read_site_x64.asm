; probe_app's own read/open wrappers (x64). The examples probe the ntdll stubs
; directly; these exported wrappers exist for the tests that need a site in the target's
; OWN image (another tool pre-hooking it: --prehook, Frida coexistence). Every remote
; read goes through ReadThunk,
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
; NtOpenProcess(PHANDLE out, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID).
OpenThunk PROC
    REPT 16
        nop
    ENDM
    jmp QWORD PTR [g_ntopen]
OpenThunk ENDP
END
