; probe_app's hookable read site (x86, ml.exe). Same as read_site_x64.asm: a 16-NOP
; sled that tail-jumps to NtReadVirtualMemory; __stdcall, so ESP is pristine and the
; 5 stack args forward unchanged. Exported as "ReadThunk" (CMakeLists.txt maps the
; decorated _ReadThunk@20). Flat model, manual MSVC decoration.
.686
.model flat
OPTION CASEMAP:NONE
EXTERN _g_ntread:DWORD
PUBLIC _ReadThunk@20, _ReadSite
.code
_ReadThunk@20:
_ReadSite LABEL BYTE
    REPT 16
        nop
    ENDM
    jmp DWORD PTR [_g_ntread]
END
