; x86 (ml.exe) variant of app_sites.asm. ReadSite is the stable mid-function
; boundary (16-NOP sled) found by RVA/symbol; ReadThunk is the __stdcall
; forwarder. Flat model, manual MSVC decoration (__stdcall -> _Name@N, data
; -> _Name). ESP is pristine at the thunk, so the 5 stack args forward unchanged.
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
