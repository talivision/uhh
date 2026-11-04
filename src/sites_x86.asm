; x86 (ml.exe) variant of sites.asm. Same stable NOP-sled boundaries as the
; ml64 version; only the dialect and name decoration differ. Flat model, manual
; MSVC decoration: __cdecl/data -> _Name, __stdcall -> _Name@N. The sled labels
; are found by RVA/symbol (decoration stripped by site_rvas.py), not called.
; Parity with the x64 fixture: ECX holds the flag pointer and EAX the loaded
; value at the flag sites, so PROBE_REG_CX/AX read the same logical registers.
.686
.model flat
OPTION CASEMAP:NONE
EXTERN _g_ntread:DWORD
PUBLIC _FlagCheck, _FlagMemSite, _FlagRegSite, _ReadThunk@20, _ReadSite
.code
_FlagCheck PROC
    mov ecx, DWORD PTR [esp+4]    ; __cdecl arg0 (flag ptr) -> ECX for probe parity
_FlagMemSite LABEL BYTE
    REPT 16
        nop
    ENDM
    mov eax, DWORD PTR [ecx]      ; EAX = *flag at FlagRegSite
_FlagRegSite LABEL BYTE
    REPT 16
        nop
    ENDM
    ret
_FlagCheck ENDP
; __stdcall thunk: ESP is pristine (no prologue), so the 5 stack args forward
; unchanged and NtReadVirtualMemory@20 cleans them on return.
_ReadThunk@20:
_ReadSite LABEL BYTE
    REPT 16
        nop
    ENDM
    jmp DWORD PTR [_g_ntread]
END
