; x86 (ml.exe) variant of flag.asm. Mid-function probe site inside the config
; library. At ParsedFlagSite EAX holds the freshly parsed reads_enabled value and
; ECX points at the output struct (parity with the x64 RCX), immediately before a
; real 2-byte store + RET: too short for a 5-byte inline jump, by design, so this
; site is breakpoint-only. ParsedFlagSite is found by RVA (map)/PDB, not called.
; Flat model, manual MSVC decoration (__cdecl -> _Name).
.686
.model flat
OPTION CASEMAP:NONE
PUBLIC _StoreParsedFlag, _ParsedFlagSite
.code
_StoreParsedFlag PROC
    mov ecx, DWORD PTR [esp+4]    ; __cdecl arg0 (parsed_config *out) -> ECX
    mov eax, DWORD PTR [esp+8]    ; __cdecl arg1 (value) -> EAX (parsed reads_enabled)
_ParsedFlagSite LABEL BYTE
    mov DWORD PTR [ecx], eax      ; *out = EAX; probe flips EAX to 1 before the store
    ret
_StoreParsedFlag ENDP
END
