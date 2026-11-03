; Mid-function probe site inside the late-loaded config library.
; ParsedFlagSite is NOT exported: tooling finds it by RVA (linker map) or by
; symbol (PDB publics). At the site EAX holds the freshly parsed reads_enabled
; value and RCX points at the output struct. The site instruction is a real
; 2-byte store followed by RET: too short to patch a 5-byte inline jump safely,
; which is deliberate. Breakpoint backends do not modify code here.
OPTION CASEMAP:NONE
PUBLIC StoreParsedFlag, ParsedFlagSite
.code
StoreParsedFlag PROC
    mov eax, edx
ParsedFlagSite LABEL BYTE
    mov DWORD PTR [rcx], eax
    ret
StoreParsedFlag ENDP
END
