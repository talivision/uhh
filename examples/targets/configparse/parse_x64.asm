; configparse.dll!ParseConfig (x64).
;   int ParseConfig(const char *text [rcx], parsed_config *out [rdx])
;
; The flag site is at a FIXED offset from the export: ParseConfig+0x16, the same
; offset as the x86 build (parse_x86.asm). At that instruction EAX holds the freshly
; parsed reads_enabled value (0 in the shipped config) and RBX points at *out; the
; store has not happened yet, so flipping EAX to 1 there turns the feature on.
; ParsedFlagSite is also PUBLIC so the linker map shows it (regress.py cross-checks
; +0x16 against the map). Every instruction before the site has a fixed encoding
; (byte counts on the right), so the offset cannot drift between builds.
OPTION CASEMAP:NONE
EXTERN ParseReadsEnabled:PROC
PUBLIC ParseConfig, ParsedFlagSite
.code
ParseConfig PROC FRAME
    push rbx                        ; 1   +00
    .pushreg rbx
    sub  rsp, 20h                   ; 4   +01
    .allocstack 20h
    .endprolog
    mov  rbx, rdx                   ; 3   +05  keep out
    call ParseReadsEnabled          ; 5   +08  eax = 0/1, or -1 (rcx/rdx already the args)
    test eax, eax                   ; 2   +0D
    js   SHORT failed               ; 2   +0F
    DB 0Fh, 1Fh, 44h, 00h, 00h      ; 5   +11  5-byte NOP: same site offset as x86
ParsedFlagSite LABEL BYTE           ;     +16
    mov  DWORD PTR [rbx], eax       ; out->reads_enabled = EAX
    mov  eax, 1
    add  rsp, 20h
    pop  rbx
    ret
failed:
    xor  eax, eax
    add  rsp, 20h
    pop  rbx
    ret
ParseConfig ENDP
END
