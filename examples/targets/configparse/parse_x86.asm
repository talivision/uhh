; configparse.dll!ParseConfig (x86, __cdecl).
;   int ParseConfig(const char *text, parsed_config *out)
;
; The flag site is at a FIXED offset from the export: ParseConfig+0x16, the same
; offset as the x64 build (parse_x64.asm). At that instruction EAX holds the freshly
; parsed reads_enabled value and EBX points at *out, just before the store. Every
; instruction before the site has a fixed encoding (byte counts on the right).
.686
.model flat
OPTION CASEMAP:NONE
EXTERN _ParseReadsEnabled:PROC
PUBLIC _ParseConfig, _ParsedFlagSite
.code
_ParseConfig PROC
    push ebx                        ; 1   +00
    mov  ebx, DWORD PTR [esp+0Ch]   ; 4   +01  out   ([esp]=ebx [esp+4]=ret [esp+8]=text)
    push ebx                        ; 1   +05  arg1 = out
    push DWORD PTR [esp+0Ch]        ; 4   +06  arg0 = text
    call _ParseReadsEnabled         ; 5   +0A  eax = 0/1, or -1
    add  esp, 8                     ; 3   +0F
    test eax, eax                   ; 2   +12
    js   SHORT failed               ; 2   +14
_ParsedFlagSite LABEL BYTE          ;     +16
    mov  DWORD PTR [ebx], eax       ; out->reads_enabled = EAX
    mov  eax, 1
    pop  ebx
    ret
failed:
    xor  eax, eax
    pop  ebx
    ret
_ParseConfig ENDP
END
