; Deliberately hostile x64 probe sites. Labels are public only so site_rvas.py can
; recover their RVAs from hook_edge.map; the C target calls the enclosing code.
OPTION CASEMAP:NONE
EXTERN ForeignReplacement:PROC
PUBLIC ShortSite, PrehookSite, PrehookOriginal, UnrelocFunction, UnrelocSite
PUBLIC StackSite, StackInsideSite
.code

; Only two bytes precede RET. An inline installer must not steal through the RET
; merely to reach its five-byte patch minimum.
ShortSite PROC
    xor eax, eax
    ret
ShortSite ENDP

; Keep the foreign E9 in the image: CREATE_PROCESS probes can arm before TLS runs,
; but they must all observe an already-detoured entry. TLS owns its trampoline.
PrehookSite PROC
    jmp ForeignReplacement
    ret
PrehookSite ENDP
PrehookOriginal LABEL BYTE
    mov eax, ecx
    add eax, 10

; JRCXZ has only a rel8 encoding. A byte-for-byte trampoline copy branches to an
; address relative to the trampoline instead of UnrelocZero.
UnrelocFunction PROC
UnrelocSite LABEL BYTE
    jrcxz SHORT UnrelocZero
    mov eax, 0BADh
    ret
UnrelocZero:
    mov eax, 77
    ret
UnrelocFunction ENDP

; StackInsideSite is inside the first five bytes an outer detour must steal.
StackSite PROC
    nop
    nop
StackInsideSite LABEL BYTE
    REPT 14
        nop
    ENDM
    lea eax, [rcx+1]
    ret
StackSite ENDP
END
