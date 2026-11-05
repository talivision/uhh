; ccfix.dll, x64 twin of ccfix_x86.asm (no hot-patch prologue on x64): an incremental-link
; thunk (E9 rel32) followed by the next one, a tail-call jmp, and their (a, b, c) targets.
EXTERN cc_body:DWORD
PUBLIC CcIlt, CcIltNext, CcTail, CcStd3T, CcJmpDst

.code
    ALIGN 16
CcIlt PROC
    db 0E9h
    dd CcStd3T - ($ + 4)
CcIlt ENDP
CcIltNext PROC
    db 0E9h
    dd CcJmpDst - ($ + 4)
CcIltNext ENDP

    ALIGN 16
CcTail PROC
    db 0E9h
    dd CcJmpDst - ($ + 4)
CcTail ENDP

    ALIGN 16
CcStd3T PROC
    lock inc cc_body
    imul eax, ecx, 100
    imul edx, edx, 10
    add eax, edx
    add eax, r8d
    ret
CcStd3T ENDP

    ALIGN 16
CcJmpDst PROC
    lock inc cc_body
    imul eax, ecx, 100
    imul edx, edx, 10
    add eax, edx
    add eax, r8d
    ret
CcJmpDst ENDP
END
