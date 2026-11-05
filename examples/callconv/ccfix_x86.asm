; ccfix.dll, x86: shapes the C compiler does not produce on demand.
;   CcHot      __stdcall (a, b) = a + b behind the hot-patch prologue every 32-bit system DLL
;              export starts with (mov edi,edi / push ebp / mov ebp,esp), 5 bytes of padding before.
;   CcIlt      an incremental-link thunk: E9 rel32 to CcStd3T, directly followed by the next
;              thunk (CcIltNext), as /INCREMENTAL lays them out.
;   CcTail     a tail call: a bare jmp into CcJmpDst, so CcJmpDst is entered by a jmp, with the
;              return address of CcTail's caller at [esp].
;   CcStd3T, CcJmpDst   __stdcall (a, b, c) = 100a + 10b + c, ret 12.
.686
.xmm
.model flat, C
OPTION CASEMAP:NONE

EXTERN cc_body:DWORD
PUBLIC CcHot, CcIlt, CcIltNext, CcTail, CcStd3T, CcJmpDst

.code
    ALIGN 16
    db 5 dup (0CCh)
CcHot PROC
    mov edi, edi
    push ebp
    mov ebp, esp
    lock inc cc_body
    mov eax, [ebp+8]
    add eax, [ebp+12]
    pop ebp
    ret 8
CcHot ENDP

    ALIGN 16
CcIlt PROC
    db 0E9h
    dd OFFSET CcStd3T - ($ + 4)
CcIlt ENDP
CcIltNext PROC
    db 0E9h
    dd OFFSET CcJmpDst - ($ + 4)
CcIltNext ENDP

    ALIGN 16
CcTail PROC
    db 0E9h
    dd OFFSET CcJmpDst - ($ + 4)
CcTail ENDP

    ALIGN 16
CcStd3T PROC
    lock inc cc_body
    mov eax, [esp+4]
    imul eax, eax, 100
    mov ecx, [esp+8]
    imul ecx, ecx, 10
    add eax, ecx
    add eax, [esp+12]
    ret 12
CcStd3T ENDP

    ALIGN 16
CcJmpDst PROC
    lock inc cc_body
    mov eax, [esp+4]
    imul eax, eax, 100
    mov ecx, [esp+8]
    imul ecx, ecx, 10
    add eax, ecx
    add eax, [esp+12]
    ret 12
CcJmpDst ENDP
END
