; Controller-review fixture sites (x86 twin of ctrl_sites_x64.asm, cdecl).
.686
.model flat, C
OPTION CASEMAP:NONE
PUBLIC CtrlLoad, CtrlLoadInsn, CtrlLoop, CtrlLoopInsn

.code
CtrlLoad PROC
    mov ecx, dword ptr [esp+4]
CtrlLoadInsn::
    mov eax, dword ptr [ecx]
    nop
    nop
    nop
    nop
    nop
    ret
CtrlLoad ENDP

; Address-size prefixed LOOP (counter CX on x86): not emulated -> in-place step.
CtrlLoop PROC
    mov edx, dword ptr [esp+4]
    mov ecx, 1
CtrlLoopInsn::
    DB 67h, 0E2h, 00h            ; addr16 loop $+3 (falls through either way)
    mov eax, edx
    nop
    nop
    nop
    nop
    nop
    ret
CtrlLoop ENDP
END
