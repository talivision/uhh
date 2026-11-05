; Controller-review fixture sites (x64). See ctrl_target.cpp.
OPTION CASEMAP:NONE
PUBLIC CtrlLoad, CtrlLoadInsn, CtrlLoop, CtrlLoopInsn, CtrlSled

.code
; int CtrlLoad(const int *p): the probed instruction is the load itself (it faults on a
; reserved or guard page; the target's VEH fixes the page and continues execution).
CtrlLoad PROC
CtrlLoadInsn::
    mov eax, dword ptr [rcx]
    nop
    nop
    nop
    nop
    nop
    ret
CtrlLoad ENDP

; uint32 CtrlLoop(uint32 tag): returns tag. The probed instruction is an address-size
; prefixed LOOP (counter ECX), which the controller neither displaces nor emulates: the
; software breakpoint takes the in-place (lift + single-step) path. ECX = 1 -> not taken.
CtrlLoop PROC
    mov edx, ecx
    mov ecx, 1
CtrlLoopInsn::
    DB 67h, 0E2h, 00h            ; addr32 loop $+3 (falls through either way)
    mov eax, edx
    nop
    nop
    nop
    nop
    nop
    ret
CtrlLoop ENDP
; CtrlSled: 1200 one-byte instructions, never executed -- the cdx-int3cap check arms a
; software breakpoint on each (more than the agent's INT3 table used to hold).
CtrlSled PROC
    DB 1200 DUP (90h)
    ret
CtrlSled ENDP
END
