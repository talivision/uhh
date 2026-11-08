; Controller-review fixture sites (x86 twin of ctrl_sites_x64.asm, cdecl).
.686
.model flat, C
OPTION CASEMAP:NONE
PUBLIC CtrlLoad, CtrlLoadInsn, CtrlLoop, CtrlLoopInsn, CtrlSled

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
; CtrlSled: 1200 one-byte instructions, never executed -- the cdx-int3cap check arms a
; software breakpoint on each (more than the agent's INT3 table used to hold).
CtrlSled PROC
    DB 1200 DUP (90h)
    ret
CtrlSled ENDP
PUBLIC CtrlHiddenBranch, CtrlMixedJump
CtrlHiddenBranch PROC
    DB 75h, 01h                 ; jnz to one byte inside the prospective patch
    DB 12 DUP (90h)
    ret
CtrlHiddenBranch ENDP
CtrlMixedJump PROC
    DB 0FFh, 24h, 8Dh          ; jmp [ecx*4+absolute table]
    DD CtrlSwitchCase
    jmp edx
    DB 12 DUP (90h)
CtrlSwitchDest:
    ret
CtrlMixedJump ENDP
.const
CtrlSwitchCase LABEL DWORD
    DD CtrlSwitchDest, 0

END
