; x86 probe sites for the stacks example. Every function carries an .FPO record so the
; controller's dbghelp walk (PDB FPO data) unwinds it; the agent's walker has no PDB.
; cdecl: int Stk*(int a). Sites are global labels (::) so the map gives their RVAs.
.686
.model flat
OPTION CASEMAP:NONE
PUBLIC _StkMid, _StkMidSite, _StkFpo, _StkFpoSite, _StkLeaf, _StkLeafSite
.code

; EBP frame, 2 locals, saves ESI; probe mid-function (EBP frames THIS function).
_StkMid PROC
    push ebp
    mov ebp, esp
    sub esp, 8
    push esi
    .FPO (2, 1, 7, 1, 1, 0)
    mov esi, [ebp+8]
    mov dword ptr [ebp-4], 0
_StkMidSite::
    mov eax, 1000h
    add eax, esi
    nop
    nop
    pop esi
    mov esp, ebp
    pop ebp
    ret
_StkMid ENDP

; Frame pointer omitted: EBP is saved first and then holds DATA (not a frame) at the site.
; 4 locals, saves EBP and ESI.
_StkFpo PROC
    push ebp
    push esi
    sub esp, 10h
    .FPO (4, 1, 5, 2, 0, 0)
    mov esi, [esp+1Ch]
    mov ebp, 0BAD0F00Dh
    mov dword ptr [esp], esi
    mov dword ptr [esp+4], 0
    mov dword ptr [esp+8], 0
    mov dword ptr [esp+0Ch], 0
_StkFpoSite::
    mov eax, 2000h
    add eax, esi
    nop
    nop
    add esp, 10h
    pop esi
    pop ebp
    ret
_StkFpo ENDP

; Leaf: no frame, no stack adjustment; probe after the first instruction ([esp] = return).
_StkLeaf PROC
    .FPO (0, 1, 0, 0, 0, 0)
    mov eax, [esp+4]
_StkLeafSite::
    add eax, 3000h
    nop
    nop
    ret
_StkLeaf ENDP
END
