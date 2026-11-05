; x86 twin of edge_sites_x64.asm (cdecl; no RIP-relative, syscall or int 2e shapes:
; a WOW64 process enters the kernel through the wow64 thunks, which are out of scope).
.686
.xmm
.model flat, C
OPTION CASEMAP:NONE

PUBLIC EdgeRepSite, EdgeStosSite, EdgeCpuidSite, EdgeRdtscSite, EdgePushfSite, EdgePopfSite
PUBLIC EdgeRetOnlySite, EdgeThunkSite, EdgeJumpSite, EdgeFaultMidSite, EdgeX87Site, EdgeLockSite
PUBLIC EdgeDualSite

.data
ALIGN 16
EdgeLockVal  DD 5
EdgeThunkPtr DD EdgeCallee
EdgeTable    DD EdgeCase0, EdgeCase1, EdgeCase2
EdgeOneHalf  DT 3FFFC000000000000000r

.code
EdgeRep PROC dst:DWORD, src:DWORD
    push esi
    push edi
    mov edi, dst
    mov esi, src
    mov ecx, 100
EdgeRepSite::
    rep movsb
    mov eax, ecx
    nop
    nop
    pop edi
    pop esi
    ret
EdgeRep ENDP

EdgeStos PROC dst:DWORD
    push edi
    mov edi, dst
    mov eax, 3Ch
    mov ecx, 64
EdgeStosSite::
    rep stosb
    mov eax, ecx
    nop
    nop
    pop edi
    ret
EdgeStos ENDP

EdgeCpuid PROC
    push ebx
    xor eax, eax
    xor ecx, ecx
EdgeCpuidSite::
    cpuid
    mov eax, ebx
    nop
    pop ebx
    ret
EdgeCpuid ENDP

EdgeRdtsc PROC
EdgeRdtscSite::
    rdtsc
    or eax, 1
    nop
    nop
    ret
EdgeRdtsc ENDP

EdgePushf PROC
EdgePushfSite::
    pushfd
    pop eax
    nop
    nop
    nop
    ret
EdgePushf ENDP

EdgePopf PROC flags:DWORD
    push flags
EdgePopfSite::
    popfd
    pushfd
    pop eax
    nop
    nop
    push 202h
    popfd
    ret
EdgePopf ENDP

EdgeRetOnly PROC
EdgeRetOnlySite::
    ret
EdgeRetOnly ENDP

EdgeCallee PROC
    mov eax, 42
    ret
EdgeCallee ENDP

EdgeThunk PROC
EdgeThunkSite::
    call dword ptr [EdgeThunkPtr]
    nop
    ret
EdgeThunk ENDP

EdgeJump PROC idx:DWORD
    mov eax, idx
EdgeJumpSite::
    jmp dword ptr [EdgeTable+eax*4]
EdgeCase0::
    mov eax, 100
    ret
EdgeCase1::
    mov eax, 101
    ret
EdgeCase2::
    mov eax, 102
    ret
EdgeJump ENDP

EdgeFaultMid PROC p:DWORD
    push ebx
    mov ecx, p
    xor eax, eax
EdgeFaultMidSite::
    mov eax, dword ptr [ecx]
    nop
    nop
    nop
    nop
    pop ebx
    ret
EdgeFaultMid ENDP

EdgeX87 PROC n:DWORD
    sub esp, 8
EdgeX87Site::
    fld tbyte ptr [EdgeOneHalf]
    fimul n
    fistp dword ptr [esp]
    mov eax, dword ptr [esp]
    add esp, 8
    ret
EdgeX87 ENDP

EdgeLock PROC v:DWORD
    mov ecx, v
    mov eax, 5
EdgeLockSite::
    lock cmpxchg dword ptr [EdgeLockVal], ecx
    nop
    mov dword ptr [EdgeLockVal], 5
    ret
EdgeLock ENDP

EdgeDual PROC
    xor eax, eax
EdgeDualSite::
    inc eax
    inc eax
    inc eax
    inc eax
    inc eax
    inc eax
    ret
EdgeDual ENDP

EdgeReaddA PROC
    mov eax, 1
    nop
    nop
    nop
    nop
    nop
    ret
EdgeReaddA ENDP

EdgeReaddB PROC
    mov eax, 2
    nop
    nop
    nop
    nop
    nop
    ret
EdgeReaddB ENDP

EdgeCodePad PROC
    int 3
    int 3
    int 3
    int 3
    int 3
    int 3
    int 3
    int 3
EdgeCodePad ENDP
END
