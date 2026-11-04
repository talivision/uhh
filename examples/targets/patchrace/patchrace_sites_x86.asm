; x86 twin of patchrace_sites_x64.asm (the linker's /EXPORT:RaceSite finds _RaceSite).
.686
.model flat
OPTION CASEMAP:NONE
PUBLIC _RaceSite
.code
_RaceSite PROC
    xor eax, eax
    inc eax
    inc eax
    inc eax
    inc eax
    inc eax
    inc eax
    inc eax
    inc eax
    inc eax
    inc eax
    inc eax
    inc eax
    inc eax
    inc eax
    inc eax
    inc eax
    ret
_RaceSite ENDP

PUBLIC _BranchSite, _PushfSite
_BranchSite PROC
    jmp short branch_next
branch_next:
    pushfd
    pop eax
    ret
_BranchSite ENDP
_PushfSite PROC
    pushfd
    pop eax
    ret
_PushfSite ENDP
END
