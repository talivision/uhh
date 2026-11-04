; RaceSite: xor eax,eax then 16 x inc eax, returns 16. Threads call it in a tight loop,
; so at any moment a thread is likely to be INSIDE the first bytes -- exactly the bytes
; an inline hook overwrites with its jump. Written unfrozen, such a thread resumes in
; the middle of the jump's displacement and returns a wrong count (or crashes); frozen,
; it is moved to the same instruction in the trampoline and returns 16.
; (A test fixture: real code needs no assembly to be hooked.)
OPTION CASEMAP:NONE
PUBLIC RaceSite
.code
RaceSite PROC
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
RaceSite ENDP

; BranchSite starts with a jmp, PushfSite with pushfq: under PROBE_BREAKPOINT neither can
; run out-of-line, so UHH emulates them (INT3 stays armed, no trap flag). Both return
; the flags image the code itself observed in eax/rax, so the target can check that no
; TF leaked into it.
PUBLIC BranchSite, PushfSite
BranchSite PROC
    jmp short branch_next
branch_next:
    pushfq
    pop rax
    ret
BranchSite ENDP
PushfSite PROC
    pushfq
    pop rax
    ret
PushfSite ENDP
END
