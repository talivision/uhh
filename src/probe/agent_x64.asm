; uhh_orig_thunk -- inline call_original on x64 (see agent.cpp, "An exception (or longjmp)
; inside the original").
;   uint64_t uhh_orig_thunk(uint64_t fn, const uint64_t *args16, const OrigFrame *frame)
; Calls fn(args16[0..15]) and returns its RAX. Its UNWIND DATA does not describe this frame's
; real caller: it declares a machine frame (RIP/RSP = the hit's return address and the
; caller's SP after it) plus the hit's nonvolatile registers, all copied into this frame
; before the call. An exception or longjmp unwinding out of the original therefore steps
; from here directly to the hooked function's caller -- exactly where it would have gone
; without the probe -- and never into the callback/agent/stub frames above us, which have
; no usable unwind data. A normal return just returns.
;
; Frame (rsp after the prologue):
;   00..1F home space for fn      20..7F fn's stack args 5..16
;   80..A7 machine frame (RIP, CS, EFLAGS, RSP, SS)   A8 HitScope* (read by uhh_orig_unwind)
;   B0..EF rbx rbp rsi rdi r12 r13 r14 r15 (the hit's)   F0..18F xmm6..xmm15 (the hit's)
; The declared prologue is: [machine frame] ; sub rsp, 80h ; save regs. Unwinding applies the
; saves (relative to this rsp), then rsp += 80h, then pops the machine frame -- the real
; allocation (198h) is larger so the fake frame never overlaps our own return address.

EXTERN uhh_orig_unwind:PROC

.code
uhh_orig_thunk PROC FRAME:uhh_orig_unwind
    .pushframe
    sub rsp, 198h
    .allocstack 80h
    .savereg rbx, 0B0h
    .savereg rbp, 0B8h
    .savereg rsi, 0C0h
    .savereg rdi, 0C8h
    .savereg r12, 0D0h
    .savereg r13, 0D8h
    .savereg r14, 0E0h
    .savereg r15, 0E8h
    .savexmm128 xmm6, 0F0h
    .savexmm128 xmm7, 100h
    .savexmm128 xmm8, 110h
    .savexmm128 xmm9, 120h
    .savexmm128 xmm10, 130h
    .savexmm128 xmm11, 140h
    .savexmm128 xmm12, 150h
    .savexmm128 xmm13, 160h
    .savexmm128 xmm14, 170h
    .savexmm128 xmm15, 180h
    .endprolog
    mov rax, [r8]                       ; machine frame
    mov [rsp+80h], rax
    mov qword ptr [rsp+88h], 33h
    mov qword ptr [rsp+90h], 202h
    mov rax, [r8+8]
    mov [rsp+98h], rax
    mov qword ptr [rsp+0A0h], 2Bh
    mov rax, [r8+50h]                   ; HitScope*
    mov [rsp+0A8h], rax
    mov rax, [r8+10h]                   ; nonvolatile GPRs
    mov [rsp+0B0h], rax
    mov rax, [r8+18h]
    mov [rsp+0B8h], rax
    mov rax, [r8+20h]
    mov [rsp+0C0h], rax
    mov rax, [r8+28h]
    mov [rsp+0C8h], rax
    mov rax, [r8+30h]
    mov [rsp+0D0h], rax
    mov rax, [r8+38h]
    mov [rsp+0D8h], rax
    mov rax, [r8+40h]
    mov [rsp+0E0h], rax
    mov rax, [r8+48h]
    mov [rsp+0E8h], rax
    mov r11, [r8+58h]                   ; XMM6..15 image (may be null: keep ours)
    test r11, r11
    jz no_xmm
    movups xmm0, [r11]
    movaps [rsp+0F0h], xmm0
    movups xmm0, [r11+10h]
    movaps [rsp+100h], xmm0
    movups xmm0, [r11+20h]
    movaps [rsp+110h], xmm0
    movups xmm0, [r11+30h]
    movaps [rsp+120h], xmm0
    movups xmm0, [r11+40h]
    movaps [rsp+130h], xmm0
    movups xmm0, [r11+50h]
    movaps [rsp+140h], xmm0
    movups xmm0, [r11+60h]
    movaps [rsp+150h], xmm0
    movups xmm0, [r11+70h]
    movaps [rsp+160h], xmm0
    movups xmm0, [r11+80h]
    movaps [rsp+170h], xmm0
    movups xmm0, [r11+90h]
    movaps [rsp+180h], xmm0
    jmp have_xmm
no_xmm:
    movaps [rsp+0F0h], xmm6
    movaps [rsp+100h], xmm7
    movaps [rsp+110h], xmm8
    movaps [rsp+120h], xmm9
    movaps [rsp+130h], xmm10
    movaps [rsp+140h], xmm11
    movaps [rsp+150h], xmm12
    movaps [rsp+160h], xmm13
    movaps [rsp+170h], xmm14
    movaps [rsp+180h], xmm15
have_xmm:
    mov r10, rdx                        ; args 5..16 on the stack
    mov rax, [r10+20h]
    mov [rsp+20h], rax
    mov rax, [r10+28h]
    mov [rsp+28h], rax
    mov rax, [r10+30h]
    mov [rsp+30h], rax
    mov rax, [r10+38h]
    mov [rsp+38h], rax
    mov rax, [r10+40h]
    mov [rsp+40h], rax
    mov rax, [r10+48h]
    mov [rsp+48h], rax
    mov rax, [r10+50h]
    mov [rsp+50h], rax
    mov rax, [r10+58h]
    mov [rsp+58h], rax
    mov rax, [r10+60h]
    mov [rsp+60h], rax
    mov rax, [r10+68h]
    mov [rsp+68h], rax
    mov rax, [r10+70h]
    mov [rsp+70h], rax
    mov rax, [r10+78h]
    mov [rsp+78h], rax
    mov rax, rcx
    mov rcx, [r10]
    mov rdx, [r10+8]
    mov r8, [r10+10h]
    mov r9, [r10+18h]
    call rax
    nop                                 ; the return address must not look like an epilogue
    add rsp, 198h
    ret
uhh_orig_thunk ENDP
END
