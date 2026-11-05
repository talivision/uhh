; uhh_orig_thunk -- inline call_original on x64 (see agent.cpp, "An exception (or longjmp)
; inside the original").
;   uint64_t uhh_orig_thunk(uint64_t fn, const uint64_t *args, OrigFrame *frame)
; Calls fn(args[0..3] in RCX/RDX/R8/R9, args[4..35] as its stack arguments 5..36) with XMM0-5
; loaded from frame->xmm0 (the hit's float/vector arguments; skipped when null), returns its
; RAX and stores its XMM0 in frame->xmm0_out. Its UNWIND DATA does not describe this frame's
; real caller: it declares a machine frame (RIP/RSP = the hit's return address and the
; caller's SP after it) plus the hit's nonvolatile registers, all copied into this frame
; before the call. An exception or longjmp unwinding out of the original therefore steps
; from here directly to the hooked function's caller -- exactly where it would have gone
; without the probe -- and never into the callback/agent/stub frames above us, which have
; no usable unwind data. A normal return just returns.
;
; Frame (rsp after the prologue):
;   000..01F home space for fn    020..11F fn's stack args 5..36
;   120..147 machine frame (RIP, CS, EFLAGS, RSP, SS)   148 HitScope* (read by uhh_orig_unwind)
;   150..18F rbx rbp rsi rdi r12 r13 r14 r15 (the hit's)   190..22F xmm6..xmm15 (the hit's)
;   230 the OrigFrame pointer (for the result after the call)
; The declared prologue is: [machine frame] ; sub rsp, 120h ; save regs. Unwinding applies the
; saves (relative to this rsp), then rsp += 120h, then pops the machine frame -- the real
; allocation (238h) is larger so the fake frame never overlaps our own return address.

EXTERN uhh_orig_unwind:PROC

.code
uhh_orig_thunk PROC FRAME:uhh_orig_unwind
    .pushframe
    sub rsp, 238h
    .allocstack 120h
    .savereg rbx, 150h
    .savereg rbp, 158h
    .savereg rsi, 160h
    .savereg rdi, 168h
    .savereg r12, 170h
    .savereg r13, 178h
    .savereg r14, 180h
    .savereg r15, 188h
    .savexmm128 xmm6, 190h
    .savexmm128 xmm7, 1A0h
    .savexmm128 xmm8, 1B0h
    .savexmm128 xmm9, 1C0h
    .savexmm128 xmm10, 1D0h
    .savexmm128 xmm11, 1E0h
    .savexmm128 xmm12, 1F0h
    .savexmm128 xmm13, 200h
    .savexmm128 xmm14, 210h
    .savexmm128 xmm15, 220h
    .endprolog
    mov [rsp+230h], r8                  ; OrigFrame*
    mov rax, [r8]                       ; machine frame
    mov [rsp+120h], rax
    mov qword ptr [rsp+128h], 33h
    mov qword ptr [rsp+130h], 202h
    mov rax, [r8+8]
    mov [rsp+138h], rax
    mov qword ptr [rsp+140h], 2Bh
    mov rax, [r8+50h]                   ; HitScope*
    mov [rsp+148h], rax
    mov rax, [r8+10h]                   ; nonvolatile GPRs
    mov [rsp+150h], rax
    mov rax, [r8+18h]
    mov [rsp+158h], rax
    mov rax, [r8+20h]
    mov [rsp+160h], rax
    mov rax, [r8+28h]
    mov [rsp+168h], rax
    mov rax, [r8+30h]
    mov [rsp+170h], rax
    mov rax, [r8+38h]
    mov [rsp+178h], rax
    mov rax, [r8+40h]
    mov [rsp+180h], rax
    mov rax, [r8+48h]
    mov [rsp+188h], rax
    mov r11, [r8+58h]                   ; XMM6..15 image (may be null: keep ours)
    test r11, r11
    jz no_xmm
    movups xmm0, [r11]
    movaps [rsp+190h], xmm0
    movups xmm0, [r11+10h]
    movaps [rsp+1A0h], xmm0
    movups xmm0, [r11+20h]
    movaps [rsp+1B0h], xmm0
    movups xmm0, [r11+30h]
    movaps [rsp+1C0h], xmm0
    movups xmm0, [r11+40h]
    movaps [rsp+1D0h], xmm0
    movups xmm0, [r11+50h]
    movaps [rsp+1E0h], xmm0
    movups xmm0, [r11+60h]
    movaps [rsp+1F0h], xmm0
    movups xmm0, [r11+70h]
    movaps [rsp+200h], xmm0
    movups xmm0, [r11+80h]
    movaps [rsp+210h], xmm0
    movups xmm0, [r11+90h]
    movaps [rsp+220h], xmm0
    jmp have_xmm
no_xmm:
    movaps [rsp+190h], xmm6
    movaps [rsp+1A0h], xmm7
    movaps [rsp+1B0h], xmm8
    movaps [rsp+1C0h], xmm9
    movaps [rsp+1D0h], xmm10
    movaps [rsp+1E0h], xmm11
    movaps [rsp+1F0h], xmm12
    movaps [rsp+200h], xmm13
    movaps [rsp+210h], xmm14
    movaps [rsp+220h], xmm15
have_xmm:
    xor eax, eax                        ; stack args 5..36
copy_args:
    mov r11, [rdx+20h+rax*8]
    mov [rsp+20h+rax*8], r11
    inc eax
    cmp eax, 32
    jb copy_args
    mov r11, [r8+60h]                   ; the hit's XMM0..5 (float/vector arguments)
    test r11, r11
    jz no_args_xmm
    movups xmm0, [r11]
    movups xmm1, [r11+10h]
    movups xmm2, [r11+20h]
    movups xmm3, [r11+30h]
    movups xmm4, [r11+40h]
    movups xmm5, [r11+50h]
no_args_xmm:
    mov rax, rcx
    mov r10, rdx
    mov rcx, [r10]
    mov rdx, [r10+8]
    mov r8, [r10+10h]
    mov r9, [r10+18h]
    call rax
    nop                                 ; the return address must not look like an epilogue
    mov r10, [rsp+230h]
    movups [r10+68h], xmm0              ; frame->xmm0_out: a float/double result
    add rsp, 238h
    ret
uhh_orig_thunk ENDP
END
