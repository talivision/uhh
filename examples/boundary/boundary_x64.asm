; Known instruction layouts for regress `boundary-*` (x64). Offsets are asserted by the check
; (scripts/regress.py check_boundary reads the bytes from the exe): keep them in sync.
OPTION CASEMAP:NONE
PUBLIC BndFrame, BndLeaf, BndHidden, BndHiddenReal, BndNoret, BndSmc, BndOverlap
EXTERN BndDie:PROC

.data
BndSink DD 0

.code
; unsigned BndFrame(unsigned x): 0 -> 0 (early ret); else x*12345678h + 9ABCDEF0h.
BndFrame PROC FRAME
    push rbx                        ; +0x0  53
    .pushreg rbx
    .endprolog
    mov ebx, ecx                    ; +0x1  (2)
    test ecx, ecx                   ; +0x3  (2)
    jnz short BndFrameBody          ; +0x5  (2)
    xor eax, eax                    ; +0x7  (2)
    pop rbx                         ; +0x9
    ret                             ; +0xA
BndFrameBody:
    imul eax, ebx, 12345678h        ; +0xB  69 C3 78 56 34 12  (reached only by the jnz)
    add eax, 9ABCDEF0h              ; +0x11 05 F0 DE BC 9A
    pop rbx                         ; +0x16
    ret                             ; +0x17
BndFrame ENDP

; No PROC: no .pdata, no PDB extent.
ALIGN 16
BndLeaf:
    mov dword ptr [BndSink], 11223344h   ; +0x0  C7 05 disp32 imm32 (10)
    mov eax, dword ptr [BndSink]         ; +0xA  8B 05 disp32 (6)
    ret                                  ; +0x10

ALIGN 16
BndHidden:
    mov eax, 1                      ; +0x0  B8 01 00 00 00
    ret                             ; +0x5
    DB 0B8h                         ; +0x6  data: decodes as `mov eax, imm32` over BndHiddenReal
BndHiddenReal:
    mov eax, 7                      ; +0x7  B8 07 00 00 00
    ret                             ; +0xC

; unsigned BndNoret(unsigned x): 0 -> 5, returned by a block that is ONE `ret`, reached only by an
; indirect jump (+0x18); else BndDie, which never returns. The byte after that call is data (B8):
; decoded through the call's fall-through it is `mov eax, imm32` over the real ret (codex5 #3).
ALIGN 16
BndNoret PROC FRAME
    .endprolog
    mov eax, 5                      ; +0x0  B8 05 00 00 00
    test ecx, ecx                   ; +0x5  85 C9
    jnz short BndNoretDie           ; +0x7  75 09
    lea rdx, BndNoretDie + 6        ; +0x9  48 8D 15 rel32: the ret below (no label on it)
    jmp rdx                         ; +0x10 FF E2
BndNoretDie:
    call BndDie                     ; +0x12 E8 rel32 (never returns)
    DB 0B8h                         ; +0x17 data
    ret                             ; +0x18 C3: the real block
    DB 8 DUP (0CCh)                 ; +0x19
BndNoret ENDP

; unsigned BndSmc(void): returns the imm32 of its own `mov eax, imm32`, which the program
; rewrites (self-modifying code): +0x4 is a dword-aligned DATA address inside an instruction
; (a data watchpoint there is valid: codex5 #2).
ALIGN 16
BndSmc PROC FRAME
    .endprolog
    nop                             ; +0x0
    nop                             ; +0x1
    nop                             ; +0x2
    mov eax, 0                      ; +0x3  B8 imm32 (imm at +0x4)
    ret                             ; +0x8
BndSmc ENDP

; Opaque jump enters MOV's immediate: FF C0 increments EAX; EB 01 skips the outer ret.
ALIGN 16
BndOverlap PROC FRAME
    .endprolog
    xor eax, eax
    lea rdx, BndOverlapOuter + 1
    test eax, eax
    jnz short BndOverlapOuter
    jmp rdx
BndOverlapOuter:                    ; +0xF: B8 FF C0 EB 01 = mov eax, 01EBC0FFh
    DB 0B8h, 0FFh, 0C0h, 0EBh, 01h
    ret                             ; never executed
    ret                             ; hidden path returns 1
    DB 8 DUP (0CCh)
BndOverlap ENDP
END
