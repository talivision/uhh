; Known instruction layouts for regress `boundary-*` (x64). Offsets are asserted by the check
; (scripts/regress.py check_boundary reads the bytes from the exe): keep them in sync.
OPTION CASEMAP:NONE
PUBLIC BndFrame, BndLeaf, BndHidden, BndHiddenReal

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
END
