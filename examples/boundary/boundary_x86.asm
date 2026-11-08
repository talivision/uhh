; x86 twin of boundary_x64.asm (cdecl). Assembled with /Zi: BndFrame gets a PDB extent.
.686
.model flat, C
OPTION CASEMAP:NONE
PUBLIC BndFrame, BndLeaf, BndHidden, BndHiddenReal

.data
BndSink DD 0

.code
BndFrame PROC
    push ebx                        ; +0x0  53
    mov ebx, dword ptr [esp+8]      ; +0x1  8B 5C 24 08
    test ebx, ebx                   ; +0x5  (2)
    jnz short BndFrameBody          ; +0x7  (2)
    xor eax, eax                    ; +0x9  (2)
    pop ebx                         ; +0xB
    ret                             ; +0xC
BndFrameBody:
    imul eax, ebx, 12345678h        ; +0xD  69 C3 78 56 34 12
    add eax, 9ABCDEF0h              ; +0x13 05 F0 DE BC 9A
    pop ebx                         ; +0x18
    ret                             ; +0x19
BndFrame ENDP

ALIGN 16
BndLeaf:
    mov dword ptr [BndSink], 11223344h   ; +0x0  C7 05 addr32 imm32 (10)
    mov eax, dword ptr [BndSink]         ; +0xA  A1 addr32 (5)
    ret                                  ; +0xF

ALIGN 16
BndHidden:
    mov eax, 1                      ; +0x0
    ret                             ; +0x5
    DB 0B8h                         ; +0x6
BndHiddenReal:
    mov eax, 7                      ; +0x7
    ret                             ; +0xC
END
