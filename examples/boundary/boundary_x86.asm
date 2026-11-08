; x86 twin of boundary_x64.asm (cdecl). Assembled with /Zi: BndFrame gets a PDB extent.
.686
.model flat, C
OPTION CASEMAP:NONE
PUBLIC BndFrame, BndLeaf, BndHidden, BndHiddenReal, BndNoret, BndSmc, BndOverlap
EXTERN BndDie:PROC

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

ALIGN 16
BndNoret PROC
    mov eax, 5                      ; +0x0  B8 05 00 00 00
    mov ecx, dword ptr [esp+4]      ; +0x5  8B 4C 24 04
    test ecx, ecx                   ; +0x9  85 C9
    jnz short BndNoretDie           ; +0xB  75 07
    mov edx, OFFSET BndNoretDie + 6 ; +0xD  BA imm32: the ret below (no label on it)
    jmp edx                         ; +0x12 FF E2
BndNoretDie:
    call BndDie                     ; +0x14 E8 rel32 (never returns)
    DB 0B8h                         ; +0x19 data
    ret                             ; +0x1A C3: the real block
    DB 8 DUP (0CCh)                 ; +0x1B
BndNoret ENDP

ALIGN 16
BndSmc PROC
    nop                             ; +0x0
    nop                             ; +0x1
    nop                             ; +0x2
    mov eax, 0                      ; +0x3  B8 imm32 (imm at +0x4)
    ret                             ; +0x8
BndSmc ENDP

; Opaque jump enters MOV's immediate: FF C0 increments EAX; EB 01 skips the outer ret.
ALIGN 16
BndOverlap PROC
    xor eax, eax
    mov edx, OFFSET BndOverlapOuter + 1
    test eax, eax
    jnz short BndOverlapOuter
    jmp edx
BndOverlapOuter:                    ; +0xD: B8 FF C0 EB 01 = mov eax, 01EBC0FFh
    DB 0B8h, 0FFh, 0C0h, 0EBh, 01h
    ret                             ; never executed
    ret                             ; hidden path returns 1
    DB 8 DUP (0CCh)
BndOverlap ENDP
END
