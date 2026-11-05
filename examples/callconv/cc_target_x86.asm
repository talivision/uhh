; cc_target.exe, x86.
;   CcImpThunk   an import thunk exactly as the linker emits one: FF 25 [abs32 IAT slot], here
;                the slot is g_pfn_std3t (filled from GetProcAddress), followed by the next thunk.
;   cc_invoke    calls fn with n stack slots, ECX/EDX and XMM0-5 loaded, sentinels in every
;                callee-saved register, and reports what the CALLER sees afterwards: EAX/EDX,
;                the bytes the callee popped (ESP after - ESP before the call), whether
;                EBX/ESI/EDI/EBP survived, ST0 if the x87 stack is not empty, and XMM0.
;   void cc_invoke(void *fn, const uint32_t *slots, int n, uint32_t ecx, uint32_t edx,
;                  const void *xmm0_5 /* 6 x 16 bytes */, cc_out *out)
;   cc_out: +0 eax, +4 edx, +8 popped, +12 nv_ok, +16 st0 (double), +24 has_st0, +28 pad, +32 xmm0[16]
.686
.xmm
.model flat, C
OPTION CASEMAP:NONE

EXTERN g_pfn_std3t:DWORD, g_pfn_jmp:DWORD
PUBLIC CcImpThunk, CcImpNext, cc_invoke

.data
g_fn      dd 0
g_ecx     dd 0
g_edx     dd 0
g_out     dd 0
g_save    dd 0
g_pre     dd 0
g_post    dd 0

.code
    ALIGN 16
CcImpThunk PROC
    jmp dword ptr [g_pfn_std3t]
CcImpThunk ENDP
CcImpNext PROC
    jmp dword ptr [g_pfn_jmp]
CcImpNext ENDP

    ALIGN 16
cc_invoke PROC
    push ebp
    push ebx
    push esi
    push edi
    mov eax, [esp+20]
    mov g_fn, eax
    mov eax, [esp+32]
    mov g_ecx, eax
    mov eax, [esp+36]
    mov g_edx, eax
    mov eax, [esp+44]
    mov g_out, eax
    mov eax, [esp+40]
    movups xmm0, [eax]
    movups xmm1, [eax+16]
    movups xmm2, [eax+32]
    movups xmm3, [eax+48]
    movups xmm4, [eax+64]
    movups xmm5, [eax+80]
    mov esi, [esp+24]
    mov ecx, [esp+28]
    mov g_save, esp
push_loop:
    test ecx, ecx
    jz do_call
    dec ecx
    push dword ptr [esi+ecx*4]
    jmp push_loop
do_call:
    mov g_pre, esp
    mov ecx, g_ecx
    mov edx, g_edx
    mov ebx, 0B0B0B0B0h
    mov esi, 51515151h
    mov edi, 0D1D1D1D1h
    mov ebp, 0EBEBEBEBh
    call dword ptr [g_fn]
    mov g_post, esp
    mov esp, g_save
    push eax
    mov eax, g_out
    pop dword ptr [eax]
    mov [eax+4], edx
    mov edx, g_post
    sub edx, g_pre
    mov [eax+8], edx
    xor edx, edx
    cmp ebx, 0B0B0B0B0h
    jne nv_done
    cmp esi, 51515151h
    jne nv_done
    cmp edi, 0D1D1D1D1h
    jne nv_done
    cmp ebp, 0EBEBEBEBh
    jne nv_done
    mov edx, 1
nv_done:
    mov [eax+12], edx
    movups [eax+32], xmm0
    mov ecx, eax
    mov dword ptr [ecx+24], 0
    fxam
    fnstsw ax
    and ax, 4500h
    cmp ax, 4100h                       ; C3=1, C0=1: ST0 empty
    je no_st0
    fstp qword ptr [ecx+16]
    mov dword ptr [ecx+24], 1
no_st0:
    pop edi
    pop esi
    pop ebx
    pop ebp
    ret
cc_invoke ENDP
END
