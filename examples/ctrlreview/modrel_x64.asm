OPTION CASEMAP:NONE
PUBLIC ModSys, ModSysInsn
.code
ModSys PROC
    mov eax, ecx
ModSysInsn::
    syscall
ModSysBack::
    lea rdx, ModSysBack
    sub rcx, rdx
    mov rax, rcx
    ret
    DB 16 DUP (90h)
ModSys ENDP
END
