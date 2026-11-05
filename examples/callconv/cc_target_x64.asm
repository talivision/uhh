; cc_target.exe, x64: an import thunk as the linker emits one (FF 25 [rip+IAT slot]); the
; slot is g_pfn_std3t, filled from GetProcAddress. Followed by the next thunk.
EXTERN g_pfn_std3t:QWORD, g_pfn_jmp:QWORD
PUBLIC CcImpThunk, CcImpNext

.code
    ALIGN 16
CcImpThunk PROC
    jmp qword ptr [g_pfn_std3t]
CcImpThunk ENDP
CcImpNext PROC
    jmp qword ptr [g_pfn_jmp]
CcImpNext ENDP
END
