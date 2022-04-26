.686
.model flat, stdcall

.code
    start:

GetCpuid PROC  deax:DWORD, debx:DWORD, decx:DWORD, dedx:DWORD, cProStr:DWORD
    pushad
    pushfd
    mov eax, 0
    cpuid
    mov edi, [deax]
    mov [edi], eax
    mov edi, [debx]
    mov [edi], ebx
    mov edi, [decx]
    mov [edi], ecx
    mov edi, [dedx]
    mov [edi], edx

    mov eax, 80000002h
    cpuid
    mov edi, [cProStr]
    mov dword ptr [edi], eax
    mov dword ptr [edi + 4], ebx
    mov dword ptr [edi + 8], ecx
    mov dword ptr [edi + 12], edx

    mov eax, 80000003h
    cpuid
    mov edi, [cProStr]
    mov dword ptr [edi + 16], eax
    mov dword ptr [edi + 20], ebx
    mov dword ptr [edi + 24], ecx
    mov dword ptr [edi + 28], edx

    mov eax, 80000004h
    cpuid
    mov edi, [cProStr]
    mov dword ptr [edi + 32], eax
    mov dword ptr [edi + 36], ebx
    mov dword ptr [edi + 40], ecx
    mov dword ptr [edi + 44], edx

    popfd
    popad
    ret
GetCpuid ENDP

end