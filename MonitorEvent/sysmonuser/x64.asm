.code
    start:

GetCpuid PROC
    push rax
    push rbx
    push rcx
    push rdx
    push r11
    push r12

    mov r11, rcx
    mov r12, rdx
    mov eax, 0
    cpuid
    mov [r11], rax
    mov [r12], rbx
    mov [r8], rcx
    mov [r9], rdx

    pop r12
    pop r11
    pop rdx
    pop rcx
    pop rbx
    pop rax

    ret
GetCpuid ENDP

GetCpuInfos PROC
    push rax
    push rbx
    push rcx
    push rdx
    push r11
    push r12

    mov r11, rcx
    mov eax, 80000002h
    cpuid
    mov dword ptr [r11], eax
    mov dword ptr [r11 + 4], ebx
    mov dword ptr [r11 + 8], ecx
    mov dword ptr [r11 + 12], edx

    mov eax, 80000003h
    cpuid
    mov dword ptr [r11 + 16], eax
    mov dword ptr [r11 + 20], ebx
    mov dword ptr [r11 + 24], ecx
    mov dword ptr [r11 + 28], edx

    mov eax, 80000004h
    cpuid
    mov dword ptr [r11 + 32], eax
    mov dword ptr [r11 + 36], ebx
    mov dword ptr [r11 + 40], ecx
    mov dword ptr [r11 + 44], edx

    pop r12
    pop r11
    pop rdx
    pop rcx
    pop rbx
    pop rax

    ret
GetCpuInfos ENDP

end