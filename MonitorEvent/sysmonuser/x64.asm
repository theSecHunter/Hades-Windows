.code
    start:

Pushad  PROC
  push        rsp
  push        rax
  push        rcx
  push        rdx
  push        rbx
  push        rbp
  push        rsi
  push        rdi
  push        r8
  push        r9
  push        r10
  push        r11
  push        r12
  push        r13
  push        r14
  push        r15
  pushfq
  ret
Pushad  ENDP

Popad PROC
   pop         r8
   pop         r9
   pop         r10
   pop         r11
   pop         r12
   pop         r13
   pop         r14
   pop         r15
   pop         rdi
   pop         rsi
   pop         rbp
   pop         rbx
   pop         rdx
   pop         rcx
   pop         rax
   popfq      
   pop         rsp
   ret
Popad ENDP

GetCpuid PROC deax:DWORD, debx:DWORD, decx:DWORD, dedx:DWORD, cProStr:DWORD
    call Pushad

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

    call Popad
    ret
GetCpuid ENDP

end