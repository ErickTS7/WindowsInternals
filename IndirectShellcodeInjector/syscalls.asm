.data
    PUBLIC currentSSN
    PUBLIC currentSyscall
    currentSSN      DWORD 0
    currentSyscall  QWORD 0

.code

PUBLIC IndirectSyscall
IndirectSyscall PROC
    mov r10, rcx
    mov eax, currentSSN
    jmp QWORD PTR [currentSyscall]
IndirectSyscall ENDP

END