# IndirectShellcodeInjector

Injeção de shellcode em processo remoto usando **Indirect Syscalls** com resolução dinâmica de SSNs, bypassando hooks de EDRs na kernel32 e ntdll.

## Técnicas utilizadas

**Structs NT definidas manualmente** — Structs internas do Windows definidas no código para chamar as Nt functions diretamente, sem depender de headers do DDK/WDK.

**SSN Resolver com HalosGate** — Resolve SSN de cada Nt function em runtime. Se a função estiver hookada, busca o SSN a partir de funções próximas (acima/abaixo) calculando o offset.

**Assembly stub (MASM)** — Stub em .asm que carrega o SSN em `eax`, move `rcx` para `r10` e faz `jmp` para o endereço real da `syscall` na ntdll.

**Shellcode** - Injetado por padrão no processo do Notepad e executa calc.exe. Gerado com: `msfvenom -p windows/x64/exec CMD=calc.exe -f c`  

## Fluxo

1. Resolve ponteiros das Nt functions
2. Extrai SSNs com fallback HalosGate
3. Localiza o endereço da instrução `syscall` na ntdll
4. Encontra o PID do processo do Notepad
5. Executa a cadeia de injeção do shellcode via indirect syscalls das funções ntdll.dll!NtOpenProcess, NtAllocateVirtualMemory, NtWriteVirtualMemory e NtCreateThreadEx

## Build

Visual Studio com suporte a MASM (.asm) habilitado. Compilar como x64 Release.

> **Projeto apenas para fins educacionais e de estudo em Windows Internals.**
