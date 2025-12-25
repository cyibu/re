#include <stdio.h>
#include <Windows.h>
#include <tlhelp32.h>

void patch(HANDLE hProc, void* address) {
	unsigned char nopPatch[] = {0x90, 0x90};
	DWORD oldProtected;

	if (VirtualProtectEx(hProc, address, sizeof(nopPatch), PAGE_EXECUTE_READWRITE, &oldProtected)) {
		SIZE_T bytesWritten;
		if (WriteProcessMemory(hProc, address, nopPatch, sizeof(nopPatch), &bytesWritten)) {
			printf("[!] Patch done! Now you are immortal.\n");
			exit(0);
		}
		else {
			printf("[!] Patch failed. %lu\n",GetLastError());
		}

		VirtualProtectEx(hProc, address, sizeof(nopPatch), oldProtected, &oldProtected);
	
	}
	else {
		printf("[!] Fail to change mem attributes: %lu\n");
	}
}

void ScanProc(HANDLE hProc, unsigned char* pattern, size_t patternSize) {
	MEMORY_BASIC_INFORMATION mbi;
	unsigned char* addr = NULL;

	while (VirtualQueryEx(hProc, addr, &mbi, sizeof(mbi))) {
		if (mbi.State == MEM_COMMIT && mbi.Protect != PAGE_NOACCESS && !(mbi.Protect & PAGE_GUARD)) {
			unsigned char* buffer = malloc(mbi.RegionSize);
			SIZE_T bytesRead;
			if (ReadProcessMemory(hProc, mbi.BaseAddress, buffer, mbi.RegionSize, &bytesRead)) {
				for (size_t i = 0; i <= bytesRead - patternSize; i++) {
					if (memcmp(buffer + i, pattern, patternSize) == 0) {
						void* foundAddr = (unsigned char*)mbi.BaseAddress + i;
						printf("[*] Pattern found at : 0x%p\n", foundAddr );
						printf("[*] Patching ..\n");
						patch(hProc, foundAddr);
					}
				}
			}
			free(buffer);
		}
		addr += mbi.RegionSize;
	}
}

int main(void) {
	unsigned char pattern[] = { 0xFF, 0xC8, 0x89, 0x86, 0xB4, 0x00, 0x00, 0x00, 0x48, 0x8B };
	size_t patternSize = sizeof(pattern);
	const char* target = "Cuphead";


	while (TRUE) {
		DWORD pid;
		HWND hwnd = FindWindowA(NULL, target);
		if (hwnd != NULL) {
			GetWindowThreadProcessId(hwnd, &pid);
		} else {
			printf("Waiting for %s process...\n",target);
			Sleep(5000);
			continue;
		}
		if (pid != 0) {
			printf("[*] Found %s pid : %lu\n", target, pid);
			HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION, FALSE, pid);
			if (hProcess == NULL) {
				printf("Failed to open proc, error %lu\n", GetLastError());
				return 1;
			}
			printf("[*] Scanning pid: %lu\n", pid);
			ScanProc(hProcess, pattern, patternSize);
		}
		else {
			printf("[!] %s process not found, run it first.", target);
		}
	}

	return 0;
}