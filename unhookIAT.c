#include <winternl.h>
#include <windows.h>
#include <stdio.h>
#include <stdbool.h>
#include <dbghelp.h>
#pragma comment (lib, "dbghelp.lib")

//coded by xalicex
//Twitter : @AliceCliment

void UnhookIAT() {

	ULONG size;
	DWORD i, j, x;
	DWORD oldProtect = 0;
	BOOL found = false;
	int sizetab;
	LPVOID TrueRVA;
	
	unsigned char xKernel32[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0x0 };
	unsigned char xVirtualProtect[] = { 'V','i','r','t','u','a','l','P','r','o','t','e','c','t', 0x0 };
	typedef BOOL (WINAPI * VirtualProtect_t)(LPVOID, SIZE_T, DWORD, PDWORD);
	VirtualProtect_t VirtualProtect_p = (VirtualProtect_t) GetProcAddress(GetModuleHandle((LPCSTR) xKernel32), (LPCSTR) xVirtualProtect);

	// get Base address of the PE
	HANDLE baseAddress = GetModuleHandle(NULL);		
	
	// get Import Table of PE
	PIMAGE_IMPORT_DESCRIPTOR importTbl = (PIMAGE_IMPORT_DESCRIPTOR) ImageDirectoryEntryToDataEx(
												baseAddress,
												TRUE,
												IMAGE_DIRECTORY_ENTRY_IMPORT,
												&size,
												NULL);

	
	int nbelement = (size/20)-1;
	for (i = 0; i < nbelement ; i++){
		
		//Get name of the DLL in the Import Table
		char * importName = (char *)((PBYTE) baseAddress + importTbl[i].Name);
		printf("DLL name in IAT : %s\n",importName);
		
		//Get Import Lookup Table (OriginalFirstThunk) and Import Address Table (FirstThunk)
		PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA) ((PBYTE) baseAddress + importTbl[i].FirstThunk);
		PIMAGE_THUNK_DATA originalFirstThunk = (PIMAGE_THUNK_DATA) ((PBYTE) baseAddress + importTbl[i].OriginalFirstThunk);
		PIMAGE_IMPORT_BY_NAME function = NULL; 
		char* functionName;
		
		//Parse DLL loaded in memory to retrieve various info
		const LPVOID BaseDLLAddr = (LPVOID)GetModuleHandle((LPCSTR)importName);
		PIMAGE_DOS_HEADER pImgDOSHead = (PIMAGE_DOS_HEADER) BaseDLLAddr;
		PIMAGE_NT_HEADERS pImgNTHead = (PIMAGE_NT_HEADERS)((DWORD_PTR) BaseDLLAddr + pImgDOSHead->e_lfanew);
		PIMAGE_EXPORT_DIRECTORY pImgExpDir =(PIMAGE_EXPORT_DIRECTORY)((LPBYTE)BaseDLLAddr+pImgNTHead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
		PDWORD Address=(PDWORD)((LPBYTE)BaseDLLAddr+pImgExpDir->AddressOfFunctions);
		PDWORD Name=(PDWORD)((LPBYTE)BaseDLLAddr+pImgExpDir->AddressOfNames);
		PWORD Ordinal=(PWORD)((LPBYTE)BaseDLLAddr+pImgExpDir->AddressOfNameOrdinals);

		//loop through all function in the lookup table for the current dll
		while (originalFirstThunk->u1.AddressOfData != NULL){
			
			function = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)baseAddress + originalFirstThunk->u1.AddressOfData);
			functionName = function->Name;
			sizetab = 7;
			//Avoid those function or I'll crash
			char* exclude[]= {"EnterCriticalSection","LeaveCriticalSection","DeleteCriticalSection","InitializeSListHead","HeapAlloc","HeapReAlloc","HeapSize"};
			for (x = 0; x < sizetab ; x++){
				if(_stricmp(functionName, exclude[x]) == 0){
					found = true;
				}
			}
			
			if(!found)
			{
				//Get RVA from DLL loaded in memory
				for(j=0;j<pImgExpDir->NumberOfFunctions;j++){
					if(!strcmp(functionName,(char*)BaseDLLAddr+Name[j])){
						TrueRVA = (PVOID)((LPBYTE)Address[Ordinal[j]]);
						break;
					}
				}
		
				//Compute real address
				uintptr_t moduleBase = (uintptr_t)BaseDLLAddr;
				uintptr_t RVA = (uintptr_t)TrueRVA;
				uintptr_t* TrueAddress = (uintptr_t*)(moduleBase + RVA);
				PROC * currentFuncAddr = (PROC *) &thunk->u1.Function;

				if(*currentFuncAddr != (PROC)(TrueAddress)) {
					oldProtect = 0;
					VirtualProtect_p((LPVOID) currentFuncAddr, 8, PAGE_READWRITE, &oldProtect); 
					printf("Bad News ! Function %s is hooked ! Address is %x and it's suppose to be %x \nUnhook like the captain !\n",functionName, *currentFuncAddr, TrueAddress);
					*currentFuncAddr = (PROC)(TrueAddress);
					VirtualProtect_p((LPVOID) currentFuncAddr, 8, oldProtect, &oldProtect);
				}else{
					printf("Good news ! Function %s is not hooked :D\n",functionName);
				}
			}
			++originalFirstThunk;
			++thunk;
			found = false;
		}
	}
}


int main(void) {
   
	UnhookIAT();
	
	return 0;
}
