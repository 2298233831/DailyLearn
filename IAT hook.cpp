#include <iostream>
#include <Windows.h>


int YourMessage(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
int hookiat();

int main()
{
	MessageBoxA(NULL, "Hello World", "hhh", 0);
	hookiat();
	MessageBoxA(NULL, "Hello World", "hhh", 0);
	return 0;
}


int YourMessage(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
	MessageBoxW(NULL, L"Hello IAT Hook", L"The IAT Have been hooked", 0);
	return 0;
}

int hookiat()
{
	PVOID imageBase = GetModuleHandleA(NULL);
	PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)imageBase;
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)imageBase + dosHeaders->e_lfanew);
	IMAGE_DATA_DIRECTORY importsDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importsDirectory.VirtualAddress + (DWORD_PTR)imageBase);
	LPCSTR DllName = NULL;
	HMODULE library = NULL;
	PIMAGE_IMPORT_BY_NAME func_name = NULL;

	while (importDescriptor->Name != NULL)
	{
		DllName = (LPCSTR)importDescriptor->Name + (DWORD_PTR)imageBase;
		library = LoadLibraryA(DllName);

		if (library)
		{
			PIMAGE_THUNK_DATA PINT = NULL, PIAT = NULL;
			PINT = (PIMAGE_THUNK_DATA)((DWORD_PTR)imageBase + importDescriptor->OriginalFirstThunk);
			PIAT = (PIMAGE_THUNK_DATA)((DWORD_PTR)imageBase + importDescriptor->FirstThunk);

			while (PINT->u1.AddressOfData != NULL)
			{
				func_name = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)imageBase + PINT->u1.AddressOfData);
				if (!strcmp(func_name->Name, "MessageBoxA"))
				{

					DWORD oldProtect = 0;
					VirtualProtect((LPVOID)(&PIAT->u1.Function), 8, PAGE_READWRITE, &oldProtect);
					PIAT->u1.Function = (DWORD_PTR)YourMessage;
					VirtualProtect((LPVOID)(&PIAT->u1.Function), 4, oldProtect, &oldProtect);
				}
				++PINT;
				++PIAT;
			}
		}
		importDescriptor++;
	}
	

	return 0;
}
