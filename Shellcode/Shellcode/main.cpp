#include <windows.h>

FARPROC  getProcAddress(HMODULE hModuleBase);
DWORD getKernel32();

int EntryMain()
{
    // get function address ：GetProcAddress
    typedef FARPROC(WINAPI* FN_GetProcAddress)(
        _In_ HMODULE hModule,
        _In_ LPCSTR lpProcName
        );
    FN_GetProcAddress fn_GetProcAddress = (FN_GetProcAddress)getProcAddress((HMODULE)getKernel32());

    // get function address ：LoadLibraryW
    typedef HMODULE(WINAPI* FN_LoadLibraryW)(
        _In_ LPCWSTR lpLibFileName
        );
    char xyLoadLibraryW[] = { 'L','o','a','d','L','i','b','r','a','r','y','W',0 };
    FN_LoadLibraryW fn_LoadLibraryW = (FN_LoadLibraryW)fn_GetProcAddress((HMODULE)getKernel32(), xyLoadLibraryW);

    // get function address ：MessageBoxA
    typedef int (WINAPI* FN_MessageBoxA)(
        _In_opt_ HWND hWnd,
        _In_opt_ LPCWSTR lpText,
        _In_opt_ LPCWSTR lpCaption,
        _In_ UINT uType);
    wchar_t xy_user32[] = { 'u','s','e','r','3','2','.','d','l','l',0 };
    char xy_MessageBoxA[] = { 'M','e','s','s','a','g','e','B','o','x','A',0 };
    FN_MessageBoxA fn_MessageBoxA = (FN_MessageBoxA)fn_GetProcAddress(fn_LoadLibraryW(xy_user32), xy_MessageBoxA);

    // get function address: VirtualProtect
    typedef BOOL(WINAPI* FN_VirtualProtect)(
		_In_ LPVOID lpAddress,
		_In_ SIZE_T dwSize,
		_In_ DWORD  flNewProtect,
		_Out_ PDWORD lpflOldProtect
		);
    char xyVirtualProtect[] = { 'V','i','r','t','u','a','l','P','r','o','t','e','c','t',0 };
    FN_VirtualProtect fn_VirtualProtect = (FN_VirtualProtect)fn_GetProcAddress((HMODULE)getKernel32(), xyVirtualProtect);

    // get function address: MessageBoxW
    typedef int (WINAPI* FN_MessageBoxW)(
		_In_opt_ HWND hWnd,
		_In_opt_ LPCWSTR lpText,
		_In_opt_ LPCWSTR lpCaption,
		_In_ UINT uType);
    char xy_MessageBoxW[] = { 'M','e','s','s','a','g','e','B','o','x','W',0 };
    FN_MessageBoxW fn_MessageBoxW = (FN_MessageBoxW)fn_GetProcAddress(fn_LoadLibraryW(xy_user32), xy_MessageBoxW);

    // get function address: strcmp
    typedef int (WINAPI* FN_strcmp)(CHAR* str1, CHAR* str2);
    char xy_strcmp[] = { 's','t','r','c','m','p',0 };
    wchar_t xy_msvcrt[] = { 'm','s','v','c','r','t','.','d','l','l',0 };
    FN_strcmp fn_strcmp = (FN_strcmp)fn_GetProcAddress(fn_LoadLibraryW(xy_msvcrt), xy_strcmp);


    // get function address: GetModuleHandle
    typedef HMODULE(WINAPI* FN_GetModuleHandle)(LPCSTR lpModuleName);
    wchar_t xy_kernel32[] = { 'k','e','r','n','e','l','3','2','.','d','l','l',0 };
    char xy_GetModuleHandle[] = { 'G','e','t','M','o','d','u','l','e','H','a','n','d','l','e','A',0 };
    FN_GetModuleHandle fn_GetModuleHandle = (FN_GetModuleHandle)fn_GetProcAddress(fn_LoadLibraryW(xy_kernel32), xy_GetModuleHandle);


    // shellcode start
    // replace MessageBoxW to MessageBoxA

    HANDLE module = fn_GetModuleHandle(NULL);
    FARPROC newFunc = (FARPROC)fn_MessageBoxA;
    // MessageBoxA(0, "This is the original function!", "Title", MB_OK);

    char targetFuncName[] = { 'G','e','t','P','a','r','e','n','t',0 };
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)module;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)module + dosHeader->e_lfanew);

    if (ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress == 0)
    {
        // printf("No import table found.\n");
        return 0;
    }

    PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)module + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    while (importDescriptor->Name)
    {
        PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((BYTE*)module + importDescriptor->OriginalFirstThunk);
        PIMAGE_THUNK_DATA thunkIAT = (PIMAGE_THUNK_DATA)((BYTE*)module + importDescriptor->FirstThunk);

        while (thunk->u1.AddressOfData)
        {
            PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)module + thunk->u1.AddressOfData);

            if (fn_strcmp(importByName->Name, targetFuncName) == 0)
            {
                DWORD oldProtect;
                fn_VirtualProtect(&thunkIAT->u1.Function, sizeof(FARPROC), PAGE_READWRITE, &oldProtect);
                thunkIAT->u1.Function = (ULONG_PTR)newFunc;
                fn_VirtualProtect(&thunkIAT->u1.Function, sizeof(FARPROC), oldProtect, &oldProtect);
                goto done;
            }

            thunk++;
            thunkIAT++;
        }

        importDescriptor++;
    }


done:
    return 0;
}

// get module base ：kernel32.dll
__declspec(naked) DWORD getKernel32()
{
    __asm
    {
        mov eax, fs: [30h]
        mov eax, [eax + 0ch]
        mov eax, [eax + 14h]
        mov eax, [eax]
        mov eax, [eax]
        mov eax, [eax + 10h]
        ret
    }
}

// get function address ：GetProcAddress
FARPROC getProcAddress(HMODULE hModuleBase)
{
    PIMAGE_DOS_HEADER lpDosHeader = (PIMAGE_DOS_HEADER)hModuleBase;
    PIMAGE_NT_HEADERS32 lpNtHeader = (PIMAGE_NT_HEADERS)((DWORD)hModuleBase + lpDosHeader->e_lfanew);
    if (!lpNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size) {
        return NULL;
    }
    if (!lpNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress) {
        return NULL;
    }
    PIMAGE_EXPORT_DIRECTORY lpExports = (PIMAGE_EXPORT_DIRECTORY)((DWORD)hModuleBase + (DWORD)lpNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    PDWORD lpdwFunName = (PDWORD)((DWORD)hModuleBase + (DWORD)lpExports->AddressOfNames);
    PWORD lpword = (PWORD)((DWORD)hModuleBase + (DWORD)lpExports->AddressOfNameOrdinals);
    PDWORD lpdwFunAddr = (PDWORD)((DWORD)hModuleBase + (DWORD)lpExports->AddressOfFunctions);

    DWORD dwLoop = 0;
    FARPROC pRet = NULL;
    for (; dwLoop <= lpExports->NumberOfNames - 1; dwLoop++) {
        char* pFunName = (char*)(lpdwFunName[dwLoop] + (DWORD)hModuleBase);

        if (pFunName[0] == 'G' &&
            pFunName[1] == 'e' &&
            pFunName[2] == 't' &&
            pFunName[3] == 'P' &&
            pFunName[4] == 'r' &&
            pFunName[5] == 'o' &&
            pFunName[6] == 'c' &&
            pFunName[7] == 'A' &&
            pFunName[8] == 'd' &&
            pFunName[9] == 'd' &&
            pFunName[10] == 'r' &&
            pFunName[11] == 'e' &&
            pFunName[12] == 's' &&
            pFunName[13] == 's')
        {
            pRet = (FARPROC)(lpdwFunAddr[lpword[dwLoop]] + (DWORD)hModuleBase);
            break;
        }
    }
    return pRet;
}