#pragma comment(linker,"/merge:.data=.text")
#pragma comment(linker,"/merge:.rdata=.text")
#pragma comment(linker,"/merge:.tls=.text")
#pragma comment(linker, "/section:.text,RWE")
#include <Windows.h>
#include "../MyShell/Conf.h"

#include "aplib.h"
#pragma comment(lib,"aPlib.lib")

//void NTAPI __stdcall TLS_CALLBACK(PVOID DllHandle, DWORD dwReason, PVOID Reserved);
//#pragma comment (linker, "/INCLUDE:__tls_used")  
//#pragma comment (linker, "/INCLUDE:__tls_callback")  
//EXTERN_C
//#pragma data_seg (".CRT$XLB")  
//
//PIMAGE_TLS_CALLBACK _tls_callback[] = { TLS_CALLBACK,0 };
//#pragma data_seg ()  
//#pragma const_seg ()  
//
//void NTAPI __stdcall TLS_CALLBACK(PVOID DllHandle, DWORD Reason, PVOID Reserved)
//{
//	//char *nnnn = "TLS���������������";
//	//MessageBox(0, 0, 0, 0);
//}


DWORD g_Bass = 0;
LONGLONG nPassWord_64 = 0;;
LONGLONG nPassWord_32L = 0;;
LONGLONG nPassWord_32R = 0;;


HMODULE hKernel32 = NULL;
HMODULE hUser32 = NULL;
HMODULE hGdi32 = NULL;
HMODULE hShlwapi = NULL;
HMODULE hNtdll = NULL;
HMODULE hMsvcrt = NULL;
DWORD g_Time1 = 0;
DWORD g_Time2 = 0;
DWORD g_Check = 0;


#define STATIC_TIP 0x999
#define EDIT_PASSWORD 0x1000
#define BUTTON_OK 0x1001


extern"C" _declspec(dllexport) StubConf ShellConfig = { 0xFFFFFFFF,0x1,0x2,0x3,0x4,0x5 };

typedef LPVOID* (WINAPI* FnGetProcAddress)(HMODULE, CHAR*);
FnGetProcAddress pfnGetProcAddress;

typedef HMODULE(WINAPI* FnLoadLibraryA)(CHAR*);
FnLoadLibraryA pfnLoadLibraryA;

typedef DWORD(WINAPI* FnMessageBoxA)(HWND, CHAR*, CHAR*, UINT);
FnMessageBoxA pfnMessageBoxA;

typedef BOOL(WINAPI* FnVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
FnVirtualProtect pfnVirtualProtect;

typedef LPVOID(WINAPI* FnVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
FnVirtualAlloc pfnVirtualAlloc;

typedef LPVOID(WINAPI* FnVirtualFree)(LPVOID, SIZE_T, DWORD);
FnVirtualFree pfnVirtualFree;

typedef VOID(WINAPI* FnRtlZeroMemory)(LPVOID, SIZE_T);
FnRtlZeroMemory pfnRtlZeroMemory;

typedef VOID(WINAPI* FnRtlMoveMemory)(LPVOID, LPVOID, SIZE_T);
FnRtlMoveMemory pfnRtlMoveMemory;

typedef INT_PTR(WINAPI* FnDialogBoxParamA)(DWORD, CHAR*, DWORD, DWORD, DWORD);
FnDialogBoxParamA pfnDialogBoxParamA;

typedef LRESULT(WINAPI* FnDefWindowProcA)(HWND, UINT, WPARAM, LPARAM);
FnDefWindowProcA pfnDefWindowProcA;

typedef VOID(WINAPI* FnPostQuitMessage)(DWORD);
FnPostQuitMessage pfnPostQuitMessage;

typedef DWORD(WINAPI* FnGetDesktopWindow)(VOID);
FnGetDesktopWindow pfnGetDesktopWindow;

typedef ATOM(WINAPI* FnRegisterClassA)(WNDCLASSA *);
FnRegisterClassA pfnRegisterClassA;

typedef HWND(WINAPI* FnCreateWindowExA)(DWORD, CHAR*, CHAR*, DWORD, int, int, int, int, HWND, HMENU, HINSTANCE, LPVOID);
FnCreateWindowExA pfnCreateWindowExA;

typedef VOID(WINAPI* FnShowWindow)(HWND, DWORD);
FnShowWindow pfnShowWindow;

typedef BOOL(WINAPI* FnGetMessageA)(LPMSG, HWND, UINT, UINT);
FnGetMessageA pfnGetMessageA;

typedef BOOL(WINAPI* FnTranslateMessage)(MSG *);
FnTranslateMessage pfnTranslateMessage;

typedef LRESULT(WINAPI* FnDispatchMessageA)(MSG *);
FnDispatchMessageA pfnDispatchMessageA;

typedef HGDIOBJ(WINAPI* FnGetStockObject)(DWORD);
FnGetStockObject pfnGetStockObject;

typedef VOID(WINAPI* FnExitProcess)(DWORD);
FnExitProcess pfnExitProcess;

typedef DWORD(WINAPI* FnGetWindowTextA)(HWND, CHAR*, DWORD);
FnGetWindowTextA pfnGetWindowTextA;

typedef HWND(WINAPI* FnGetDlgItem)(HWND, DWORD);
FnGetDlgItem pfnGetDlgItem;

typedef HWND(WINAPI* FnStrToInt64ExA)(CHAR*, DWORD, LONGLONG*);
FnStrToInt64ExA pfnStrToInt64ExA;

typedef DWORD(WINAPI* FnRand)(VOID);
FnRand pfnRand;

BOOL MyStrCmp(CHAR *nText1, CHAR* nText2)
{
	DWORD i = 0;
	while (nText1[i])
	{
		if (nText1[i] != nText2[i])return FALSE;
		i++;
	}
	return TRUE;
}
INT MyFindStr(CHAR* nText, CHAR nText2)
{
	int i = 0;
	while (nText[i])
	{
		if (nText[i] == nText2)
			return i;
		i++;
	}
	return -1;

	//int i = 0;
	//for (; i < 6; i++)
	//{
	//	if (nText[i] == nText2)
	//		return TRUE;
	//}
	//return FALSE;
}
VOID MyGetStrLeft(CHAR* nDest, CHAR *nSrc,CHAR nSeg)
{
	int i = 0;
	while (nSrc[i]!= nSeg)
	{
		nDest[i] = nSrc[i];
		i++;
	}

}
VOID MyGetStrRight(CHAR* nDest, CHAR *nSrc, CHAR nSeg)
{
	int i = 0;
	while (nSrc[i] != nSeg)
	{
		i++;
	}

	i++;

	int j = 0;
	while (nSrc[i])
	{
		nDest[j] = nSrc[i];
		i++;
		j++;
	}

}

IMAGE_DOS_HEADER* GetDosHeader(char* pFileData)
{
	return (IMAGE_DOS_HEADER *)pFileData;
}
DosStub* GetDosSubHeader(char* pFileData)
{
	return (DosStub*)(pFileData + sizeof(IMAGE_DOS_HEADER));
}
IMAGE_NT_HEADERS* GetNtHeader(char* pFileData)
{
	return (IMAGE_NT_HEADERS*)(GetDosHeader(pFileData)->e_lfanew + (SIZE_T)pFileData);
}
IMAGE_FILE_HEADER* GetFileHeader(char* pFileData)
{
	return &GetNtHeader(pFileData)->FileHeader;
}
IMAGE_OPTIONAL_HEADER* GetOptionHeader(char* pFileData)
{
	return &GetNtHeader(pFileData)->OptionalHeader;
}
IMAGE_SECTION_HEADER* GetSection(char* pFileData, const char* scnName)//��ȡָ�����ֵ�����
{
	// ��ȡ���θ�ʽ
	DWORD dwScnCount = GetFileHeader(pFileData)->NumberOfSections;
	// ��ȡ��һ������
	IMAGE_SECTION_HEADER* pScn = IMAGE_FIRST_SECTION(GetNtHeader(pFileData));
	char buff[10] = { 0 };
	// ��������
	for (DWORD i = 0; i < dwScnCount; ++i) {
		pfnRtlMoveMemory(buff, (char*)pScn[i].Name, 8);
		// �ж��Ƿ�����ͬ������
		if (MyStrCmp(buff, (char*)scnName))
			return pScn + i;
	}
	return nullptr;
}
IMAGE_SECTION_HEADER* GetSectionHeader(char* pFileData)
{
	return IMAGE_FIRST_SECTION(GetNtHeader(pFileData));
}

//*********************************************************************************
// ���ڻص�����
//*********************************************************************************
LRESULT CALLBACK WndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	WORD wHigh = HIWORD(wParam);
	WORD wLow = LOWORD(wParam);

	switch (uMsg)
	{

	case WM_CLOSE:
	{
		pfnExitProcess(0);
		//UINT uRet = pfnMessageBoxA(hWnd, "����Ĳ���������", "��ʾ", MB_YESNO | MB_ICONASTERISK);
		//if (uRet == 6)
		//	pfnExitProcess(0);
		//else
		//	return 0;
	}
	break;



	//case WM_CHAR:
	//{
	//	if (wParam == 13)
	//	{
	//		goto BUTTONCODE;
	//	}
	//}
	//break;



	case WM_COMMAND:
	{
		switch (wLow)
		{
		case BUTTON_OK:
			//BUTTONCODE:
			HWND hEdit = pfnGetDlgItem(hWnd, EDIT_PASSWORD);
			CHAR nBuff[MAX_PATH];
			pfnRtlZeroMemory(nBuff, MAX_PATH);
			pfnGetWindowTextA(hEdit, nBuff, MAX_PATH);



			CHAR nNewBuff_64[17];
			CHAR nNewBuff_32L[9];
			CHAR nNewBuff_32R[9];
			pfnRtlZeroMemory(nNewBuff_64, _countof(nNewBuff_64));;
			pfnRtlZeroMemory(nNewBuff_32L, _countof(nNewBuff_32L));;
			pfnRtlZeroMemory(nNewBuff_32R, _countof(nNewBuff_32R));;

			DWORD i = 0;
			for (DWORD j = 0; j < 16; j++)
			{
				if (nBuff[i] == 0)i = 0;
				nNewBuff_64[j] = nBuff[i];
				i++;
			}

			for (DWORD j = 0; j < 8; j++)
			{
				nNewBuff_32L[j] = nNewBuff_64[j];
				nNewBuff_32R[j] = nNewBuff_64[j + 8];
			}

			pfnStrToInt64ExA(nNewBuff_64, 1, &nPassWord_64);
			pfnStrToInt64ExA(nNewBuff_32L, 1, &nPassWord_32L);
			pfnStrToInt64ExA(nNewBuff_32R, 1, &nPassWord_32R);


			pfnShowWindow(hWnd, SW_HIDE);
			pfnPostQuitMessage(0);

			//UINT uRet = pfnMessageBoxA(hWnd, "ȷ���������������ȷ��", "��ʾ", MB_YESNO | MB_ICONINFORMATION);

		}
		break;
	}
	break;

	}
	return pfnDefWindowProcA(hWnd, uMsg, wParam, lParam);
}

//*********************************************************************************
// �������봰��
//*********************************************************************************
void MyDialogBox()
{

	WNDCLASSA wc = { 0 };
	wc.lpszClassName = ("Hock");
	wc.lpfnWndProc = &WndProc;
	wc.hbrBackground = (HBRUSH)pfnGetStockObject(WHITE_BRUSH);
	pfnRegisterClassA(&wc);

	HWND hWnd = NULL;/*���ھ��,���ڱ��洴�������Ĵ��ڶ���*/
	hWnd = pfnCreateWindowExA(0, "Hock", "Hock Protect", WS_OVERLAPPEDWINDOW, 600, 300, 250, 320, 0, 0, (HINSTANCE)g_Bass, 0);

	pfnCreateWindowExA(0, "Edit", "���������룺", SS_CENTER | WS_CHILD | WS_VISIBLE | WS_GROUP, 60, 70, 120, 30, hWnd, (HMENU)STATIC_TIP, (HINSTANCE)g_Bass, NULL);
	pfnCreateWindowExA(WS_EX_CLIENTEDGE, "Edit", "", ES_NUMBER | WS_CHILD | WS_OVERLAPPED | WS_VISIBLE, 60, 100, 120, 30, hWnd, (HMENU)EDIT_PASSWORD, (HINSTANCE)g_Bass, NULL);
	pfnCreateWindowExA(0, "Button", "ȷ������", BS_PUSHBUTTON | WS_CHILD | WS_VISIBLE, 60, 150, 120, 30, hWnd, (HMENU)BUTTON_OK, (HINSTANCE)g_Bass, NULL);

	pfnShowWindow(hWnd, SW_SHOW);

	MSG msg = { 0 };
	while (pfnGetMessageA(&msg, 0, 0, 0))
	{
		pfnTranslateMessage(&msg);
		pfnDispatchMessageA(&msg);
	}

}

//*********************************************************************************
// ��ȡ�����API������ַ
//*********************************************************************************
void GetApiLibrary()
{
	// 1. �Ȼ�ȡkernel32�ļ��ػ�ַ
	_asm
	{
		mov eax, FS:[0x30];
		mov eax, [eax + 0xc];
		mov eax, [eax + 0xc];
		mov eax, [eax];
		mov eax, [eax];
		mov eax, [eax + 0x18];
		mov hKernel32, eax;
	}
	// 2. �ٻ�ȡLoadLibrayA��GetProcAddress�����ĵ�ַ
	// 2.1 �����������ȡ������ַ
	IMAGE_EXPORT_DIRECTORY* pExp = NULL;
	pExp = (IMAGE_EXPORT_DIRECTORY*)(GetOptionHeader((char*)hKernel32)->DataDirectory[0].VirtualAddress + (DWORD)hKernel32);

	DWORD* pEAT = NULL, *pENT = NULL;
	WORD* pEOT = NULL;
	pEAT = (DWORD*)(pExp->AddressOfFunctions + (DWORD)hKernel32);
	pENT = (DWORD*)(pExp->AddressOfNames + (DWORD)hKernel32);
	pEOT = (WORD*)(pExp->AddressOfNameOrdinals + (DWORD)hKernel32);
	for (size_t i = 0; i < pExp->NumberOfNames; i++)
	{
		char* pName = pENT[i] + (char*)hKernel32;
		if (MyStrCmp(pName, "GetProcAddress"))
		{
			int index = pEOT[i];
			pfnGetProcAddress = (FnGetProcAddress)(pEAT[index] + (DWORD)hKernel32);
			break;
		}
	}
	// 3. ͨ��������API��ȡ������API
	pfnLoadLibraryA = (FnLoadLibraryA)pfnGetProcAddress(hKernel32, "LoadLibraryA");
	hUser32 = pfnLoadLibraryA("user32.dll");
	hGdi32 = pfnLoadLibraryA("gdi32.dll");
	hShlwapi = pfnLoadLibraryA("shlwapi.dll");
	hNtdll = pfnLoadLibraryA("ntdll.dll");
	hMsvcrt = pfnLoadLibraryA("msvcrt.dll");

	pfnMessageBoxA = (FnMessageBoxA)pfnGetProcAddress(hUser32, "MessageBoxA");
	pfnVirtualProtect = (FnVirtualProtect)pfnGetProcAddress(hKernel32, "VirtualProtect");
	pfnVirtualAlloc = (FnVirtualAlloc)pfnGetProcAddress(hKernel32, "VirtualAlloc");
	pfnVirtualFree = (FnVirtualFree)pfnGetProcAddress(hKernel32, "VirtualFree");
	pfnRtlZeroMemory = (FnRtlZeroMemory)pfnGetProcAddress(hKernel32, "RtlZeroMemory");
	pfnRtlMoveMemory = (FnRtlMoveMemory)pfnGetProcAddress(hKernel32, "RtlMoveMemory");
	pfnExitProcess = (FnExitProcess)pfnGetProcAddress(hKernel32, "ExitProcess");


	pfnDialogBoxParamA = (FnDialogBoxParamA)pfnGetProcAddress(hUser32, "DialogBoxParamA");
	pfnDefWindowProcA = (FnDefWindowProcA)pfnGetProcAddress(hUser32, "DefWindowProcA");
	pfnPostQuitMessage = (FnPostQuitMessage)pfnGetProcAddress(hUser32, "PostQuitMessage");
	pfnGetDesktopWindow = (FnGetDesktopWindow)pfnGetProcAddress(hUser32, "GetDesktopWindow");
	pfnRegisterClassA = (FnRegisterClassA)pfnGetProcAddress(hUser32, "RegisterClassA");
	pfnCreateWindowExA = (FnCreateWindowExA)pfnGetProcAddress(hUser32, "CreateWindowExA");
	pfnShowWindow = (FnShowWindow)pfnGetProcAddress(hUser32, "ShowWindow");

	pfnGetMessageA = (FnGetMessageA)pfnGetProcAddress(hUser32, "GetMessageA");
	pfnTranslateMessage = (FnTranslateMessage)pfnGetProcAddress(hUser32, "TranslateMessage");
	pfnDispatchMessageA = (FnDispatchMessageA)pfnGetProcAddress(hUser32, "DispatchMessageA");
	pfnGetWindowTextA = (FnGetWindowTextA)pfnGetProcAddress(hUser32, "GetWindowTextA");
	pfnGetDlgItem = (FnGetDlgItem)pfnGetProcAddress(hUser32, "GetDlgItem");


	pfnGetStockObject = (FnGetStockObject)pfnGetProcAddress(hGdi32, "GetStockObject");

	pfnStrToInt64ExA = (FnStrToInt64ExA)pfnGetProcAddress(hShlwapi, "StrToInt64ExA");

	pfnRand = (FnRand)pfnGetProcAddress(hMsvcrt, "rand");


}

//*********************************************************************************
// ��ѹ����
//*********************************************************************************
void UpackCode()
{
	DWORD dwScnCount = GetFileHeader((char*)g_Bass)->NumberOfSections;
	IMAGE_SECTION_HEADER* pScn = IMAGE_FIRST_SECTION(GetNtHeader((char*)g_Bass));

	DWORD nSubNum = ShellConfig.nFixIco ? 1 : 1;//����޸���ͼ�꣬��ѹ��ʱ��Ҫ�ų�HOCKPACK��.rsrc��

	for (DWORD i = 0; i < dwScnCount - nSubNum; i++)
	{
		if (pScn->SizeOfRawData)
		{
			char *nSectionByte = (char*)(pScn->VirtualAddress + (DWORD)g_Bass);


			DWORD nPackSize = pScn->SizeOfRawData;

			size_t nUPackSize = aPsafe_get_orig_size(nSectionByte);


			char *nUPackData = (char*)pfnVirtualAlloc(NULL, nUPackSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

			nPackSize = aPsafe_depack(nSectionByte, nPackSize, nUPackData, nUPackSize);


			DWORD nOldProtect = 0;
			pfnVirtualProtect(nSectionByte, pScn->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &nOldProtect);


			pfnRtlZeroMemory(nSectionByte, nPackSize);

			pfnRtlMoveMemory(nSectionByte, nUPackData, nUPackSize);

			//pfnVirtualProtect(nSectionByte, pScn->VirtualAddress, nOldProtect, &nOldProtect);

			pfnVirtualFree(nUPackData, nUPackSize, MEM_RELEASE);

			
			pScn->SizeOfRawData = nUPackSize;
		}



		pScn++;
	}

}

//*********************************************************************************
// ��������
//*********************************************************************************
void DecryptCode()
{

	DWORD dwScnCount = GetFileHeader((char*)g_Bass)->NumberOfSections;
	IMAGE_SECTION_HEADER* pScn = GetSectionHeader((char*)g_Bass);

	DWORD nSubNum = ShellConfig.nFixIco ? 1 : 1;//����޸���ͼ�꣬��ѹ��ʱ��Ҫ�ų�HOCKPACK��.rsrc��

	for (DWORD i = 0; i < dwScnCount - nSubNum; i++)
	{
		DWORD nDataSize = pScn->SizeOfRawData;
		if (nDataSize)
		{
			LONGLONG *nSectionLongLong = (LONGLONG*)(pScn->VirtualAddress + (DWORD)g_Bass);


			DWORD nOldProtect = 0;
			pfnVirtualProtect(nSectionLongLong, pScn->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &nOldProtect);

			for (DWORD i = 0; i < pScn->SizeOfRawData / 8; i++)
			{
				nSectionLongLong[i] = nSectionLongLong[i] ^ nPassWord_64;
				DWORD *nSectionDword = (DWORD*)&nSectionLongLong[i];
				nSectionDword[0] = nSectionDword[0] ^ (DWORD)nPassWord_32L;
				nSectionDword[1] = nSectionDword[1] ^ (DWORD)nPassWord_32R;
			}
			pfnVirtualProtect(nSectionLongLong, pScn->Misc.VirtualSize, nOldProtect, &nOldProtect);
		}

		pScn++;
	}

}

//*********************************************************************************
// �����ļ�ͷ�Ƿ��д
//*********************************************************************************
void SetFileHeaderProtect(bool nWrite)
{
	DWORD nOldProtect = 0;
	if (nWrite)
		pfnVirtualProtect((LPVOID)g_Bass, 0x400, PAGE_EXECUTE_READWRITE, &nOldProtect);
	else
		pfnVirtualProtect((LPVOID)g_Bass, 0x400, nOldProtect, &nOldProtect);
}

//*********************************************************************************
// ��ȡ��ǰ���ػ�ַ
//*********************************************************************************
void GetPeModuleHandle()
{
	_asm
	{
		mov eax, FS:[0x30];
		mov eax, [eax + 0xc];
		mov eax, [eax + 0xc];
		mov eax, [eax + 0x18];
		mov g_Bass, eax;
	}

}

//*********************************************************************************
// ��ϣֵ�뺯�����Ƚϣ�����������ϣֵ
//*********************************************************************************
bool Hash_CmpString(char *strFunName, int nHash)
{
	unsigned int nDigest = 0;
	while (*strFunName)
	{
		nDigest = ((nDigest << 25) | (nDigest >> 7));
		nDigest = nDigest + *strFunName;
		strFunName++;
	}
	return nHash == nDigest ? true : false;
}

//*********************************************************************************
// ͨ����ϣֵ��ȡAPI������ַ����ϣֵ��ģ����ػ�ַ
//*********************************************************************************
int GetFunAddrByHash(int nHashDigest, HMODULE hModule)
{
	// 1. ��ȡDOSͷ��NTͷ
	PIMAGE_DOS_HEADER pDos_Header;
	PIMAGE_NT_HEADERS pNt_Header;
	pDos_Header = (PIMAGE_DOS_HEADER)hModule;
	pNt_Header = (PIMAGE_NT_HEADERS)((DWORD)hModule + pDos_Header->e_lfanew);

	// 2. ��ȡ��������
	PIMAGE_DATA_DIRECTORY   pDataDir;
	PIMAGE_EXPORT_DIRECTORY pExport;
	pDataDir = pNt_Header->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_EXPORT;
	pExport = (PIMAGE_EXPORT_DIRECTORY)((DWORD)hModule + pDataDir->VirtualAddress);

	// 3. ��ȡ��������ϸ��Ϣ
	PDWORD pAddrOfFun = (PDWORD)(pExport->AddressOfFunctions + (DWORD)hModule);
	PDWORD pAddrOfNames = (PDWORD)(pExport->AddressOfNames + (DWORD)hModule);
	PWORD  pAddrOfOrdinals = (PWORD)(pExport->AddressOfNameOrdinals + (DWORD)hModule);

	// 4. �����Ժ��������Һ�����ַ������ѭ����ȡENT�еĺ���������Ϊ���Ժ�����
	//    Ϊ��׼����˲������޺�����������������봫��ֵ�Աȣ�����ƥ��������EAT
	//    ����ָ�������Ϊ��������ȡ�����ֵַ��
	DWORD dwFunAddr;
	for (DWORD i = 0; i < pExport->NumberOfNames; i++)
	{
		PCHAR lpFunName = (PCHAR)(pAddrOfNames[i] + (DWORD)hModule);
		if (Hash_CmpString(lpFunName, nHashDigest))
		{
			dwFunAddr = pAddrOfFun[pAddrOfOrdinals[i]] + (DWORD)hModule;
			break;
		}
		if (i == pExport->NumberOfNames - 1)
			return 0;
	}

	return dwFunAddr;
}

//*********************************************************************************
// ���ɼ��ܵ�IAT��ַ��������ַ
//*********************************************************************************
int EncryptIat(SIZE_T ImpAddress)
{
	DWORD nNum = pfnRand() + pfnRand() + (DWORD)nPassWord_32L;

	DWORD nNewImpAddress = ImpAddress^nNum;

	int nNewIat = (int)pfnVirtualAlloc(0, 1, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	//char nOpCode[] = { 0xb8,0,0,0,0,0x35,0,0,0,0,0x50,0xc3 };
	//*(int*)(nOpCode + 1) = nNewImpAddress;
	//*(int*)(nOpCode + 6) = nNum;

	CHAR nOpCode[] = { (CHAR)0x60,(CHAR)0xC7,(CHAR)0x04,(CHAR)0x24,(CHAR)0x00,(CHAR)0x00,(CHAR)0x00,(CHAR)0x10,(CHAR)0x8B,(CHAR)0x44,(CHAR)0x24,(CHAR)0x10,(CHAR)0x87,(CHAR)0x04,(CHAR)0x24,(CHAR)0x87,(CHAR)0x44,(CHAR)0x24,(CHAR)0x10,(CHAR)0xC7,(CHAR)0x44,(CHAR)0x24,(CHAR)0x04,(CHAR)0x00,(CHAR)0x00,(CHAR)0x00,(CHAR)0x02,(CHAR)0x87,(CHAR)0x44,(CHAR)0x24,(CHAR)0x04,(CHAR)0x09,(CHAR)0x44,(CHAR)0x24,(CHAR)0x10,(CHAR)0x4C,(CHAR)0x8D,(CHAR)0x64,(CHAR)0x24,(CHAR)0xFD,(CHAR)0xB8,(CHAR)0x08,(CHAR)0x00,(CHAR)0x00,(CHAR)0x00,(CHAR)0x6B,(CHAR)0xC0,(CHAR)0x02,(CHAR)0xD1,(CHAR)0xE8,(CHAR)0x66,(CHAR)0x89,(CHAR)0x44,(CHAR)0x24,(CHAR)0x04,(CHAR)0x8D,(CHAR)0x64,(CHAR)0x24,(CHAR)0x03,(CHAR)0x31,(CHAR)0xC0,(CHAR)0x44,(CHAR)0x66,(CHAR)0x8B,(CHAR)0x04,(CHAR)0x24,(CHAR)0x87,(CHAR)0x44,(CHAR)0x24,(CHAR)0x0C,(CHAR)0x87,(CHAR)0x44,(CHAR)0x24,(CHAR)0x10,(CHAR)0x0B,(CHAR)0x44,(CHAR)0x24,(CHAR)0x0C,(CHAR)0x87,(CHAR)0x44,(CHAR)0x24,(CHAR)0x10,(CHAR)0xC7,(CHAR)0x44,(CHAR)0x24,(CHAR)0x08,(CHAR)0x00,(CHAR)0x00,(CHAR)0x30,(CHAR)0x00,(CHAR)0x87,(CHAR)0x44,(CHAR)0x24,(CHAR)0x08,(CHAR)0x09,(CHAR)0x44,(CHAR)0x24,(CHAR)0x10,(CHAR)0x31,(CHAR)0xC0,(CHAR)0xC7,(CHAR)0x44,(CHAR)0x24,(CHAR)0x14,(CHAR)0x70,(CHAR)0x56,(CHAR)0x04,(CHAR)0x00,(CHAR)0x87,(CHAR)0x44,(CHAR)0x24,(CHAR)0x10,(CHAR)0x09,(CHAR)0x44,(CHAR)0x24,(CHAR)0x14,(CHAR)0x8D,(CHAR)0x64,(CHAR)0x24,(CHAR)0x10,(CHAR)0xB8,(CHAR)0x99,(CHAR)0x99,(CHAR)0x99,(CHAR)0x99,(CHAR)0x87,(CHAR)0x44,(CHAR)0x24,(CHAR)0x0C,(CHAR)0x87,(CHAR)0x44,(CHAR)0x24,(CHAR)0x04,(CHAR)0x31,(CHAR)0x44,(CHAR)0x24,(CHAR)0x0C,(CHAR)0x83,(CHAR)0xC4,(CHAR)0x0C,(CHAR)0xC3 };
	//	ԭʼָ��
	//	004010C0 - pushad
	//	004010C1 - mov[esp], 10000000
	//	004010C8 - mov eax, [esp + 10]
	//	004010CC - xchg[esp], eax
	//	004010CF - xchg[esp + 10], eax
	//	004010D3 - mov[esp + 04], 02000000
	//	004010DB - xchg[esp + 04], eax
	//	004010DF - or [esp + 10], eax
	//	004010E3 - dec esp
	//	004010E4 - lea esp, [esp - 03]
	//	004010E8 - mov eax, 00000008
	//	004010ED - imul eax, eax, 02
	//	004010F0 - shr eax, 1
	//	004010F2 - mov[esp + 04], ax
	//	004010F7 - lea esp, [esp + 03]
	//	004010FB - xor eax, eax
	//	004010FD - inc esp
	//	004010FE - mov ax, [esp]
	//	00401102 - xchg[esp + 0C], eax
	//	00401106 - xchg[esp + 10], eax
	//	0040110A - or eax, [esp + 0C]
	//	0040110E - xchg[esp + 10], eax
	//	00401112 - mov[esp + 08], 00300000
	//	0040111A - xchg[esp + 08], eax
	//	0040111E - or [esp + 10], eax
	//	00401122 - xor eax, eax
	//	00401124 - mov[esp + 14], 00045670
	//	0040112C - xchg[esp + 10], eax
	//	00401130 - or [esp + 14], eax
	//	00401134 - lea esp, [esp + 10]
	//	00401138 - mov eax, 99999999
	//	0040113D - xchg[esp + 0C], eax
	//	00401141 - xchg[esp + 04], eax
	//	00401145 - xor[esp + 0C], eax
	//	00401149 - add esp, -70
	//	0040114C - ret



	DWORD A = nNewImpAddress;
	A = A >> 0x1C;
	A = A << 0x1C;
	DWORD B = nNewImpAddress;
	B = B << 0x4;
	B = B >> 0x1C;
	B = B << 0x18;
	DWORD C = nNewImpAddress;
	C = C << 0x8;
	C = C >> 0x1C;
	C = C << 0x14;
	DWORD D = nNewImpAddress;
	D = D >> 0x4;
	D = D << 0x10;
	D = D >> 0xc;
	DWORD E = nNewImpAddress;
	E = E << 0x1c;
	E = E >> 0x1c;



	*(DWORD*)(nOpCode + 0x4) = A;
	*(DWORD*)(nOpCode + 0x17) = B;
	*(DWORD*)(nOpCode + 0x29) = E;
	*(DWORD*)(nOpCode + 0x56) = C;
	*(DWORD*)(nOpCode + 0x68) = D;

	*(DWORD*)(nOpCode + 0x79) = nNum;



	pfnRtlMoveMemory((LPVOID)nNewIat, nOpCode, (SIZE_T)_countof(nOpCode));

	return nNewIat;
}

//*********************************************************************************
// �޸������δ���ܵ�
//*********************************************************************************
void FixImportTable_Normal()
{

	IMAGE_THUNK_DATA* pInt = NULL;
	IMAGE_THUNK_DATA* pIat = NULL;
	SIZE_T impAddress = 0;
	HMODULE	hImpModule = 0;
	DWORD dwOldProtect = 0;
	IMAGE_IMPORT_BY_NAME* pImpName = 0;



	if (!GetOptionHeader((char*)g_Bass)->DataDirectory[1].VirtualAddress)return;


	IMAGE_IMPORT_DESCRIPTOR* pImp = (IMAGE_IMPORT_DESCRIPTOR*)(GetOptionHeader((char*)g_Bass)->DataDirectory[1].VirtualAddress + g_Bass);


	while (pImp->Name) {
		pIat = (IMAGE_THUNK_DATA*)(pImp->FirstThunk + g_Bass);
		if (pImp->OriginalFirstThunk == 0) // ���������INT��ʹ��IAT
		{
			pInt = pIat;
		}
		else
		{
			pInt = (IMAGE_THUNK_DATA*)(pImp->OriginalFirstThunk + g_Bass);
		}

		// ����dll
		hImpModule = pfnLoadLibraryA((char*)(pImp->Name + g_Bass));

		while (pInt->u1.Function) {

			if (!IMAGE_SNAP_BY_ORDINAL(pInt->u1.Ordinal))
			{
				pImpName = (IMAGE_IMPORT_BY_NAME*)(pInt->u1.Function + g_Bass);
				impAddress = (SIZE_T)pfnGetProcAddress(hImpModule, (char*)pImpName->Name);
			}
			else
			{
				impAddress = (SIZE_T)pfnGetProcAddress(hImpModule, (char*)(pInt->u1.Function & 0xFFFF));
			}

			pfnVirtualProtect(&pIat->u1.Function, sizeof(pIat->u1.Function), PAGE_READWRITE, &dwOldProtect);

			//pIat->u1.Function = encryptIat(hImpModule, impAddress);
			pIat->u1.Function = impAddress;

			pfnVirtualProtect(&pIat->u1.Function, sizeof(pIat->u1.Function), dwOldProtect, &dwOldProtect);

			++pInt;
			++pIat;
		}

		++pImp;
	}

}

//*********************************************************************************
// �޸�������Ѽ��ܵ�
//*********************************************************************************
void FixImportTable_Encrypt()
{

	IMAGE_THUNK_DATA* pInt = NULL;
	IMAGE_THUNK_DATA* pIat = NULL;
	SIZE_T ImpAddress = 0;
	SIZE_T TempImpAddress = 0;
	HMODULE	hImpModule = 0;
	DWORD dwOldProtect = 0;
	IMAGE_IMPORT_BY_NAME* pImpName = 0;

	if (!GetOptionHeader((char*)g_Bass)->DataDirectory[1].VirtualAddress)return;

	__asm 
	{
		rdtsc;
		mov g_Time1, edx;
	}

	IMAGE_IMPORT_DESCRIPTOR* pImp = (IMAGE_IMPORT_DESCRIPTOR*)(GetOptionHeader((char*)g_Bass)->DataDirectory[1].VirtualAddress + g_Bass);


	while (pImp->Name) {
		pIat = (IMAGE_THUNK_DATA*)(pImp->FirstThunk + g_Bass);
		if (pImp->OriginalFirstThunk == 0) // ���������INT��ʹ��IAT
		{
			pInt = pIat;
		}
		else
		{
			pInt = (IMAGE_THUNK_DATA*)(pImp->OriginalFirstThunk + g_Bass);
		}

		// ����dll
		hImpModule = pfnLoadLibraryA((char*)(pImp->Name + g_Bass));


		//int nMinAddress = (GetSection((char*)hImpModule, ".text")->VirtualAddress) + (int)hImpModule;;
		int nMaxAddress = (GetOptionHeader((char*)hImpModule)->DataDirectory[0].VirtualAddress) +
			(GetOptionHeader((char*)hImpModule)->DataDirectory[0].Size) + (int)hImpModule;

		while (pInt->u1.Function)
		{
			int nTempHash = pInt->u1.Function;

			if ((nTempHash & 0xFFFF0000) != 0x80000000)
			{
				ImpAddress = GetFunAddrByHash(pInt->u1.Function, hImpModule);

				INT nIndex = MyFindStr((CHAR*)ImpAddress, '.');
				if (nIndex != -1)
				{
					CHAR nStrLeft[MAX_PATH];//����DLL����
					CHAR nStrRight[MAX_PATH];//���溯������
					pfnRtlZeroMemory(nStrLeft, MAX_PATH);
					pfnRtlZeroMemory(nStrRight, MAX_PATH);

					MyGetStrLeft(nStrLeft, (CHAR*)ImpAddress, '.');
					MyGetStrRight(nStrRight, (CHAR*)ImpAddress, '.');

					HMODULE  nTempModule = pfnLoadLibraryA(nStrLeft);//���¼����ض����DLL			 
					TempImpAddress = (SIZE_T)pfnGetProcAddress(nTempModule, nStrRight);//����ȡAPI��ַ

					if (TempImpAddress)ImpAddress = TempImpAddress;

				}
				//char *Top = "�����������������������������������";
			}
			else
			{
				ImpAddress = (SIZE_T)pfnGetProcAddress(hImpModule, (char*)(pInt->u1.Function & 0xFFFF));
			}

			pfnVirtualProtect(&pIat->u1.Function, sizeof(pIat->u1.Function), PAGE_READWRITE, &dwOldProtect);

			//pIat->u1.Function = encryptIat(hImpModule, impAddress);
			pIat->u1.Function = EncryptIat(ImpAddress);

			pfnVirtualProtect(&pIat->u1.Function, sizeof(pIat->u1.Function), dwOldProtect, &dwOldProtect);

			++pInt;
			++pIat;
		}

		++pImp;
	}

}

//*********************************************************************************
// �޸�����Ŀ¼��ָ��
//*********************************************************************************
void FixDataDir()
{
	GetOptionHeader((char*)g_Bass)->DataDirectory[1].VirtualAddress = ShellConfig.nImportVirtual;
	GetOptionHeader((char*)g_Bass)->DataDirectory[1].Size = ShellConfig.nImportSize;
	GetOptionHeader((char*)g_Bass)->DataDirectory[2].VirtualAddress = ShellConfig.nResourceVirtual;
	GetOptionHeader((char*)g_Bass)->DataDirectory[2].Size = ShellConfig.nResourceSize;
	GetOptionHeader((char*)g_Bass)->DataDirectory[5].VirtualAddress = ShellConfig.nRelocVirtual;
	GetOptionHeader((char*)g_Bass)->DataDirectory[5].Size = ShellConfig.nRelocSize;
	GetOptionHeader((char*)g_Bass)->DataDirectory[9].VirtualAddress = ShellConfig.nTlsVirtual;
	GetOptionHeader((char*)g_Bass)->DataDirectory[9].Size = ShellConfig.nTlsSize;

}

//*********************************************************************************
// �޸�����CALLIAT�Ĵ���
//*********************************************************************************
void FixCallCode()
{

	IMAGE_SECTION_HEADER* nOpcodeSection = GetSection((CHAR*)g_Bass, "OPCODE");

	__asm
	{
		rdtsc;
		mov g_Time2, edx;
	}

	CHAR *nByte = (CHAR*)(nOpcodeSection->VirtualAddress + (DWORD)g_Bass);

	//g_Check = (g_Time2 - g_Time1 >= 1);

	if (ShellConfig.nVmp)
	{
		DWORD nCodeRecordNum = *(DWORD*)nByte;

		nByte = nByte + nCodeRecordNum * 4 + nCodeRecordNum * 5 + 4;
	}

	DWORD nCallRecordNum = *(DWORD*)nByte;

	nByte = nByte + 4 + g_Check;

	LPVOID nIndexTab = pfnVirtualAlloc(NULL, nCallRecordNum * 8, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	pfnRtlMoveMemory(nIndexTab, nByte, nCallRecordNum * 8);

	pfnRtlZeroMemory(nByte - 4, nCallRecordNum * 8 + 4);


	CHAR nMyCallCode[] = { (CHAR)0x53,(CHAR)0x51,(CHAR)0x52,(CHAR)0x57,(CHAR)0x56,(CHAR)0x55,(CHAR)0x8B,(CHAR)0xEC,(CHAR)0x83,(CHAR)0xEC,(CHAR)0x40,(CHAR)0x64,(CHAR)0xA1,(CHAR)0x30,(CHAR)0x00,(CHAR)0x00,(CHAR)0x00,(CHAR)0x8B,(CHAR)0x40,(CHAR)0x0C,(CHAR)0x8B,(CHAR)0x40,(CHAR)0x0C,(CHAR)0x8B,(CHAR)0x50,(CHAR)0x18,(CHAR)0x89,(CHAR)0x55,(CHAR)0xFC,(CHAR)0x8B,(CHAR)0x45,(CHAR)0x18,(CHAR)0x89,(CHAR)0x45,(CHAR)0xF8,(CHAR)0xBE,(CHAR)0x00,(CHAR)0x08,(CHAR)0x51,(CHAR)0x00,(CHAR)0xE9,(CHAR)0x03,(CHAR)0x00,(CHAR)0x00,(CHAR)0x00,(CHAR)0x83,(CHAR)0xC6,(CHAR)0x08,(CHAR)0x8B,(CHAR)0x06,(CHAR)0x83,(CHAR)0xF8,(CHAR)0x00,(CHAR)0x0F,(CHAR)0x84,(CHAR)0x11,(CHAR)0x00,(CHAR)0x00,(CHAR)0x00,(CHAR)0x83,(CHAR)0xC0,(CHAR)0x05,(CHAR)0x03,(CHAR)0x45,(CHAR)0xFC,(CHAR)0x3B,(CHAR)0x45,(CHAR)0xF8,(CHAR)0x75,(CHAR)0xE7,(CHAR)0x8B,(CHAR)0x46,(CHAR)0x04,(CHAR)0x89,(CHAR)0x45,(CHAR)0xEC,(CHAR)0x8B,(CHAR)0x55,(CHAR)0xFC,(CHAR)0x8B,(CHAR)0x42,(CHAR)0x3C,(CHAR)0x8D,(CHAR)0x04,(CHAR)0x10,(CHAR)0x89,(CHAR)0x45,(CHAR)0xF4,(CHAR)0x8B,(CHAR)0x80,(CHAR)0x80,(CHAR)0x00,(CHAR)0x00,(CHAR)0x00,(CHAR)0x8D,(CHAR)0x04,(CHAR)0x10,(CHAR)0x89,(CHAR)0x45,(CHAR)0xF0,(CHAR)0x8B,(CHAR)0xF0,(CHAR)0x31,(CHAR)0xC9,(CHAR)0xE9,(CHAR)0x0F,(CHAR)0x00,(CHAR)0x00,(CHAR)0x00,(CHAR)0x83,(CHAR)0xC6,(CHAR)0x14,(CHAR)0x8B,(CHAR)0x46,(CHAR)0x10,(CHAR)0x83,(CHAR)0xF8,(CHAR)0x00,(CHAR)0x0F,(CHAR)0x84,(CHAR)0x3A,(CHAR)0x00,(CHAR)0x00,(CHAR)0x00,(CHAR)0x8B,(CHAR)0x46,(CHAR)0x10,(CHAR)0x83,(CHAR)0xF8,(CHAR)0x00,(CHAR)0x74,(CHAR)0xE9,(CHAR)0x8B,(CHAR)0x7E,(CHAR)0x10,(CHAR)0x03,(CHAR)0x7D,(CHAR)0xFC,(CHAR)0xE9,(CHAR)0x0E,(CHAR)0x00,(CHAR)0x00,(CHAR)0x00,(CHAR)0x83,(CHAR)0xC7,(CHAR)0x04,(CHAR)0x8B,(CHAR)0x07,(CHAR)0x83,(CHAR)0xF8,(CHAR)0x00,(CHAR)0x0F,(CHAR)0x84,(CHAR)0x17,(CHAR)0x00,(CHAR)0x00,(CHAR)0x00,(CHAR)0x8B,(CHAR)0x07,(CHAR)0x83,(CHAR)0xF8,(CHAR)0x00,(CHAR)0x0F,(CHAR)0x84,(CHAR)0x0C,(CHAR)0x00,(CHAR)0x00,(CHAR)0x00,(CHAR)0x39,(CHAR)0x4D,(CHAR)0xEC,(CHAR)0x0F,(CHAR)0x84,(CHAR)0x05,(CHAR)0x00,(CHAR)0x00,(CHAR)0x00,(CHAR)0x41,(CHAR)0xEB,(CHAR)0xDB,(CHAR)0xEB,(CHAR)0xB7,(CHAR)0x8B,(CHAR)0xC0,(CHAR)0x8B,(CHAR)0xE5,(CHAR)0x5D,(CHAR)0x5E,(CHAR)0x5F,(CHAR)0x5A,(CHAR)0x59,(CHAR)0x5B,(CHAR)0xFF,(CHAR)0xE0 };
	//	ԭʼָ��
	//	004C0000 - push ebx
	//	004C0001 - push ecx
	//	004C0002 - push edx
	//	004C0003 - push edi
	//	004C0004 - push esi
	//	004C0005 - push ebp
	//	004C0006 - mov ebp, esp
	//	004C0008 - sub esp, 40
	//	004C000B - mov eax, fs:[00000030]
	//	004C0011 - mov eax, [eax + 0C]
	//	004C0014 - mov eax, [eax + 0C]
	//	004C0017 - mov edx, [eax + 18]
	//	004C001A - mov[ebp - 04], edx
	//	004C001D - mov eax, [ebp + 18]
	//	004C0020 - mov[ebp - 08], eax
	//	004C0023 - mov esi, 004C0800
	//	004C0028 - jmp 004C0030
	//	004C002D - add esi, 08
	//	004C0030 - mov eax, [esi]
	//	004C0032 - cmp eax, 00
	//	004C0035 - je 004C004C
	//	004C003B - add eax, 05
	//	004C003E - add eax, [ebp - 04]
	//	004C0041 - cmp eax, [ebp - 08]
	//	004C0044 - jne 004C002D
	//	004C0046 - mov eax, [esi + 04]
	//	004C0049 - mov[ebp - 14], eax
	//	004C004C - mov edx, [ebp - 04]
	//	004C004F - mov eax, [edx + 3C]
	//	004C0052 - lea eax, [eax + edx]
	//	004C0055 - mov[ebp - 0C], eax
	//	004C0058 - mov eax, [eax + 00000080]
	//	004C005E - lea eax, [eax + edx]
	//	004C0061 - mov[ebp - 10], eax
	//	004C0064 - mov esi, eax
	//	004C0066 - xor ecx, ecx
	//	004C0068 - jmp 004C007C
	//	004C006D - add esi, 14
	//	004C0070 - mov eax, [esi + 10]
	//	004C0073 - cmp eax, 00
	//	004C0076 - je 004C00B6
	//	004C007C - mov eax, [esi + 10]
	//	004C007F - cmp eax, 00
	//	004C0082 - je 004C006D
	//	004C0084 - mov edi, [esi + 10]
	//	004C0087 - add edi, [ebp - 04]
	//	004C008A - jmp 004C009D
	//	004C008F - add edi, 04
	//	004C0092 - mov eax, [edi]
	//	004C0094 - cmp eax, 00
	//	004C0097 - je 004C00B4
	//	004C009D - mov eax, [edi]
	//	004C009F - cmp eax, 00
	//	004C00A2 - je 004C00B4
	//	004C00A8 - cmp[ebp - 14], ecx
	//	004C00AB - je 004C00B6
	//	004C00B1 - inc ecx
	//	004C00B2 - jmp 004C008F
	//	004C00B4 - jmp 004C006D
	//	004C00B6 - mov eax, eax
	//	004C00B8 - mov esp, ebp
	//	004C00BA - pop ebp
	//	004C00BB - pop esi
	//	004C00BC - pop edi
	//	004C00BD - pop edx
	//	004C00BE - pop ecx
	//	004C00BF - pop ebx
	//	004C00C0 - jmp eax



	*(DWORD*)(nMyCallCode + 0x24) = (DWORD)nIndexTab;

	LPVOID nMyCallHandle = pfnVirtualAlloc(NULL, _countof(nMyCallCode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	__asm
	{
		rdtsc;
		mov g_Time1, edx;
	}

	pfnRtlMoveMemory(nMyCallHandle, nMyCallCode, _countof(nMyCallCode));

	CHAR nCallCode[6] = { (CHAR)0xe8,(CHAR)0,(CHAR)0,(CHAR)0,(CHAR)0,(CHAR)0x90 };
	for (DWORD i = 0; i < nCallRecordNum; i++)
	{
		DWORD nAddress = *(DWORD*)((DWORD)nIndexTab + i * 8) + g_Bass;
		DWORD nOldProtect = 0;
		pfnVirtualProtect((LPVOID)nAddress, 6, PAGE_EXECUTE_READWRITE, &nOldProtect);
		*(DWORD*)(nCallCode + 1) = (DWORD)nMyCallHandle - nAddress - 5;
		pfnRtlMoveMemory((LPVOID)nAddress, nCallCode,_countof(nCallCode));

	}

}

//*********************************************************************************
// �޸�����VMP����
//*********************************************************************************

LPVOID HandleTab = NULL;

void _declspec(naked) VmStart()
{
	__asm {
		push esp;
		push ebp;
		push edi;
		push esi;
		push edx;
		push ecx;
		push ebx;
		push eax;
		pushf;
		pushf;
		mov ebp, esp;
		lea ebp, [ebp + 0x24];
		//0x11
		mov eax, [ebp + 0x4];
		mov eax, [eax];
		and eax, 0xFF;
		mov ebx, HandleTab;
		jmp dword ptr[eax * 0x4 + ebx];
		//0x22
		popf;
		popf;
		pop eax;
		pop ebx;
		pop ecx;
		pop edx;
		pop esi;
		pop edi;
		pop ebp;
		pop esp;
		ret 0x4;
	}
}

void _declspec(naked) Vir_Push()
{
	__asm {

		mov eax, [ebp + 0x4];
		inc eax;
		mov eax, [eax];
		push 0;
		pop dword ptr[esp - 0x4];
		lea esp, [esp - 0x4];
		mov ecx, 0x1F;
		lea esi, [esp + 0x4];
		lea edi, [esp];
		repe movsd;
		mov[ebp + 0x54], eax;
		sub ebp, 0x4;
		sub dword ptr[ebp - 0x4], 0x4;

		add[ebp + 0x4], 0x5;
		mov eax, [ebp + 0x4];
		mov eax, [eax];
		and eax, 0xFF;
		cmp eax, 0x0;
		jmp RETURN;
		mov ebx, VmStart;
		add ebx, 0x11;
		jmp ebx;
	RETURN:
		mov ebx, VmStart;
		add ebx, 0x24;
		jmp ebx;
	}
}

void _declspec(naked) Vir_Mov_Eax()
{
	__asm {

		mov eax, [ebp + 0x4];
		push eax;
		push esp;
		mov eax, [ebp + 0x4];
		pop ebx;
		mov esp, ebx;
		pop eax;
		push dword ptr[eax + 0x1];
		pushf;
		inc esp;
		lea esp, [esp + 0x1];
		pop dword ptr[ebp - 0x20];


		add[ebp + 0x4], 0x5;
		mov eax, [ebp + 0x4];
		mov eax, [eax];
		and eax, 0xFF;
		cmp eax, 0x0;
		jmp RETURN;
		mov ebx, VmStart;
		add ebx, 0x11;
		jmp ebx;
	RETURN:
		mov ebx, VmStart;
		add ebx, 0x24;
		jmp ebx;	
	}
}

void _declspec(naked) Vir_Mov_Ebx()
{
	__asm {

		mov eax, [ebp + 0x4];
		push eax;
		push esp;
		mov eax, [ebp + 0x4];
		pop ebx;
		mov esp, ebx;
		pop eax;
		push dword ptr[eax + 0x1];
		pushf;
		inc esp;
		lea esp, [esp + 0x1];
		pop dword ptr[ebp - 0x1c];


		add[ebp + 0x4], 0x5;
		mov eax, [ebp + 0x4];
		mov eax, [eax];
		and eax, 0xFF;
		cmp eax, 0x0;
		je RETURN;
		mov ebx, VmStart;
		add ebx, 0x11;
		jmp ebx;
	RETURN:
		mov ebx, VmStart;
		add ebx, 0x24;
		jmp ebx;	
	}
}

void _declspec(naked) Vir_Mov_Ecx()
{
	__asm {

		mov eax, [ebp + 0x4];
		push eax;
		push esp;
		mov eax, [ebp + 0x4];
		pop ebx;
		mov esp, ebx;
		pop eax;
		push dword ptr[eax + 0x1];
		pushf;
		inc esp;
		lea esp, [esp + 0x1];
		pop dword ptr[ebp - 0x18];


		add[ebp + 0x4], 0x5;
		mov eax, [ebp + 0x4];
		mov eax, [eax];
		and eax, 0xFF;
		cmp eax, 0x0;
		je RETURN;
		mov ebx, VmStart;
		add ebx, 0x11;
		jmp ebx;
	RETURN:
		mov ebx, VmStart;
		add ebx, 0x24;
		jmp ebx;	
	}
}

void _declspec(naked) Vir_Mov_Edx()
{
	__asm {

		mov eax, [ebp + 0x4];
		push eax;
		push esp;
		mov eax, [ebp + 0x4];
		pop ebx;
		mov esp, ebx;
		pop eax;
		push dword ptr[eax + 0x1];
		pushf;
		inc esp;
		lea esp, [esp + 0x1];
		pop dword ptr[ebp - 0x14];


		add[ebp + 0x4], 0x5;
		mov eax, [ebp + 0x4];
		mov eax, [eax];
		and eax, 0xFF;
		cmp eax, 0x0;
		je RETURN;
		mov ebx, VmStart;
		add ebx, 0x11;
		jmp ebx;
	RETURN:
		mov ebx, VmStart;
		add ebx, 0x24;
		jmp ebx;	
	}
}

void _declspec(naked) Vir_Mov_Esi()
{
	__asm {

		mov eax, [ebp + 0x4];
		push eax;
		push esp;
		mov eax, [ebp + 0x4];
		pop ebx;
		mov esp, ebx;
		pop eax;
		push dword ptr[eax + 0x1];
		pushf;
		inc esp;
		lea esp, [esp + 0x1];
		pop dword ptr[ebp - 0x10];


		add[ebp + 0x4], 0x5;
		mov eax, [ebp + 0x4];
		mov eax, [eax];
		and eax, 0xFF;
		cmp eax, 0x0;
		je RETURN;
		mov ebx, VmStart;
		add ebx, 0x11;
		jmp ebx;
	RETURN:
		mov ebx, VmStart;
		add ebx, 0x24;
		jmp ebx;	
	}
}

void _declspec(naked) Vir_Mov_Edi()
{
	__asm {

		mov eax, [ebp + 0x4];
		push eax;
		push esp;
		mov eax, [ebp + 0x4];
		pop ebx;
		mov esp, ebx;
		pop eax;
		push dword ptr[eax + 0x1];
		pushf;
		inc esp;
		lea esp, [esp + 0x1];
		pop dword ptr[ebp - 0xc];


		add[ebp + 0x4], 0x5;
		mov eax, [ebp + 0x4];
		mov eax, [eax];
		and eax, 0xFF;
		cmp eax, 0x0;
		je RETURN;
		mov ebx, VmStart;
		add ebx, 0x11;
		jmp ebx;
	RETURN:
		mov ebx, VmStart;
		add ebx, 0x24;
		jmp ebx;	
	}
}

void _declspec(naked) Vir_Mov_Ebp()
{
	__asm {

		mov eax, [ebp + 0x4];
		push eax;
		push esp;
		mov eax, [ebp + 0x4];
		pop ebx;
		mov esp, ebx;
		pop eax;
		push dword ptr[eax + 0x1];
		pushf;
		inc esp;
		lea esp, [esp + 0x1];
		pop dword ptr[ebp - 0x8];


		add[ebp + 0x4], 0x5;
		mov eax, [ebp + 0x4];
		mov eax, [eax];
		and eax, 0xFF;
		cmp eax, 0x0;
		je RETURN;
		mov ebx, VmStart;
		add ebx, 0x11;
		jmp ebx;
	RETURN:
		mov ebx, VmStart;
		add ebx, 0x24;
		jmp ebx;	
	}
}

void _declspec(naked) Vir_Mov_Esp()
{
	__asm {

		mov eax, [ebp + 0x4];
		push eax;
		push esp;
		mov eax, [ebp + 0x4];
		pop ebx;
		mov esp, ebx;
		pop eax;
		push dword ptr[eax + 0x1];
		pushf;
		inc esp;
		lea esp, [esp + 0x1];
		pop dword ptr[ebp - 0x4];


		add[ebp + 0x4], 0x5;
		mov eax, [ebp + 0x4];
		mov eax, [eax];
		and eax, 0xFF;
		cmp eax, 0x0;
		je RETURN;
		mov ebx, VmStart;
		add ebx, 0x11;
		jmp ebx;
	RETURN:
		mov ebx, VmStart;
		add ebx, 0x24;
		jmp ebx;	
	}
}

void VmpCode()
{
	__asm
	{
		rdtsc;
		mov g_Time2, edx;
	}

	int nImageBass = g_Bass;;
	int nOldImageBass = GetDosSubHeader((char*)g_Bass)->nOldImageBass;
	
	//g_Check = (g_Time2 - g_Time1 >= 1);

	IMAGE_SECTION_HEADER* nOpcodeSection = GetSection((char*)g_Bass, "OPCODE");

	char *nByte = (char*)(nOpcodeSection->VirtualAddress + (DWORD)g_Bass + g_Check);

	int nCodeRecordNum = *(int*)nByte;
	nByte += 4;

	int *nRva = (int*)pfnVirtualAlloc(NULL, nCodeRecordNum * 4, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	char *nVirCode = (char*)pfnVirtualAlloc(NULL, nCodeRecordNum * 5, MEM_COMMIT, PAGE_EXECUTE_READWRITE);;

	pfnRtlZeroMemory(nRva, nCodeRecordNum * 4);
	pfnRtlZeroMemory(nVirCode, nCodeRecordNum * 5);

	pfnRtlMoveMemory(nRva, nByte, nCodeRecordNum * 4);
	pfnRtlMoveMemory(nVirCode, nByte + nCodeRecordNum * 4, nCodeRecordNum * 5);

	pfnRtlZeroMemory(nByte - 4, nCodeRecordNum * 4 + nCodeRecordNum * 5 + 4);


	//�����Handle
	//LPVOID nVir_Push = pfnVirtualAlloc(0, 1, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	//char nVir_Push_Code[] = { 0x8B,0x45,0x04,0x40,0x8B,0x00,0x6A,0x00,0x8F,0x44,0x24,0xFC,0x8D,0x64,0x24,0xFC,0xB9,0x1F,0x00,0x00,0x00,0x8D,0x74,0x24,0x04,0x8D,0x3C,0x24,0xF3,0xA5,0x89,0x45,0x54,0x83,0xED,0x04,0x83,0x6D,0xFC,0x04,0xE9,0x1E,0x00,0x00,0x00,0x8B,0x45,0x04,0x50,0x54,0x8B,0x45,0x04,0x5B,0x8B,0xE3,0x58,0xFF,0x70,0x01,0x66,0x9C,0x44,0x8D,0x64,0x24,0x01,0x8F,0x45,0xE0,0xE9,0x00,0x00,0x00,0x00,0x66,0x9D,0x66,0x9D,0x58,0x5B,0x59,0x5A,0x5E,0x5F,0x5D,0x5C,0xC2,0x04 };

	//pfnRtlMoveMemory(nVir_Push, nVir_Push_Code, _countof(nVir_Push_Code));


	//�����Handle��
	HandleTab = pfnVirtualAlloc(0, 1, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	int nHandleTableCode[] = { 0,(int)Vir_Push,(int)Vir_Mov_Eax,(int)Vir_Mov_Ebx,(int)Vir_Mov_Ecx ,
		(int)Vir_Mov_Edx,(int)Vir_Mov_Esi,(int)Vir_Mov_Edi,(int)Vir_Mov_Ebp,(int)Vir_Mov_Esp };

	pfnRtlMoveMemory(HandleTab, nHandleTableCode, _countof(nHandleTableCode) * 4);


	//��������
	//nMyVmAddress = pfnVirtualAlloc(0, 1, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	//char nMyVmCode[] = { 0x54,0x55,0x57,0x56,0x52,0x51,0x53,0x50,0x66,0x9C,0x66,0x9C,0x8B,0xEC,0x8D,0x6D,0x24,0x8B,0x45,0x04,0x8B,0x00,0x25,0xFF,0x00,0x00,0x00,0xFF,0x24,0x85,0x00,0x08,0xFB,0x01 };

	//*(int*)(nMyVmCode + _countof(nMyVmCode) - 4) = (int)HandleTab;
	//pfnRtlMoveMemory(nMyVmAddress, nMyVmCode, _countof(nMyVmCode));


	//���������������
	LPVOID nCallCodeAddress = pfnVirtualAlloc(0, nCodeRecordNum * 23, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	char *nCallTable = (char*)pfnVirtualAlloc(0, nCodeRecordNum * 23, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	pfnRtlZeroMemory(nCallTable, nCodeRecordNum * 23);

	char nCallCode[23]{ (CHAR)0x8d,(CHAR)0x64,(CHAR)0x24,(CHAR)0xb0, (CHAR)0x68,(CHAR)0,(CHAR)0,(CHAR)0,(CHAR)0,(CHAR)0xe8,(CHAR)0,(CHAR)0,(CHAR)0,(CHAR)0,(CHAR)0x8d,(CHAR)0x64,(CHAR)0x24,(CHAR)0x50,(CHAR)0xe9,(CHAR)0,(CHAR)0,(CHAR)0,(CHAR)0 };
	for (int i = 0; i < nCodeRecordNum; i++)
	{
		int nPathAddress = nImageBass + *(nRva + i);

		*(int*)(nCallCode + 5) = (int)nVirCode + i + i * 4;
		*(int*)(nCallCode + 10) = (int)VmStart - ((int)nCallCodeAddress + 9 + i * 23) - 5;
		*(int*)(nCallCode + 19) = nPathAddress - ((int)nCallCodeAddress + 18 + i * 23);

		//push ����OpCode
		//call ��������
		//jmp  �ص�ԭ����ַ

		pfnRtlMoveMemory(nCallTable + i * 23, nCallCode, 23);
	}

	pfnRtlMoveMemory(nCallCodeAddress, nCallTable, nCodeRecordNum * 23);
	pfnVirtualFree(nCallTable, nCodeRecordNum * 23, MEM_RELEASE);


	//�޸�nop����ĳ�jmpָ��
	__asm
	{
		rdtsc;
		mov g_Time1, edx;
	}

	char nJmpCode[5]{ (char)0xe9 };
	for (int i = 0; i < nCodeRecordNum; i++)
	{
		int nPathAddress = nImageBass + *(nRva + i);

		*(int*)(nJmpCode + 1) = ((int)nCallCodeAddress + i * 23) - nPathAddress - 5;

		DWORD nOldProtect = 0;
		pfnVirtualProtect((LPVOID)nPathAddress, 5, PAGE_EXECUTE_READWRITE, &nOldProtect);

		pfnRtlMoveMemory((LPVOID)nPathAddress, nJmpCode, 5);
	}
	__asm
	{
		rdtsc;
		mov g_Time2, edx;
	}


	//�޸�����ָ����ض�λ
	DWORD nRelTabRva = (GetOptionHeader((char*)g_Bass)->DataDirectory[5].VirtualAddress);
	DWORD nRelSize = (GetOptionHeader((char*)g_Bass)->DataDirectory[5].Size);
	if (nRelTabRva == 0)return;

	IMAGE_BASE_RELOCATION* pRelTab = (IMAGE_BASE_RELOCATION*)(nRelTabRva + g_Bass);

	//g_Check = (g_Time2 - g_Time1 >= 1);

	while (pRelTab->SizeOfBlock != 0)
	{
		struct TypeOffset
		{
			WORD ofs : 12;
			WORD type : 4;
		};

		TypeOffset* pTypeOffset = NULL;
		pTypeOffset = (TypeOffset*)(pRelTab + 1);

		DWORD dwCount = (pRelTab->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;

		while (pTypeOffset->ofs)
		{
			int nOld = 0;
			int nNew = 0;

			if (pTypeOffset->type == 3)
			{
				BOOL nHave = FALSE;
				for (int i = 0; i < nCodeRecordNum; i++)
				{
					if (*(nRva + i) + 1 == pRelTab->VirtualAddress + pTypeOffset->ofs)
					{
						pfnRtlMoveMemory(&nOld, (LPVOID)((int)nVirCode + i + i * 4 + 1+ g_Check), 4);
						nNew = nOld - nOldImageBass + nImageBass;
						pfnRtlMoveMemory((LPVOID)((int)nVirCode + i + i * 4 + 1), &nNew, 4);
						nHave = TRUE;
						break;
					}
				}
				//if (nHave == FALSE)
				//{
				//	pfnRtlMoveMemory(&nOld, (LPVOID)(nImageBass + pRelTab->VirtualAddress + pTypeOffset->ofs), 4);
				//	//ReadProcessMemory(pi.hProcess, (LPVOID)(nImageBass + pRelTab->VirtualAddress + pTypeOffset->ofs), &nOld, 4, 0);
				//	nNew = nOld - 0x400000 + nImageBass;
				//	pfnRtlMoveMemory((LPVOID)(nImageBass + pRelTab->VirtualAddress + pTypeOffset->ofs), &nNew, 4);
				//	//WriteProcessMemory(pi.hProcess, (LPVOID)(nImageBass + pRelTab->VirtualAddress + pTypeOffset->ofs), &nNew, 4, 0);
				//}
			}

			pTypeOffset++;
		}

		// �õ���һ���ض�λ����׵�ַ
		pRelTab = (IMAGE_BASE_RELOCATION*)((LPBYTE)pRelTab + pRelTab->SizeOfBlock);
	}



}

//*********************************************************************************
// �޸������ض�λ��
//*********************************************************************************
void _declspec(naked) FixMyReloc()
{
	_asm{
		push ebp;
		mov ebp, esp;
		sub esp, 0x40;
		mov eax, FS:[0x30];
		mov eax, [eax + 0xc];
		mov eax, [eax + 0xc];
		mov edx, [eax + 0x18];
		mov[ebp - 0x4], edx;//���ػ�ַ
		mov eax, [edx + 0x3c];//��ȡNTͷRVA
		lea eax, [eax + edx];
		mov[ebp - 0x18], eax;//NTͷVA
		mov eax, [ebp - 0x4];//���ػ�ַ
		mov eax, [eax + 0x48];//����ض�λ��RVA
		add eax, [ebp - 0x4]; //���ϻ�ַ�õ��ض�λ��VA
		mov[ebp - 0x8], eax;//�ض�λָ��
	START:
		mov eax, [ebp - 0x8];//��ȡ�ض�λָ��
		mov ebx, [eax];
		mov[ebp - 0xc], ebx;//��ҳ�׵�ַ
		mov ebx, [eax + 4];
		mov[ebp - 0x10], ebx;//�ߴ�
		sub ebx, 8;
		shr ebx, 1;
		mov[ebp - 0x14], ebx;//ƫ������
		cmp[ebp - 0x10], 0;//�жϳߴ��Ƿ�Ϊ0
		je END;
		push[ebp - 0x4];//������ػ�ַ
		push[ebp - 0x18];//����NTͷVA
		call GETINFO;
		mov[ebp - 0x1c], eax;//������RVA
		mov[ebp - 0x20], ebx;//���������RVA
		mov[ebp - 0x24], ecx;//���ԭʼ���ػ�ַ
		mov[ebp - 0x28], edx;//��ÿ�ԭʼ.text����RVA
		mov ecx, [ebp - 0x14];//����ѭ������
		mov esi, [ebp - 0x8];//��ȡ�ض�λָ��
		add esi, 8;
		jmp LOOPSTART;

	LOOPHEAD:
		add esi, 2;
		dec ecx;
		cmp ecx, 0;
		je LOOPEND;
	LOOPSTART:
		xor ebx, ebx;
		mov bx, [esi];//��ȡƫ��
		cmp bx, 0;
		je LOOPHEAD;
		and bx, 0xF000;//��ȡtype
		cmp bx, 0x3000;
		jne LOOPHEAD;
		mov eax, [ebp - 0xc];//��ȡ��ҳ�׵�ַ
		sub eax, [ebp - 0x28];//��ȥԭ����.text�����׵�ַ
		add eax, [ebp - 0x1c];//�����������׵�ַ

		xor ebx, ebx;
		mov bx, [esi];//��ȡƫ��
		and bx, 0xFFF;//��ȡoffset
		add eax, ebx;//����ƫ��
		add eax, [ebp - 0x4];//���ϼ��ػ�ַ
		mov edi, eax;//������Ҫ�޸���λ��
		cmp eax, [ebp - 0x20];//�ж���Ҫ�޸��ĵ�ַ�Ƿ񳬳�����
		ja LOOPHEAD;

		mov eax, [eax];//��ȡ��Ҫ�޸���ƫ��
		sub eax, [ebp - 0x24];//��ȥԭʼ���ػ�ַ
		add eax, [ebp - 0x4];//�����µļ��ػ�ַ
		mov[edi], eax;//�޸��ض�λ����
		cmp ecx, 0;
		ja LOOPHEAD;
	LOOPEND:


		mov eax, [ebp - 0x10];//ȡ���ߴ�
		add[ebp - 0x8], eax;//�ض�λָ����ϳߴ磬�����һ���ض�λ��
		jmp START;
	END:

		mov esp, ebp;
		pop ebp;
		ret;
		//28



		//**************************************************************************
	//GETRELOCADDRESS:
	//	push ebp;
	//	mov ebp, esp;
	//	sub esp, 0x40;
	//	mov eax, [ebp + 0x8];


	//	add eax, 0x6;//�õ����α�������ַ
	//	mov ax, [eax];//�õ����α�����
	//	mov[ebp - 0x4], 0;
	//	mov[ebp - 0x4], ax;

	//	mov eax, [ebp + 8];
	//	add eax, 0xF8;//�õ����α��׵�ַ

	//	mov edx, [ebp - 0x4];//��������
	//	jmp FINDRELOCSTART;

	//FINDRELOCHEAD:
	//	add eax, 0x28;//��ȡ��һ������
	//	dec edx;//����-1
	//	cmp edx, 0;
	//	je FINDRELOCEND;//����0����

	//FINDRELOCSTART:
	//	mov ecx, 0x5;//�Ƚ�5���ַ�
	//	mov esi, eax;
	//	call STRRELOCNEXT;
	//	_asm _emit(0x52) _asm _emit(0x45)//RELOC
	//	_asm _emit(0x4C) _asm _emit(0x4F)
	//	_asm _emit(0x43) _asm _emit(0x00)
	//STRRELOCNEXT:
	//	pop edi;
	//	repe cmpsb;
	//	je FINDRELOCEND;//��������ѭ��
	//	jmp FINDRELOCHEAD;
	//FINDRELOCEND:
	//	sub esi, 0x5;//��ԭesiλ��
	//	lea esi, [esi + 0xc];
	//	mov eax, [esi];//�������RVA
	//	mov esp, ebp;
	//	pop ebp;
	//	ret 0x4;
		//**************************************************************************


	
	
		//**************************************************************************
	GETINFO://��ȡ��������RVA����ȡ�����������VA����ȡĬ�ϼ��ػ�ַ����ȡԭʼ���ػ�ַ
		push ebp;
		mov ebp, esp;
		sub esp, 0x40;
		mov eax, [ebp + 0x8];
		add eax, 0x6;//�õ����α�������ַ
		mov ax, [eax];//�õ����α�����
		mov[ebp - 0x4], 0;
		mov[ebp - 0x4], ax;

		mov eax, [ebp + 8];
		add eax, 0xF8;//�õ����α��׵�ַ

		mov edx, [ebp - 0x4];//��������
		jmp FINDSTART;

	FINDHEAD:
		add eax, 0x28;//��ȡ��һ������
		dec edx;//����-1
		cmp edx, 0;
		je FINDEND;//����0����

	FINDSTART:
		mov ecx, 0x8;//�Ƚ�8���ַ�
		mov esi, eax;
		call STRNEXT;
		_asm _emit(0x48) _asm _emit(0x4F)//HOCKPACK
		_asm _emit(0x43) _asm _emit(0x4B)
		_asm _emit(0x50) _asm _emit(0x41)
		_asm _emit(0x43) _asm _emit(0x4B)
		_asm _emit(0x00);
	STRNEXT:
		pop edi;
		repe cmpsb;
		je FINDEND;//��������ѭ��
		jmp FINDHEAD;
	FINDEND:
		sub esi, 0x8;//��ԭesiλ��

		lea esi, [esi + 0xc];
		mov eax, [esi];//�������RVA
		mov ebx, [esi - 0x4];//����������ڴ��д�С
		add ebx, eax;//����������ڴ������RVA
		add ebx, [ebp + 0xc];//���ϼ��ػ�ַ���VA

		//mov edx, [ebp + 0x8];
		//add edx, 0x70;
		//mov ecx, [edx];//���ԭʼ���ػ�ַ
		//			   //mov ecx, 0x400000;//���ԭʼ���ػ�ַ

		//mov edx, [ebp + 0x8];
		//add edx, 0x58;
		//mov edx, [edx];//��ÿ�ԭʼ.text���ε�RVA


		mov ecx, [ebp + 0xc];//��ü��ػ�ַ
		mov ecx, [ecx + 0x40];//���ԭʼ���ػ�ַ

		mov edx, [ebp + 0xc];//��ü��ػ�ַ
		mov edx, [edx + 0x44];//��ÿ�ԭʼ.text���ε�RVA

		mov esp, ebp;
		pop ebp;
		ret 0x8;
		//**************************************************************************

	}

}

//*********************************************************************************
// �޸����ӿǳ����ض�λ��
//*********************************************************************************
void FixRelocTable()
{
	int nRelocRva = (GetOptionHeader((char*)g_Bass)->DataDirectory[5].VirtualAddress);
	if (nRelocRva == 0)return;

	IMAGE_BASE_RELOCATION* pRelTab = (IMAGE_BASE_RELOCATION*)(nRelocRva + g_Bass);
	while (pRelTab->SizeOfBlock != 0)
	{
		struct TypeOffset
		{
			WORD ofs : 12;
			WORD type : 4;
		};

		TypeOffset* pTypeOffset = NULL;
		pTypeOffset = (TypeOffset*)(pRelTab + 1);

		DWORD dwCount = (pRelTab->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;


		DWORD nOldProtect = 0;

		for (DWORD i = 0; i < dwCount; i++)
		{
			if (pTypeOffset->type == 3)
			{
				int *nFixAddress = (int*)(pTypeOffset->ofs + pRelTab->VirtualAddress + g_Bass);

				pfnVirtualProtect(nFixAddress, 4, PAGE_EXECUTE_READWRITE, &nOldProtect);

				*nFixAddress = *nFixAddress - 0x400000 + g_Bass;
			}

			pTypeOffset++;
		}


		//�õ���һ���ض�λ����׵�ַ
		pRelTab = (IMAGE_BASE_RELOCATION*)((LPBYTE)pRelTab + pRelTab->SizeOfBlock);
	}
}

//*********************************************************************************
// ����TLS��
//*********************************************************************************
void CallTls()
{
	DWORD nTlsHeadRva = GetOptionHeader((char*)g_Bass)->DataDirectory[9].VirtualAddress;
	if (nTlsHeadRva == 0)return;

	PIMAGE_TLS_DIRECTORY pTlsTab = (PIMAGE_TLS_DIRECTORY)(nTlsHeadRva + g_Bass);

	if (pTlsTab->AddressOfCallBacks == 0)return;

	DWORD nTlsCallBack = *(DWORD*)pTlsTab->AddressOfCallBacks;
	__asm 
	{
		cmp nTlsCallBack, 0;
		je ENDCALL;
		push 0;
		push 1;
		push g_Bass;
		call nTlsCallBack;
	ENDCALL:
	}

}

extern"C"
{
	_declspec(dllexport) _declspec(naked) void ShellEncry()
	{
		_asm pushad;

		FixMyReloc();//�޸��������ض�λ����

		GetPeModuleHandle();//��ȡ���̼��ص�ģ����
		ShellConfig.nOEP += g_Bass;

		GetApiLibrary();//��ȡ�����API����

		SetFileHeaderProtect(true);//�ļ�ͷ���ÿ��޸�

		if (ShellConfig.nEncryptCode) MyDialogBox();//���������

		if (ShellConfig.nPackData) UpackCode();//��ѹ����

		if (ShellConfig.nEncryptCode) DecryptCode();//���ܴ���

		FixDataDir();//�޸�����Ŀ¼��

		if (ShellConfig.nRandImageBass)FixRelocTable();//�޸��ض�λ��

		if (ShellConfig.nIatEncrypt) 
		{
			FixImportTable_Encrypt();//�޸������
			FixCallCode();
		}
		else FixImportTable_Normal();//�޸������

		if (ShellConfig.nVmp) VmpCode();//����VMP

		SetFileHeaderProtect(false);//�ļ�ͷ���ò����޸�

		CallTls();

		_asm popad;
		_asm jmp ShellConfig.nOEP;
	}
}