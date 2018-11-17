#include "stdafx.h"
#include "MyShell.h"
#include "MyShellDlg.h"
#include "afxdialogex.h"
#include <windows.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


CMyShellDlg::CMyShellDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_MYSHELL_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CMyShellDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_CHECK1, m_Check_PackData);
	DDX_Control(pDX, IDC_CHECK3, m_Check_IatEncrypt);
	DDX_Control(pDX, IDC_CHECK2, m_Check_Vmp);
	DDX_Control(pDX, IDC_CHECK4, m_Check_RandImageBass);
	DDX_Control(pDX, IDC_CHECK5, m_Check_EncryptCode);
	DDX_Control(pDX, IDC_EDIT1, m_Edit_PassWord);
	DDX_Control(pDX, IDC_BUTTON1, m_Button_OpenFile);
	DDX_Control(pDX, IDC_BUTTON2, m_Button_Run);
	DDX_Control(pDX, IDC_BUTTON3, m_Button_About);
	DDX_Control(pDX, IDC_STATIC_FILEPATH, m_Static_FilePath);
	DDX_Control(pDX, IDC_STATIC_FILESIZE, m_Static_FileSize);
	DDX_Control(pDX, IDC_STATIC_TIP, m_Static_Tip);
	DDX_Control(pDX, IDC_PROGRESS1, m_Progress_File);
	DDX_Control(pDX, IDC_STATIC_PACKSIZE, m_Static_PackSize);
	DDX_Control(pDX, IDC_CHECK6, m_Check_FixIco);
	DDX_Control(pDX, IDC_BUTTON4, m_Button_Start);
	DDX_Control(pDX, IDC_EDIT2, m_Edit_FilePath);
}

BEGIN_MESSAGE_MAP(CMyShellDlg, CDialogEx)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_WM_DROPFILES()
	ON_BN_CLICKED(IDC_BUTTON2, &CMyShellDlg::OnBnClickedButton2)
	ON_BN_CLICKED(IDC_BUTTON1, &CMyShellDlg::OnBnClickedButton1)
	ON_BN_CLICKED(IDC_BUTTON3, &CMyShellDlg::OnBnClickedButton3)
	ON_BN_CLICKED(IDC_BUTTON4, &CMyShellDlg::OnBnClickedButton4)
END_MESSAGE_MAP()


BOOL CMyShellDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	HMODULE hModule = LoadLibrary(TEXT("MySafeSkin.dll"));
	if (hModule)
	{
		typedef  int  (WINAPI*pMySafeSkin)(void);
		pMySafeSkin MySafeSkin;
		MySafeSkin = (pMySafeSkin)GetProcAddress(hModule, "MySafeSkin");
		MySafeSkin();
	}

	m_Check_PackData.SetCheck(TRUE);
	m_Check_Vmp.SetCheck(TRUE);
	m_Check_EncryptCode.SetCheck(TRUE);
	m_Check_IatEncrypt.SetCheck(TRUE);
	m_Check_RandImageBass.SetCheck(TRUE);
	m_Check_FixIco.SetCheck(TRUE);

	m_Edit_PassWord.SetWindowText(TEXT("15"));

	return TRUE; 
}

void CMyShellDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

HCURSOR CMyShellDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CMyShellDlg::OnDropFiles(HDROP hDropInfo)
{
	CDialogEx::OnDropFiles(hDropInfo);
	m_FilePath.GetBufferSetLength(MAX_PATH);
	DragQueryFile(hDropInfo, 0, (TCHAR*)(const TCHAR*)m_FilePath, MAX_PATH);
	DragFinish(hDropInfo);

	m_Button_OpenFile.EnableWindow(FALSE);
	m_Button_Start.EnableWindow(FALSE);
	m_Button_Run.EnableWindow(FALSE);

	StartShell();

	m_Button_Run.EnableWindow(TRUE);
	m_Button_Start.EnableWindow(TRUE);
	m_Button_OpenFile.EnableWindow(TRUE);
}

 void CMyShellDlg::StartShell()
 {
	 LoadStub(&StubConfig);

	 // 读取文件数据
	 DWORD nFileSize = 0;
	 CHAR* pFileData = GetFileData(m_FilePath, &nFileSize);
	 DWORD nOldSectionSize = nFileSize;

	 GetResources(pFileData, 0x03, &m_FileIcon);// 获取图标
	 GetResources(pFileData, 0x0E, &m_FileIconGroup);// 获取图标组
	 GetResources(pFileData, 0x10, &m_FileVersion);// 获取版本信息
	 

	 CString nTemp;
	 nTemp.Format(TEXT("%d"), nFileSize / 1024);
	 m_Edit_FilePath.SetWindowText( m_FilePath);
	 m_Static_FileSize.SetWindowText(TEXT("文件尺寸：") + nTemp + TEXT("KB"));
	 m_Static_PackSize.SetWindowText(TEXT("压缩后："));


	 // 将被加壳程序的信息保存到stub的导出结构体变量中.
	 StubConfig.pConf->nOEP = GetOptionHeader(pFileData)->AddressOfEntryPoint;
	 StubConfig.pConf->nImportVirtual = GetOptionHeader(pFileData)->DataDirectory[1].VirtualAddress;
	 StubConfig.pConf->nImportSize = GetOptionHeader(pFileData)->DataDirectory[1].Size;
	 StubConfig.pConf->nResourceVirtual = GetOptionHeader(pFileData)->DataDirectory[2].VirtualAddress;
	 StubConfig.pConf->nResourceSize = GetOptionHeader(pFileData)->DataDirectory[2].Size;
	 StubConfig.pConf->nRelocVirtual = GetOptionHeader(pFileData)->DataDirectory[5].VirtualAddress;
	 StubConfig.pConf->nRelocSize = GetOptionHeader(pFileData)->DataDirectory[5].Size;
	 StubConfig.pConf->nTlsVirtual = GetOptionHeader(pFileData)->DataDirectory[9].VirtualAddress;
	 StubConfig.pConf->nTlsSize = GetOptionHeader(pFileData)->DataDirectory[9].Size;


	 m_Static_Tip.SetWindowText(TEXT("处理VMP代码"));
	 CHAR *nVmpCode = nullptr;
	 DWORD nVmpCodeSize = 0;
	 if (m_Check_Vmp.GetCheck())
	 {
		 VmpCode(pFileData, nVmpCode, &nVmpCodeSize);//VMP保护
	 }



	 m_Static_Tip.SetWindowText(TEXT("处理IAT表"));
	 CHAR *nCallCode = nullptr;
	 DWORD nCallCodeSize = 0;
	 if (m_Check_IatEncrypt.GetCheck())
	 {
		 EncryIat(pFileData);//加密IAT表
		 m_Static_Tip.SetWindowText(TEXT("处理CALL代码"));
		 EncryptCall(pFileData, nCallCode, &nCallCodeSize);//修改所有CALL代码
	 }


	 //将VMPCODE与CALLCODE数据合并
	 if (nVmpCodeSize || nCallCodeSize)
	 {
		 DWORD nAllSize = nVmpCodeSize + nCallCodeSize;
		 CHAR *nOpcode = new CHAR[nAllSize]{};

		 if (nVmpCodeSize)//如果VMP有代码
		 {
			 memcpy_s(nOpcode, nAllSize, nVmpCode, nVmpCodeSize);
		 }
		 if (nCallCodeSize)//如果CALL有代码
		 {
			 memcpy_s(nOpcode + nVmpCodeSize, nAllSize, nCallCode, nCallCodeSize);
		 }

		 AddSection(pFileData, nFileSize, "OPCODE", nAllSize, nOpcode);

		 delete[]nOpcode;
	 }
	 if (nVmpCodeSize) delete[]nVmpCode;
	 if (nCallCodeSize) delete[]nCallCode;


	 //将选项传到壳内
	 StubConfig.pConf->nVmp = m_Check_Vmp.GetCheck();
	 StubConfig.pConf->nIatEncrypt = m_Check_IatEncrypt.GetCheck();
	 StubConfig.pConf->nEncryptCode = m_Check_EncryptCode.GetCheck();
	 StubConfig.pConf->nPackData = m_Check_PackData.GetCheck();
	 StubConfig.pConf->nRandImageBass = m_Check_RandImageBass.GetCheck();
	 StubConfig.pConf->nFixIco = (m_FileIcon.size() || m_FileIconGroup.size()) ? m_Check_FixIco.GetCheck() : false;


	 // 修正dll的重定位数据
	 IMAGE_SECTION_HEADER* pLastScn = GetLastSection(pFileData);
	 DWORD dwNewScnRva = pLastScn->VirtualAddress + Aligment(pLastScn->SizeOfRawData, GetOptionHeader(pFileData)->SectionAlignment);
	 FixStubRelocation(&StubConfig, pFileData, dwNewScnRva);
	 //AddSection(pFileData, nFileSize, "HOCKPACK", StubConfig.dwTextDataSize, StubConfig.pTextData);



	 //将壳的重定位表与代码段合并，只添加一个区段即可
	 DWORD nHockPack_RelocSize = Aligment(StubConfig.dwTextDataSize + StubConfig.dwRelocDataSize, GetOptionHeader(pFileData)->SectionAlignment);
	 CHAR *nHockPack_RelocData = new CHAR[nHockPack_RelocSize]{};
	 AssembleData(nHockPack_RelocData, StubConfig.pTextData, StubConfig.dwTextDataSize, StubConfig.pRelocData, StubConfig.dwRelocDataSize);
	 

	 //提前获取图标资源数据
	 CHAR *nResourceData = NULL;
	 DWORD nResourceSize = 0;
	 if (m_Check_FixIco.GetCheck())
	 {
		 FixResources(pFileData, nFileSize, nResourceData, nResourceSize, nHockPack_RelocData, nHockPack_RelocSize);
	 }



	 //将图标资源数据与代码段合并
	 DWORD nHockPack_Reloc_ResourceSize = nHockPack_RelocSize + nResourceSize;
	 CHAR* nHockPack_Reloc_ResourceData = new CHAR[nHockPack_Reloc_ResourceSize]{};
	 AssembleData(nHockPack_Reloc_ResourceData, nHockPack_RelocData, nHockPack_RelocSize, nResourceData, nResourceSize);


	 //添加区段
	 AddSection(pFileData, nFileSize, "HOCKPACK", nHockPack_Reloc_ResourceSize, nHockPack_Reloc_ResourceData);
	 delete[]nResourceData;
	 delete[]nHockPack_RelocData;
	 delete[]nHockPack_Reloc_ResourceData;




	 //保存部分数据到DosStub
	 GetDosSubHeader(pFileData)->nOldImageBass = GetOptionHeader(pFileData)->ImageBase;
	 GetDosSubHeader(pFileData)->nStubTextSectionRva = GetSection(StubConfig.pFileData, ".text")->VirtualAddress;
	 GetDosSubHeader(pFileData)->nStubRelocSectionRva = dwNewScnRva + StubConfig.dwTextDataSize;

	 //AddSection(pFileData, nFileSize, "RELOC", StubConfig.dwRelocDataSize, StubConfig.pRelocData);


	 // 将OEP设置到新区段中(stub.dll的代码段中).
	 // stub.dll中的一个VA转换成被加壳程序中的VA
	 // VA - stub.dll加载基址 ==> RVA
	 // RVA - stub.dll的代码段的RVA ==> 段内偏移
	 // 段内偏移 + 新区段的RVA ==> 被加壳程序中的RVA
	 DWORD stubStartRva = (DWORD)StubConfig.start;
	 stubStartRva -= (DWORD)StubConfig.pFileData;
	 stubStartRva -= GetSection(StubConfig.pFileData, ".text")->VirtualAddress;
	 stubStartRva += GetSection(pFileData, "HOCKPACK")->VirtualAddress;
	 GetOptionHeader(pFileData)->AddressOfEntryPoint = stubStartRva;

	 if (!m_Check_RandImageBass.GetCheck())
	 {
		 struct DllCharcter
		 {
			 unsigned n1 : 6;
			 unsigned bass : 1;
			 unsigned n2 : 9;
		 };
		 //去除随机基址
		 DllCharcter *nDllCharcter = (DllCharcter*)&GetOptionHeader(pFileData)->DllCharacteristics;
		 nDllCharcter->bass = 0;
	 }



	 m_Static_Tip.SetWindowText(TEXT("加密代码段"));
	 if (m_Check_EncryptCode.GetCheck())
	 {
		 EncryCode(pFileData);//加密代码段
	 }


	 //是否压缩所有数据
	 m_Static_Tip.SetWindowText(TEXT("压缩所有段"));
	 if (m_Check_PackData.GetCheck())
	 {
		 PackCode(pFileData);//压缩所有段
		 FixSection(pFileData, nFileSize);//修正压缩后的区段位置
	 }
	 
	 ClearDataDir(pFileData);//清除输局目录表


	//是否修复图标资源
	 if (StubConfig.pConf->nFixIco)
	 {
		 GetOptionHeader(pFileData)->DataDirectory[2].VirtualAddress = GetSection(pFileData, "HOCKPACK")->VirtualAddress + nHockPack_RelocSize;
		 GetOptionHeader(pFileData)->DataDirectory[2].Size = nResourceSize;
	 }


	 DWORD nNewSectionSize = GetLastSection(pFileData)->PointerToRawData + GetLastSection(pFileData)->SizeOfRawData;

	 DWORD nPack = DWORD((DOUBLE)(nNewSectionSize ) / (DOUBLE)(nOldSectionSize)*(DOUBLE)100.0);
	 nTemp.Format(TEXT("压缩后：%dKB - 压缩率：%d%%"), nNewSectionSize / 1024, 100 - nPack);
	 m_Static_PackSize.SetWindowText(nTemp);

	 	 
	 SavePeFile(pFileData, nNewSectionSize, m_FilePath);//保存文件
	 FreeFileData(pFileData);//释放内存

	 FreeLibrary((HMODULE)StubConfig.pFileData);//释放壳数据
	 memset(&StubConfig, 0, sizeof(StubConfig));

	 m_Static_Tip.SetWindowText(TEXT("处理完成"));
	 m_Progress_File.SetPos(100);
 }

//打开一个磁盘中的pe文件
HANDLE CMyShellDlg::OpenPeFile(CString path)
{
	return CreateFile(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
}

//关闭文件
void CMyShellDlg::ClosePeFile(HANDLE hFile)
{
	CloseHandle(hFile);
}

//将文件保存到指定路径中
bool CMyShellDlg::SavePeFile(char* pFileData, int nSize, CString nFileName)
{
	INT nIndex = nFileName.ReverseFind('.');

	CString nLastFileName = nFileName.Right(nFileName.GetLength() - nIndex - 1);
	nFileName = nFileName.Left(nIndex);

	nFileName += "_pack.";
	nFileName += nLastFileName;

	m_ShellFilePath = nFileName;

	HANDLE hFile = CreateFile(nFileName, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		return false;

	DWORD dwWrite = 0;
	// 将内容写入到文件
	WriteFile(hFile, pFileData, nSize, &dwWrite, NULL);
	// 关闭文件句柄
	CloseHandle(hFile);
	return dwWrite == nSize;
}

//获取文件内容和大小
char* CMyShellDlg::GetFileData(CString pFilePath, DWORD* nFileSize)
{
	// 打开文件
	HANDLE hFile = OpenPeFile(pFilePath);
	if (hFile == INVALID_HANDLE_VALUE)
		return NULL;
	// 获取文件大小
	DWORD dwSize = GetFileSize(hFile, NULL);
	if (nFileSize)
		*nFileSize = dwSize;
	// 申请对空间
	char* pFileBuff = new char[dwSize];
	memset(pFileBuff, 0, dwSize);
	// 读取文件内容到堆空间
	DWORD dwRead = 0;
	ReadFile(hFile, pFileBuff, dwSize, &dwRead, NULL);
	CloseHandle(hFile);
	// 将堆空间返回
	return pFileBuff;
}

//释放文件内容
void CMyShellDlg::FreeFileData(char* pFileData)
{
	delete[] pFileData;
}

//获取指定资源
DWORD CMyShellDlg::GetResources(char* pFileData,SIZE_T dwType, std::vector<ResourcesData>* vecData) {


	ResourcesData resData = { 0 };
	PIMAGE_RESOURCE_DIRECTORY pDirFir = nullptr;
	PIMAGE_RESOURCE_DIRECTORY pDirSec = nullptr;
	PIMAGE_RESOURCE_DIRECTORY pDirThi = nullptr;
	PIMAGE_RESOURCE_DIRECTORY_ENTRY pEntryFir = nullptr;
	PIMAGE_RESOURCE_DIRECTORY_ENTRY pEntrySec = nullptr;
	PIMAGE_RESOURCE_DIRECTORY_ENTRY pEntryThi = nullptr;
	PIMAGE_RESOURCE_DATA_ENTRY pDataEntry = nullptr;

	
	DWORD dwResTabRva = GetOptionHeader(pFileData)->DataDirectory[2].VirtualAddress;
	if (dwResTabRva == 0)
		return 0;

	pDirFir = (PIMAGE_RESOURCE_DIRECTORY)(RvaToFoa(pFileData,dwResTabRva) + pFileData);

	pEntryFir = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pDirFir + 1);
	DWORD dwSize = sizeof(IMAGE_RESOURCE_DIRECTORY);

	DWORD dwOfs = 0;
	for (int i = 0; i < pDirFir->NumberOfIdEntries + pDirFir->NumberOfNamedEntries; ++i, ++pEntryFir) {
		if (pEntryFir->Id == dwType) {
			dwSize += sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY);

			pDirSec = (PIMAGE_RESOURCE_DIRECTORY)(pEntryFir->OffsetToDirectory + (DWORD)pDirFir);
			pEntrySec = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pDirSec + 1);
			for (int j = 0; j < pDirSec->NumberOfIdEntries + pDirSec->NumberOfNamedEntries; ++j, ++pEntrySec) {
				pDirThi = (PIMAGE_RESOURCE_DIRECTORY)(pEntrySec->OffsetToDirectory + (DWORD)pDirFir);
				dwSize += sizeof(IMAGE_RESOURCE_DIRECTORY);

				pEntryThi = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pDirThi + 1);
				dwSize += sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY);

				pDataEntry = (PIMAGE_RESOURCE_DATA_ENTRY)(pEntryThi->OffsetToData + (DWORD)pDirFir);
				dwSize += sizeof(IMAGE_RESOURCE_DATA_ENTRY);
				dwSize += pDataEntry->Size;

				resData.dwSize = pDataEntry->Size;
				resData.dwId = pEntrySec->Id;
				resData.pData = (LPBYTE)malloc(resData.dwSize);
				DWORD dwDataOfs = RvaToFoa(pFileData,pDataEntry->OffsetToData);
				memcpy(resData.pData, dwDataOfs + (LPBYTE)pFileData, resData.dwSize);
				vecData->push_back(resData);
			}
		}
	}
	return dwSize;
}

//释放资源
void CMyShellDlg::FreeResources(std::vector<ResourcesData>* vecData) {
	for (auto &i : *vecData) {
		if (i.pData != nullptr)
			free(i.pData);
	}
	vecData->clear();
}

//获取DOS头
IMAGE_DOS_HEADER* CMyShellDlg::GetDosHeader(char* pFileData)
{
	return (IMAGE_DOS_HEADER *)pFileData;
}

//获取DOSSUB头
DosStub* CMyShellDlg::GetDosSubHeader(char* pFileData)
{
	return (DosStub*)(pFileData + sizeof(IMAGE_DOS_HEADER));
}

// 获取NT头
IMAGE_NT_HEADERS* CMyShellDlg::GetNtHeader(char* pFileData)
{
	return (IMAGE_NT_HEADERS*)(GetDosHeader(pFileData)->e_lfanew + (SIZE_T)pFileData);
}

//获取区段头
IMAGE_SECTION_HEADER* CMyShellDlg::GetSectionHeader(char* pFileData)
{
	return IMAGE_FIRST_SECTION(GetNtHeader(pFileData));
}

//获取文件头
IMAGE_FILE_HEADER* CMyShellDlg::GetFileHeader(char* pFileData)
{
	return &GetNtHeader(pFileData)->FileHeader;
}

//获取扩展头
IMAGE_OPTIONAL_HEADER* CMyShellDlg::GetOptionHeader(char* pFileData)
{
	return &GetNtHeader(pFileData)->OptionalHeader;
}

//获取指定名字的区段头
IMAGE_SECTION_HEADER* CMyShellDlg::GetSection(char* pFileData, char* scnName)//获取指定名字的区段
{
	// 获取区段格式
	DWORD dwScnCount = GetFileHeader(pFileData)->NumberOfSections;
	// 获取第一个区段
	IMAGE_SECTION_HEADER* pScn = IMAGE_FIRST_SECTION(GetNtHeader(pFileData));
	char buff[10] = { 0 };
	// 遍历区段
	for (DWORD i = 0; i < dwScnCount; ++i) {
		memcpy_s(buff, 8, (char*)pScn[i].Name, 8);
		// 判断是否是相同的名字
		if (strcmp(buff, scnName) == 0)
			return pScn + i;
	}
	return nullptr;
}

//获取最后一个区段头
IMAGE_SECTION_HEADER* CMyShellDlg::GetLastSection(char* pFileData)// 获取最后一个区段
{
	// 获取区段个数
	DWORD dwScnCount = GetFileHeader(pFileData)->NumberOfSections;
	// 获取第一个区段
	IMAGE_SECTION_HEADER* pScn = IMAGE_FIRST_SECTION(GetNtHeader(pFileData));
	// 得到最后一个有效的区段
	return pScn + (dwScnCount - 1);
}

//计算对齐大小
int CMyShellDlg::Aligment(int size, int aliginment)
{
	return (size) % (aliginment) == 0 ? (size) : ((size) / (aliginment)+1)* (aliginment);
}


//*********************************************************************************
//RVA转FOA：文件指针，RVA
//*********************************************************************************
int CMyShellDlg::RvaToFoa(char* pFileData, int nRva)
{
	DWORD nSectionNum = GetFileHeader(pFileData)->NumberOfSections;
	CString nRvaValue;
	CString nFoaValue;
	DWORD nFoa = 0;

	PIMAGE_SECTION_HEADER nSeltionHead = GetSectionHeader(pFileData);
	for (DWORD i = 0; i < nSectionNum; i++)
	{
		if (nRva >= (int)nSeltionHead->VirtualAddress && nRva <= (int)(nSeltionHead->VirtualAddress + nSeltionHead->Misc.VirtualSize))
		{
			nFoa = nRva - nSeltionHead->VirtualAddress + nSeltionHead->PointerToRawData;
			return nFoa;
		}
		nSeltionHead++;
	}

	return -1;
}

//*********************************************************************************
// 取函数名哈希值：函数名
//*********************************************************************************
int CMyShellDlg::GetHash(char *strFunName)
{
	unsigned int nDigest = 0;
	while (*strFunName)
	{
		nDigest = ((nDigest << 25) | (nDigest >> 7));
		nDigest = nDigest + *strFunName;
		strFunName++;
	}
	return nDigest;
}

//*********************************************************************************
// 添加新区段：文件指针，文件尺寸，新区段名，新区段尺寸，新区段数据
//*********************************************************************************
void CMyShellDlg::AddSection(char*& pFileData, DWORD&nFileSize, char* pNewSecName, int  nSecSize, void* pSecData)
{
	// 1. 修改文件头的区段个数
	GetFileHeader(pFileData)->NumberOfSections++;
	// 2. 修改新区段头
	IMAGE_SECTION_HEADER* pScn = GetLastSection(pFileData);
	// 2.1 区段名
	memcpy(pScn->Name, pNewSecName, 8);
	// 2.2 区段的大小
	// 2.2.1 实际大小
	pScn->Misc.VirtualSize = nSecSize;
	// 2.2.2 对齐后的大小
	pScn->SizeOfRawData = Aligment(nSecSize,GetOptionHeader(pFileData)->FileAlignment);
	// 2.3 区段的位置
	// 2.3.1 文件的偏移 = 对齐后的文件大小
	pScn->PointerToRawData = Aligment(nFileSize,GetOptionHeader(pFileData)->FileAlignment);

	// 2.3.2 内存的偏移 = 上一个区段的内存偏移的结束位置
	IMAGE_SECTION_HEADER* pPreSection = NULL;
	pPreSection = pScn - 1;
	pScn->VirtualAddress = pPreSection->VirtualAddress+ Aligment(pPreSection->SizeOfRawData,GetOptionHeader(pFileData)->SectionAlignment);
	// 2.4 区段的属性
	// 2.4.1 可读可写可执行
	pScn->Characteristics = 0xE00000E0;
	// 3. 设置扩展头中映像大小.
	GetOptionHeader(pFileData)->SizeOfImage =pScn->VirtualAddress + pScn->SizeOfRawData;

	// 4. 重新分配更大的内存空间来保存新的区段数据
	int nNewSize = pScn->PointerToRawData + pScn->SizeOfRawData;
	char* pBuff = new char[nNewSize];
	memcpy(pBuff, pFileData, nFileSize);
	memcpy(pBuff + pScn->PointerToRawData,pSecData,pScn->Misc.VirtualSize);
	FreeFileData(pFileData);

	// 修改文件大小
	pFileData = pBuff;
	nFileSize = nNewSize;
}

void CMyShellDlg::AddNullSection(char* pFileData, DWORD nFileSize, char* pNewSecName)
{
	// 1. 修改文件头的区段个数
	GetFileHeader(pFileData)->NumberOfSections++;
	// 2. 修改新区段头
	IMAGE_SECTION_HEADER* pScn = GetLastSection(pFileData);
	// 2.1 区段名
	memcpy(pScn->Name, pNewSecName, 8);
	// 2.2 区段的大小
	// 2.2.1 实际大小
	pScn->Misc.VirtualSize = 0;
	// 2.2.2 对齐后的大小
	pScn->SizeOfRawData = 0;
	// 2.3 区段的位置
	// 2.3.1 文件的偏移 = 对齐后的文件大小
	pScn->PointerToRawData = Aligment(nFileSize, GetOptionHeader(pFileData)->FileAlignment);

	// 2.3.2 内存的偏移 = 上一个区段的内存偏移的结束位置
	IMAGE_SECTION_HEADER* pPreSection = NULL;
	pPreSection = pScn - 1;
	pScn->VirtualAddress = pPreSection->VirtualAddress + Aligment(pPreSection->SizeOfRawData, GetOptionHeader(pFileData)->SectionAlignment);
	// 2.4 区段的属性
	// 2.4.1 可读可写可执行
	pScn->Characteristics = 0xE00000E0;
}

//*********************************************************************************
// 合并数据：返回新数据指针，合并数据1指针，合并数据1尺寸，合并数据2指针，合并数据2尺寸
//*********************************************************************************
void CMyShellDlg::AssembleData(PCHAR &nNewSection ,char* pDestSection,int nDestDataSize, char* pSrcSection, int nSrcDataSize)
{
	DWORD nNewSize = nDestDataSize + nSrcDataSize;
	memcpy_s(nNewSection, nNewSize, pDestSection, nDestDataSize);
	memcpy_s(nNewSection+ nDestDataSize, nNewSize, pSrcSection, nSrcDataSize);
}

//*********************************************************************************
// 载入壳DLL
//*********************************************************************************
void CMyShellDlg::LoadStub(StubDll* pStub)
{
	// 将stub.dll加载到内存
	// 加载到内存只是为了更方便地获取,以及修改
	// dll的数据,并不是真正要调用dll的代码.
	pStub->pFileData = (char*)LoadLibraryEx(L"stub.dll", NULL, DONT_RESOLVE_DLL_REFERENCES);
	if (pStub->pFileData == NULL)
	{
		MessageBox( L"DLL加载失败", 0, 0);
		ExitProcess(0);
	}
	IMAGE_SECTION_HEADER* pSectionHeader;
	pSectionHeader = GetSection(pStub->pFileData, ".text");
	pStub->pTextData = pSectionHeader->VirtualAddress + pStub->pFileData;
	pStub->dwTextDataSize = pSectionHeader->Misc.VirtualSize;

	pSectionHeader = GetSection(pStub->pFileData, ".reloc");
	pStub->pRelocData = pSectionHeader->VirtualAddress + pStub->pFileData;
	pStub->dwRelocDataSize = pSectionHeader->Misc.VirtualSize;

	// 获取两个导出符号
	pStub->pConf = (StubConf*)GetProcAddress((HMODULE)pStub->pFileData, "ShellConfig");
	pStub->start = GetProcAddress((HMODULE)pStub->pFileData, "ShellEncry");

}

//*********************************************************************************
// 修复壳的重定位项
//*********************************************************************************
void CMyShellDlg::FixStubRelocation(StubDll* stub, char* pFileData, DWORD dwNewScnRva)
{
	// 1. 先找到stub.dll中所有的重定位项.
	// 1.1 遍历重定位表.
	// 1.2 修改重定位(将DLL中所有的重定位数据改掉)
	//     重定位项 = 重定位项 - 当前加载基址 - 当前段首rva + 新的加载基址(被加壳程序的加载基址) + 新区段的段首RVA.
	IMAGE_BASE_RELOCATION* pRel =
		(IMAGE_BASE_RELOCATION*)
		(GetOptionHeader(stub->pFileData)->DataDirectory[5].VirtualAddress + (DWORD)stub->pFileData);

	DWORD pStubTextRva = GetSection(stub->pFileData, ".text")->VirtualAddress;
	while (pRel->SizeOfBlock != 0)
	{
		TypeOffset *nTypeOffest = NULL;

		nTypeOffest = (TypeOffset*)(pRel + 1);
		DWORD count = (pRel->SizeOfBlock - 8) / 2;
		for (size_t i = 0; i < count; i++)
		{
			if (nTypeOffest[i].type == 3)
			{
				DWORD fixAddr = nTypeOffest[i].ofs + pRel->VirtualAddress + (DWORD)stub->pFileData;

				DWORD oldProt = 0;
				VirtualProtect((LPVOID)fixAddr, 1, PAGE_EXECUTE_READWRITE, &oldProt);
				*(DWORD*)fixAddr -= (DWORD)stub->pFileData;
				*(DWORD*)fixAddr -= pStubTextRva;
				*(DWORD*)fixAddr += GetOptionHeader(pFileData)->ImageBase;
				*(DWORD*)fixAddr += dwNewScnRva;
				VirtualProtect((LPVOID)fixAddr, 1, oldProt, &oldProt);
			}
		}

		pRel = (IMAGE_BASE_RELOCATION*)((LPBYTE)pRel + pRel->SizeOfBlock);
	}
}

//*********************************************************************************
// 加密数据：文件指针
//*********************************************************************************
void CMyShellDlg::EncryCode(char *pFileData)
{
	CString nTempPass;
	CStringA nTempPass2;
	CHAR *nBuff = nullptr;
	m_Edit_PassWord.GetWindowText((nTempPass));
	nTempPass2 = nTempPass;
	nBuff = (CHAR*)&*nTempPass2;


	CHAR nNewBuff_64[17];
	CHAR nNewBuff_32L[9];
	CHAR nNewBuff_32R[9];
	ZeroMemory(nNewBuff_64, _countof(nNewBuff_64));;
	ZeroMemory(nNewBuff_32L, _countof(nNewBuff_32L));;
	ZeroMemory(nNewBuff_32R, _countof(nNewBuff_32R));;

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

	LONGLONG nPassWord_64 = 0;;
	LONGLONG nPassWord_32L = 0;;
	LONGLONG nPassWord_32R = 0;;
	StrToInt64ExA(nNewBuff_64, 1, &nPassWord_64);
	StrToInt64ExA(nNewBuff_32L, 1, &nPassWord_32L);
	StrToInt64ExA(nNewBuff_32R, 1, &nPassWord_32R);



	DWORD dwScnCount = GetFileHeader(pFileData)->NumberOfSections;
	IMAGE_SECTION_HEADER* pScn = GetSectionHeader(pFileData);

	for (DWORD i = 0; i < dwScnCount - 1; i++)//除了HOCKPACK段不加密
	{
		DWORD nDataSize = pScn->SizeOfRawData;
		if (nDataSize)
		{

			LONGLONG *nSectionLongLong = (LONGLONG*)(pScn->PointerToRawData + (DWORD)pFileData);

			for (DWORD i = 0; i < pScn->SizeOfRawData / 8; i++)
			{
				DWORD *nSectionDword = (DWORD*)&nSectionLongLong[i];
				nSectionDword[0] = nSectionDword[0] ^ (DWORD)nPassWord_32L;
				nSectionDword[1] = nSectionDword[1] ^ (DWORD)nPassWord_32R;

				nSectionLongLong[i] = nSectionLongLong[i] ^ nPassWord_64;

			}
		}

		pScn++;
	}

	GetOptionHeader(pFileData)->DataDirectory[2].VirtualAddress = 0;
	GetOptionHeader(pFileData)->DataDirectory[2].Size = 0;

}

//*********************************************************************************
// 压缩数据：文件指针
//*********************************************************************************
void CMyShellDlg::PackCode(char *pFileData)
{

	DWORD dwScnCount = GetFileHeader(pFileData)->NumberOfSections;
	IMAGE_SECTION_HEADER* pScn = GetSectionHeader(pFileData);

	m_Progress_File.SetStep(dwScnCount);

	for (DWORD i = 0; i < dwScnCount - 1; i++)//除了HOCKPACK段不压缩
	{
		m_Progress_File.StepIt();

		DWORD nDataSize = pScn->SizeOfRawData;
		if (nDataSize)
		{
			char *nSectionByte = (char*)(pScn->PointerToRawData + (DWORD)pFileData);


			char *nWorkMem = (char*)malloc(aP_workmem_size(nDataSize));
			char *nPackData = (char*)malloc(aP_max_packed_size(nDataSize));

			size_t nPackSize = aPsafe_pack(nSectionByte, nPackData, nDataSize, nWorkMem, NULL, NULL);

			memset(nSectionByte, 0, pScn->SizeOfRawData);

			memcpy_s(nSectionByte, pScn->SizeOfRawData, nPackData, nPackSize);

			pScn->SizeOfRawData = nPackSize;

			free(nPackData);
			free(nWorkMem);
		}

		pScn++;
	}

	GetOptionHeader(pFileData)->DataDirectory[2].VirtualAddress = 0;
	GetOptionHeader(pFileData)->DataDirectory[2].Size = 0;

}

//*********************************************************************************
// 修复压缩后的区段：文件指针，返回文件尺寸
//*********************************************************************************
void CMyShellDlg::FixSection(char *pFileData, DWORD&nFileSize)
{


	DWORD dwScnCount = GetFileHeader(pFileData)->NumberOfSections;
	IMAGE_SECTION_HEADER* pScn = GetSectionHeader(pFileData);
	DWORD nFileAligment = GetOptionHeader(pFileData)->FileAlignment;

	for (DWORD i = 0; i < dwScnCount - 1; i++)
	{
		if (pScn->PointerToRawData)
		{
			DWORD nSectionAligment = Aligment(pScn->SizeOfRawData, nFileAligment);
			IMAGE_SECTION_HEADER* pTempScn = pScn + 1;

			DWORD nTempDataSize = pTempScn->SizeOfRawData;
			CHAR *nTempData = new CHAR[nTempDataSize]{};
			memcpy_s(nTempData, nTempDataSize, pFileData + pTempScn->PointerToRawData, nTempDataSize);

			pTempScn->PointerToRawData = pScn->PointerToRawData + nSectionAligment;

			memcpy_s(pFileData + pTempScn->PointerToRawData, nTempDataSize, nTempData, nTempDataSize);

			delete[]nTempData;
		}

		pScn++;
	}

	pScn = GetLastSection(pFileData);
	nFileSize= pScn->PointerToRawData + pScn->SizeOfRawData;

}

//*********************************************************************************
// VMP代码：文件指针，返回处理的代码和虚拟指令数据，返回数据长度
//*********************************************************************************
void CMyShellDlg::VmpCode(char *pFileData, PCHAR &nOpcode, PDWORD nOpcodeSize)
{
	using std::vector;

	struct CodeRecord
	{
		int Address;	//被VM的地址
		int Type;		//指令类型
		int Value;		//操作数
	};

	vector<CodeRecord>g_CodeRecord;

	//vector<vector<CodeRecord>>g_CodeRecordArray;


	int nImageBass = GetOptionHeader(pFileData)->ImageBase;
	int nSectionRva = 0;
	int nSectionFoa = 0;
	int nSectionSize = 0;

	nSectionRva = GetSection(pFileData, ".text")->VirtualAddress;
	nSectionFoa = GetSection(pFileData, ".text")->PointerToRawData;
	nSectionSize = GetSection(pFileData, ".text")->SizeOfRawData;


	DISASM disAsm = { 0 };

	disAsm.EIP = (UIntPtr)pFileData + nSectionFoa;
	disAsm.VirtualAddr = nImageBass + nSectionRva;
	disAsm.Archi = 0;
	disAsm.Options = 0x000;
	INT nLen = 0;

	m_Progress_File.SetStep((nImageBass + nSectionRva + nSectionSize)- (DWORD)disAsm.VirtualAddr);

	bool nFunction = FALSE;
	for (DWORD nFunNum = 0; disAsm.VirtualAddr < nImageBass + nSectionRva + nSectionSize; nFunNum++)
	{

		nLen = Disasm(&disAsm);
		if (nLen == -1)
		{
			//printf("发现异常地址%08X\n", disAsm.VirtualAddr);
			disAsm.EIP += 1;
			disAsm.VirtualAddr += 1;
			
			//g_CodeRecordArray.push_back(g_CodeRecord);
			//g_CodeRecord.swap(vector<CodeRecord>());
			
			continue;
		}

		if (*(char*)disAsm.EIP == (char)0x64 || *(char*)disAsm.EIP == (char)0x65 || *(char*)disAsm.EIP == (char)0x67 || 
			*(char*)disAsm.EIP == (char)0x69 || *(char*)disAsm.EIP == (char)0x6e || *(char*)disAsm.EIP == (char)0x0)
		{
			disAsm.EIP += 1;
			disAsm.VirtualAddr += 1;
			continue;
		}

		if (CString(disAsm.CompleteInstr) == CString("mov ebp, esp"))
		{
			//printf("函数首部：%s\n", disAsm.CompleteInstr);
			nFunction = TRUE;
			disAsm.EIP += nLen;
			disAsm.VirtualAddr += nLen;
			continue;
		}
		else if (CString(disAsm.CompleteInstr) == CString("mov esp, ebp"))
		{
			//printf("函数结束：%s\n", disAsm.CompleteInstr);
			nFunction = FALSE;
			disAsm.EIP += nLen;
			disAsm.VirtualAddr += nLen;
			continue;
		}

		
		if (!nFunction)
		{
			disAsm.EIP += nLen;
			disAsm.VirtualAddr += nLen;
			continue;
		}


		if (nLen != 5)
		{
			disAsm.EIP += nLen;
			disAsm.VirtualAddr += nLen;
			continue;
		}


		if (*(int*)disAsm.EIP >= nImageBass && *(int*)disAsm.EIP <= nImageBass + nSectionSize)
		{
			disAsm.EIP += nLen;
			disAsm.VirtualAddr += nLen;
			continue;
		}


		if (*(char*)disAsm.EIP == (char)0x68 || *(char*)disAsm.EIP == (char)0xb8)
		{
			m_Progress_File.StepIt();
			//printf("正在处理代码%08X:", (int)disAsm.VirtualAddr);
			//printf("%s\n", disAsm.CompleteInstr);

			int nNum = *(int*)(disAsm.EIP + 1);

			if (*(char*)disAsm.EIP == (char)0x68)//push 指令加密
			{
				g_CodeRecord.push_back({ (int)disAsm.VirtualAddr - nImageBass, 1,nNum });
			}
			else if (*(char*)disAsm.EIP == (char)0xb8)//Mov eax 指令加密
			{
				g_CodeRecord.push_back({ (int)disAsm.VirtualAddr - nImageBass, 2,nNum });
			}

			for (int nIndex = 0; nIndex < 5; nIndex++)
			{
				*(char*)(disAsm.EIP + nIndex) = (char)0x90;//填充NOP
			}

		}

		disAsm.EIP += nLen;
		disAsm.VirtualAddr += nLen;

	}


	//整合数据，生成区段代码
	int nCodeRecordNum = g_CodeRecord.size();

	int *nRva = new int[nCodeRecordNum];
	for (int i = 0; i < nCodeRecordNum; i++)
	{
		*(nRva + i) = g_CodeRecord[i].Address;
	}


	char *nVirCode = new char[nCodeRecordNum * 5]{};
	for (int i = 0; i < nCodeRecordNum; i++)
	{
		*(nVirCode + i + i * 4) = (char)g_CodeRecord[i].Type;
		*(int*)(nVirCode + i + i * 4 + 1) = g_CodeRecord[i].Value;
	}


	DWORD nAllSize = 4 + nCodeRecordNum * 4 + nCodeRecordNum * 5;
	nOpcode = new CHAR[nAllSize]{};

	memcpy_s(nOpcode, nAllSize, &nCodeRecordNum, 4);
	memcpy_s(nOpcode + 4, nAllSize, nRva, nCodeRecordNum * 4);
	memcpy_s(nOpcode + 4 + nCodeRecordNum * 4, nAllSize, nVirCode, nCodeRecordNum * 5);

	*nOpcodeSize = nAllSize;


}

//*********************************************************************************
// 加密CALLIAT代码：文件指针，返回处理的代码，返回数据长度
//*********************************************************************************
void CMyShellDlg::EncryptCall(char *pFileData,PCHAR &nOpcode, PDWORD nOpcodeSize)
{
	using std::vector;

	struct CallRecord
	{
		int RvaAddress;
		int Index;
	};

	vector<CallRecord>g_CallRecord;

	int nImageBass = GetOptionHeader(pFileData)->ImageBase;
	int nSectionRva = 0;
	int nSectionFoa = 0;
	int nSectionSize = 0;

	nSectionRva = GetSection(pFileData, ".text")->VirtualAddress;
	nSectionFoa = GetSection(pFileData, ".text")->PointerToRawData;
	nSectionSize = GetSection(pFileData, ".text")->SizeOfRawData;


	DISASM disAsm = { 0 };

	disAsm.EIP = (UIntPtr)pFileData + nSectionFoa;
	disAsm.VirtualAddr = nImageBass + nSectionRva;
	disAsm.Archi = 0;
	disAsm.Options = 0x000;
	INT nLen = 0;

	m_Progress_File.SetStep((nImageBass + nSectionRva + nSectionSize) - (DWORD)disAsm.VirtualAddr);

	for (DWORD nFunNum = 0; disAsm.VirtualAddr < nImageBass + nSectionRva + nSectionSize; nFunNum++)
	{
		nLen = Disasm(&disAsm);
		if (nLen == -1)
		{
			//printf("发现异常地址%08X\n", disAsm.VirtualAddr);
			disAsm.EIP += 1;
			disAsm.VirtualAddr += 1;
			continue;
		}

		if (nLen != 6)
		{
			disAsm.EIP += nLen;
			disAsm.VirtualAddr += nLen;
			continue;
		}

		//判断是否CALL [XXXXXXX]代码
		if (*(char*)disAsm.EIP == (char)0xFF && *(char*)(disAsm.EIP + 1) == (char)0x15)
		{
			m_Progress_File.StepIt();

			int nAddress = *(int*)(disAsm.EIP + 2);//获取指向的IAT表地址

			int nIndex = FindIatNum(pFileData, nAddress);//寻找IAT表序号

			if (nIndex != -1)
			{
				g_CallRecord.push_back({ (int)disAsm.VirtualAddr - nImageBass,nIndex });
				for (int nIndex = 0; nIndex < 6; nIndex++)
				{
					*(char*)(disAsm.EIP + nIndex) = (char)0x90;//填充NOP
				}
			}

		}
		disAsm.EIP += nLen;
		disAsm.VirtualAddr += nLen;
	}

	//整合数据，生成区段数据
	int nCallRecordNum = g_CallRecord.size();

	nOpcode = new CHAR[nCallRecordNum * 8 + 4]{};

	*(DWORD*)(nOpcode)= nCallRecordNum;

	for (int i = 0; i < nCallRecordNum; i++)
	{
		*(DWORD*)(4 + nOpcode + i * 8) = g_CallRecord[i].RvaAddress;
		*(DWORD*)(4 + nOpcode + 4 + i * 8) = g_CallRecord[i].Index;
	}

	*nOpcodeSize = nCallRecordNum * 8 + 4;

}

//*********************************************************************************
// 寻找IAT的序号：文件指针，待寻找的地址
//*********************************************************************************
DWORD CMyShellDlg::FindIatNum(char *pFileData,int nAddress)
{
	IMAGE_THUNK_DATA* pIatFoa = NULL;
	IMAGE_THUNK_DATA* pIatRva = NULL;


	int nImageBass = GetOptionHeader(pFileData)->ImageBase;

	if (!GetOptionHeader(pFileData)->DataDirectory[1].VirtualAddress)return -1;

	IMAGE_OPTIONAL_HEADER * nOptionHeader = GetOptionHeader(pFileData);

	IMAGE_IMPORT_DESCRIPTOR* pImp = (IMAGE_IMPORT_DESCRIPTOR*)(RvaToFoa(pFileData, nOptionHeader->DataDirectory[1].VirtualAddress) + pFileData);


	int nIndex = 0;

	while (pImp->Name)
	{
		pIatFoa = (IMAGE_THUNK_DATA*)(RvaToFoa(pFileData, pImp->FirstThunk) + pFileData);

		pIatRva = (IMAGE_THUNK_DATA*)pImp->FirstThunk;

		while (pIatFoa->u1.Function)
		{
			if ((DWORD)pIatRva + nImageBass == nAddress)return nIndex;

			nIndex++;
			pIatFoa++;
			pIatRva++;
		}
		pImp++;
	}

	return -1;
}

//*********************************************************************************
// 加密处理IAT表，变成哈希值：文件指针
//*********************************************************************************
void CMyShellDlg::EncryIat(char *pFileData)
{
	IMAGE_THUNK_DATA* pInt = NULL;
	IMAGE_THUNK_DATA* pIat = NULL;
	IMAGE_IMPORT_BY_NAME* pIntImpName = 0;
	IMAGE_IMPORT_BY_NAME* pIatImpName = 0;


	if (!GetOptionHeader(pFileData)->DataDirectory[1].VirtualAddress)return;

	IMAGE_OPTIONAL_HEADER * nOptionHeader = GetOptionHeader(pFileData);

	IMAGE_IMPORT_DESCRIPTOR* pImp = (IMAGE_IMPORT_DESCRIPTOR*)(RvaToFoa(pFileData, nOptionHeader->DataDirectory[1].VirtualAddress) + pFileData);


	while (pImp->Name)
	{
		pIat = (IMAGE_THUNK_DATA*)(RvaToFoa(pFileData, pImp->FirstThunk) + pFileData);
		if (pImp->OriginalFirstThunk == 0) // 如果不存在INT则使用IAT
		{
			pInt = pIat;
		}
		else
		{
			pInt = (IMAGE_THUNK_DATA*)(RvaToFoa(pFileData, pImp->OriginalFirstThunk) + pFileData);
		}


		while (pInt->u1.Function)
		{
			if (!IMAGE_SNAP_BY_ORDINAL(pInt->u1.Ordinal))//是否序号导入
			{
				pIntImpName = (IMAGE_IMPORT_BY_NAME*)(RvaToFoa(pFileData, pInt->u1.Function) + pFileData);
				pIatImpName = (IMAGE_IMPORT_BY_NAME*)(RvaToFoa(pFileData, pInt->u1.Function) + pFileData);

				int nHash = GetHash((char*)pIntImpName->Name);//获取函数的哈希值

				memset((char*)pIntImpName->Name, 0, strlen((char*)pIntImpName->Name));//将原本的函数明文字符串抹掉
				memset((char*)pIatImpName->Name, 0, strlen((char*)pIntImpName->Name));//将原本的函数明文字符串抹掉

				memcpy_s(&pInt->u1.Function, 4, &nHash, 4);//填入哈希值
				memcpy_s(&pIat->u1.Function, 4, &nHash, 4);//填入哈希值
			}

			++pInt;
			++pIat;
		}

		++pImp;
	}

}

//*********************************************************************************
// 清除数据目录表：文件指针
//*********************************************************************************
void CMyShellDlg::ClearDataDir(char *pFileData)
{
	//GetOptionHeader(pFileData)->DataDirectory[1].VirtualAddress = 0;
	//GetOptionHeader(pFileData)->DataDirectory[1].Size = 0;
	//GetOptionHeader(pFileData)->DataDirectory[5].VirtualAddress = 0;
	//GetOptionHeader(pFileData)->DataDirectory[5].Size = 0;
	//GetOptionHeader(pFileData)->DataDirectory[9].VirtualAddress = 0;
	//GetOptionHeader(pFileData)->DataDirectory[9].Size = 0;

	for (DWORD i = 0; i < GetOptionHeader(pFileData)->NumberOfRvaAndSizes; i++)
	{
		if (i != 2)
		{
			GetOptionHeader(pFileData)->DataDirectory[i].VirtualAddress = 0;
			GetOptionHeader(pFileData)->DataDirectory[i].Size = 0;
		}
	}
	//memset(GetOptionHeader(pFileData)->DataDirectory,0, GetOptionHeader(pFileData)->NumberOfRvaAndSizes * sizeof(IMAGE_DATA_DIRECTORY));

	//int nStubTextSection = GetSection(StubConfig.pFileData, ".text")->VirtualAddress;
	//int nFileTextSection = GetSection(pFileData, "15PBPACK")->VirtualAddress;

	//int nNewTlsRva = GetOptionHeader(StubConfig.pFileData)->DataDirectory[9].VirtualAddress - nStubTextSection;

	//nNewTlsRva = nNewTlsRva + nFileTextSection;

	//GetOptionHeader(pFileData)->DataDirectory[9].VirtualAddress = nNewTlsRva;
	//GetOptionHeader(pFileData)->DataDirectory[9].Size = GetOptionHeader(StubConfig.pFileData)->DataDirectory[9].Size;


	//int nImageBass = GetOptionHeader(pFileData)->ImageBase;
	//nNewTlsRva = RvaToFoa(pFileData,nNewTlsRva) + (DWORD)pFileData;
	//int nTlsDataVa = *(int*)(nNewTlsRva + 12);
	//int ntemp = RvaToFoa(pFileData, nTlsDataVa-nImageBass)+(DWORD) pFileData;
	//ntemp= RvaToFoa(pFileData, *(int*)(ntemp)- nImageBass) + (DWORD)pFileData;
	//*(int*)nNewTlsRva = nTlsDataVa;

	//GetOptionHeader(pFileData)->DataDirectory[5].VirtualAddress = GetSection(pFileData, "RELOC")->VirtualAddress;
	//GetOptionHeader(pFileData)->DataDirectory[5].Size = GetOptionHeader(StubConfig.pFileData)->DataDirectory[5].Size;

}

//*********************************************************************************
// 修复资源图标
//*********************************************************************************
void CMyShellDlg::FixResources(char *pFileData, DWORD nFileSize,char *&pResourcesData,DWORD &nResourcesSize,CHAR *nHockPack_RelocData,DWORD nHockPack_RelocSize)
{
	DWORD nTempFileSize = nFileSize;
	CHAR* pTempFileData = new CHAR[nFileSize]{};
	memcpy_s(pTempFileData, nTempFileSize, pFileData, nTempFileSize);


	AddSection(pTempFileData, nFileSize, "HOCKPACK", nHockPack_RelocSize, nHockPack_RelocData);


	memcpy_s(GetSection(pTempFileData, ".rsrc")->Name, 8, " ", 1);
	AddNullSection(pTempFileData, nTempFileSize, ".rsrc");//末尾添加资源段

	GetOptionHeader(pTempFileData)->DataDirectory[2].VirtualAddress = 0;
	GetOptionHeader(pTempFileData)->DataDirectory[2].Size = 0;

	DWORD nNewSectionSize = GetLastSection(pTempFileData)->PointerToRawData + GetLastSection(pTempFileData)->SizeOfRawData;
	SavePeFile(pTempFileData, nNewSectionSize, m_FilePath);//保存文件

	delete[]pTempFileData;

	HANDLE hResUpdata = BeginUpdateResource(m_ShellFilePath, FALSE);
	for (auto &i : m_FileIcon) {
		UpdateResource(hResUpdata, RT_ICON, MAKEINTRESOURCE(i.dwId), 0, i.pData, i.dwSize);
	}
	for (auto &i : m_FileIconGroup) {
		UpdateResource(hResUpdata, RT_GROUP_ICON, MAKEINTRESOURCE(i.dwId), 0, i.pData, i.dwSize);
	}
	for (auto &i : m_FileVersion) {
		UpdateResource(hResUpdata, RT_VERSION, MAKEINTRESOURCE(i.dwId), 0, i.pData, i.dwSize);
	}
	EndUpdateResource(hResUpdata, FALSE);


	pTempFileData = GetFileData(m_ShellFilePath, &nTempFileSize);

	nResourcesSize = GetSection(pTempFileData, ".rsrc")->SizeOfRawData;
	pResourcesData = new CHAR[nResourcesSize]{};
	memcpy_s(pResourcesData, nResourcesSize, GetSection(pTempFileData, ".rsrc")->PointerToRawData + pTempFileData, nResourcesSize);
	FreeFileData(pTempFileData);

	FreeResources(&m_FileIcon);
	FreeResources(&m_FileIconGroup);
	FreeResources(&m_FileVersion);

	//HANDLE hResUpdata = BeginUpdateResource(m_ShellFilePath, FALSE);
	//for (auto &i : m_FileIcon) {
	//	UpdateResource(hResUpdata, RT_ICON, MAKEINTRESOURCE(i.dwId), 0, i.pData, i.dwSize);
	//}
	//for (auto &i : m_FileIconGroup) {
	//	UpdateResource(hResUpdata, RT_GROUP_ICON, MAKEINTRESOURCE(i.dwId), 0, i.pData, i.dwSize);
	//}
	//for (auto &i : m_FileVersion) {
	//	UpdateResource(hResUpdata, RT_VERSION, MAKEINTRESOURCE(i.dwId), 0, i.pData, i.dwSize);
	//}
	//EndUpdateResource(hResUpdata, FALSE);

	//FreeResources(&m_FileIcon);
	//FreeResources(&m_FileIconGroup);
	//FreeResources(&m_FileVersion);

	////修复图标后需要将重定位表清零
	//DWORD nFileSize = 0;
	//CHAR* pFileData = GetFileData(m_ShellFilePath, &nFileSize);

	//GetOptionHeader(pFileData)->DataDirectory[5].VirtualAddress = 0;
	//GetOptionHeader(pFileData)->DataDirectory[5].Size = 0;

	//SavePeFile(pFileData, nFileSize, m_FilePath);
	//FreeFileData(pFileData);


}

//*********************************************************************************
// 弹窗打开选择文件
//*********************************************************************************
CString CMyShellDlg::GetRoute()
{
	TCHAR szFileName[MAX_PATH] = { 0 };

	OPENFILENAME openFileName = { 0 };
	openFileName.lStructSize = sizeof(OPENFILENAME);
	openFileName.nMaxFile = MAX_PATH;  //这个必须设置，不设置的话不会出现打开文件对话框
	openFileName.lpstrFile = szFileName;
	openFileName.nFilterIndex = 1;
	openFileName.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR;
	openFileName.lpstrFilter = L"可执行文件(*.exe)\0*.EXE\0";

	if (GetOpenFileName(&openFileName))
	{
		return openFileName.lpstrFile;
	}

	return szFileName;
}

void CMyShellDlg::OnBnClickedButton1()
{
	CString nFilePath;
	nFilePath = GetRoute();
	if (nFilePath == "")return;

	m_FilePath = nFilePath;

	m_Button_OpenFile.EnableWindow(FALSE);
	m_Button_Start.EnableWindow(FALSE);
	m_Button_Run.EnableWindow(FALSE);

	StartShell();

	m_Button_Run.EnableWindow(TRUE);
	m_Button_Start.EnableWindow(TRUE);
	m_Button_OpenFile.EnableWindow(TRUE);

}

void CMyShellDlg::OnBnClickedButton4()
{
	m_Button_OpenFile.EnableWindow(FALSE);
	m_Button_Start.EnableWindow(FALSE);
	m_Button_Run.EnableWindow(FALSE);

	StartShell();

	m_Button_Run.EnableWindow(TRUE);
	m_Button_Start.EnableWindow(TRUE);
	m_Button_OpenFile.EnableWindow(TRUE);
}

void CMyShellDlg::OnBnClickedButton2()
{
	ShellExecute(0, 0, m_ShellFilePath, 0, 0, SW_SHOW);
}

void CMyShellDlg::OnBnClickedButton3()
{
	MessageBox(TEXT("感谢15PB！"), TEXT("提示"), MB_OK | MB_ICONINFORMATION);
}



