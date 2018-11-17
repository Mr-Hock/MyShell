#pragma once
#include <Vector>
#include <windows.h>
#include "Conf.h"

#include "aplib.h"
#pragma comment(lib,"aPlib.lib")



//反汇编引擎头文件，静态库
#define BEA_ENGINE_STATIC
#define BEA_USE_STDCALL
#include "BeaEngine_4.1/Win32/headers/BeaEngine.h"
#pragma comment (lib , "BeaEngine_4.1/Win32/Win32/Lib/BeaEngine.lib")
#pragma comment(linker, "/NODEFAULTLIB:\"crt.lib\"")


// CMyShellDlg 对话框
class CMyShellDlg : public CDialogEx
{
// 构造
public:
	CMyShellDlg(CWnd* pParent = NULL);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_MYSHELL_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnDropFiles(HDROP hDropInfo);

	struct StubDll
	{
		CHAR* pFileData; // DLL的加载基址

		CHAR* pTextData; // 代码段的数据
		DWORD dwTextDataSize; // 代码段的大小

		CHAR* pRelocData; // 重定位段的数据
		DWORD dwRelocDataSize; // 代码段的大小

		StubConf* pConf;// DLL中导出的全局变量
		VOID* start;    // DLL中导出函数
	};

	struct TypeOffset
	{
		WORD ofs : 12;
		WORD type : 4;
	};

	struct ResourcesData 
	{
		DWORD	dwSize;
		DWORD	dwId;
		LPBYTE	pData;
	};


	StubDll StubConfig;
	CString m_FilePath;
	CString m_ShellFilePath;
	std::vector<ResourcesData>	m_FileIcon;
	std::vector<ResourcesData>	m_FileIconGroup;
	std::vector<ResourcesData>	m_FileVersion;


	void StartShell();
	HANDLE OpenPeFile(CString path);
	void ClosePeFile(HANDLE hFile);
	bool SavePeFile(char* pFileData, int nSize, CString nFileName);
	char* GetFileData(CString pFilePath, DWORD* nFileSize = NULL);
	void FreeFileData(char* pFileData);

	DWORD GetResources(char* pFileData,SIZE_T dwType, std::vector<ResourcesData>* vecData);
	void FreeResources(std::vector<ResourcesData>* vecData);
	IMAGE_DOS_HEADER* GetDosHeader(char* pFileData);
	DosStub* GetDosSubHeader(char* pFileData);
	IMAGE_NT_HEADERS* GetNtHeader(char* pFileData);
	IMAGE_SECTION_HEADER* GetSectionHeader(char* pFileData);
	IMAGE_FILE_HEADER* GetFileHeader(char* pFileData);
	IMAGE_OPTIONAL_HEADER* GetOptionHeader(char* pFileData);
	IMAGE_SECTION_HEADER* GetSection(char* pFileData, char* scnName);
	IMAGE_SECTION_HEADER* CMyShellDlg::GetLastSection(char* pFileData);

	int Aligment(int size, int aliginment);
	int RvaToFoa(char* pFileData, int nRva);
	int GetHash(char *strFunName);
	void AddSection(char*& pFileData, DWORD&nFileSize, char* pNewSecName, int nSecSize, void* pSecData);
	void AddNullSection(char* pFileData, DWORD nFileSize, char* pNewSecName);
	void AssembleData(PCHAR &nNewSection, char* pDestSection, int nDestDataSize, char* pSrcSection, int nSrcDataSize);
	void LoadStub(StubDll* pStub);
	void FixStubRelocation(StubDll* stub, char* pFileData, DWORD dwNewScnRva);
	void EncryCode(char *pFileData);
	void PackCode(char *pFileData);
	void FixSection(char *pFileData, DWORD&nFileSize);
	void VmpCode(char *pFileData, PCHAR &nOpcode, PDWORD nOpcodeSize);
	void EncryptCall(char *pFileData, PCHAR &nOpcode, PDWORD nOpcodeSize);
	DWORD FindIatNum(char *pFileData, int nAddress);
	void EncryIat(char *pFileData);
	void ClearDataDir(char *pFileData);
	void FixResources(char *pFileData, DWORD nFileSize,char *&pResourcesData, DWORD &nResourcesSize, CHAR *nHockPack_RelocData, DWORD nHockPack_RelocSize);
	CString GetRoute();

	afx_msg void OnBnClickedButton1();
	afx_msg void OnBnClickedButton2();
	afx_msg void OnBnClickedButton3();
	afx_msg void OnBnClickedButton4();

	CButton m_Check_PackData;
	CButton m_Check_IatEncrypt;
	CButton m_Check_Vmp;
	CButton m_Check_RandImageBass;
	CButton m_Check_EncryptCode;
	CEdit m_Edit_PassWord;
	CButton m_Button_OpenFile;
	CButton m_Button_Run;
	CButton m_Button_About;
	CStatic m_Static_FilePath;
	CStatic m_Static_FileSize;
	CStatic m_Static_Tip;
	CProgressCtrl m_Progress_File;
	CStatic m_Static_PackSize;
	CButton m_Check_FixIco;
	CButton m_Button_Start;
	CEdit m_Edit_FilePath;
};
