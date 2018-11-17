#pragma once
#include <windows.h>

typedef struct StubConf
{
	DWORD nOEP;
	DWORD nImportVirtual;
	DWORD nImportSize;
	DWORD nRelocVirtual;
	DWORD nRelocSize;
	DWORD nResourceVirtual;
	DWORD nResourceSize;
	DWORD nTlsVirtual;
	DWORD nTlsSize;

	BOOL nPackData;
	BOOL nIatEncrypt;
	BOOL nVmp;
	BOOL nRandImageBass;
	BOOL nEncryptCode;

	BOOL nFixIco;


}StubConf;


typedef struct DosStub 
{
	DWORD nOldImageBass;//���ӿǳ�������ǰĬ�ϵļ��ػ�ַ
	DWORD nStubTextSectionRva;//���ڿ������text��Rva
	DWORD nStubRelocSectionRva;//�ǵ��ض�λ����text�κϲ����ڱ��ӿǳ����Rva

}DosSub;
