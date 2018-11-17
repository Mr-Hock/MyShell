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
	DWORD nOldImageBass;//被加壳程序运行前默认的加载基址
	DWORD nStubTextSectionRva;//壳在壳自身的text段Rva
	DWORD nStubRelocSectionRva;//壳的重定位表与text段合并后在被加壳程序的Rva

}DosSub;
