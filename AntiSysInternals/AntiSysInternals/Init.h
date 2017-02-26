#pragma once
#include "Procexp.h"
#include <string>


void Hijack(std::wstring fileName)
{
	//Procexp
	if (fileName.find(L"Procexp") != std::string::npos)
	{
		Procexp *p = new Procexp(fileName);
		p->DoActions();
	}
	//...
	
}

bool AdaptToTool()
{
	/////Get Original Filename From Current Exe to bypass renamed tools////////////
	wchar_t szModPath[MAX_PATH];
	DWORD h;
	unsigned int size;
	if (!GetModuleFileName(NULL, szModPath, sizeof(szModPath)))
		return false;
	DWORD dwSize = GetFileVersionInfoSize(szModPath, &h);
	BYTE *pbBuf = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
	if (!GetFileVersionInfo(szModPath, h, dwSize, pbBuf))
		return false;
	void* originalFileName;
	WORD *langInfo;

	if (!VerQueryValue(pbBuf, L"\\VarFileInfo\\Translation", (PVOID*)&langInfo, &size))
		return false;
	wchar_t* path = (wchar_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 64);
	wsprintf(path,L"\\StringFileInfo\\%04x%04x\\OriginalFileName", langInfo[0], langInfo[1]);
	
	if (!VerQueryValue(pbBuf, path, &originalFileName, &size))
		return false;
	/////////////////////////////////////////////////////////
	Hijack((wchar_t*)originalFileName);

	return true;
}

