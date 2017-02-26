#include "stdafx.h"
#include "ISysInternals.h"

int64_t ISysInternals::targetProcAddr;
std::wstring ISysInternals::fileName = L"";

bool ISysInternals::CheckPrivilege(std::wstring privilege)
{
	HANDLE hToken;
	LUID luid;
	TOKEN_PRIVILEGES tp;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		if (hToken)
			CloseHandle(hToken);
		return false;
	}
	
	if (!LookupPrivilegeValue(NULL, privilege.c_str(), &luid))
	{
		if (hToken)
			CloseHandle(hToken);
		return false;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	
	//ERROR_NOT_ALL_ASSIGNED will be the failure cause in cases the privilege is not given
	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
		return false;
	
	CloseHandle(hToken);

	return true;
}

bool ISysInternals::isAdmin()
{
	BOOL fRet = FALSE;
	HANDLE hToken = NULL;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
		TOKEN_ELEVATION Elevation;
		DWORD cbSize = sizeof(TOKEN_ELEVATION);
		if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) {
			fRet = Elevation.TokenIsElevated;
		}
	}
	if (hToken) {
		CloseHandle(hToken);
	}
	return fRet;
}

Permissions *ISysInternals::GetPermissions()
{
	Permissions *p = new Permissions;
	p->admin = isAdmin();
	p->debug = CheckPrivilege(SE_DEBUG_NAME);
}

//Virtual - implimented tool-by-tool basis
void ISysInternals::Patch(void * hook, void * jmpAddr)
{
	return;
}

ISysInternals::ISysInternals()
{
	processRights = GetPermissions();
	wchar_t filename[MAX_PATH];
    GetModuleFileName(NULL, filename, MAX_PATH);
	fileName = filename;
}

ISysInternals::~ISysInternals()
{
}

//Dereference Import Table Entry for actual function address
int64_t JmpTableToFuncAddr(void *jmpAddr)
{
	BYTE jmpCode[0x4];
	int funcAddr;
	if ((WORD)JMP_TO != *(WORD*)jmpAddr)
		//No jmp table found - exit (consider making this recoverable)
		exit(-1);

	memcpy(jmpCode, (BYTE*)jmpAddr + 3, 0x4);
	//little endian to int
	funcAddr = jmpCode[3] << 0x18 | jmpCode[2] << 0x10 | jmpCode[1] << 0x8 | jmpCode[0];
	//return absolute addres of function
	return *(int64_t*)((int64_t)jmpAddr + (funcAddr + 7));
}

//Core function wrapper used to apply hook. Internal hooking specifics are overridden through "Patch"
bool ISysInternals::RegisterHook(void* hook, std::wstring libName, std::string procName)
{
	void* jmpAddr = GetProcAddress(GetModuleHandle(libName.c_str()), procName.c_str());
	//derive actual function EP by dereferencing JMP address
    ISysInternals::targetProcAddr = JmpTableToFuncAddr(jmpAddr);
	
	//virtual function - patching implimented tool-by-tool basis
	Patch(hook, jmpAddr);

	FlushInstructionCache(NULL, (void*)jmpAddr, 0x30);
	return true;
}