#include "stdafx.h"
#include "ISysInternals.h"


ISysInternals::ISysInternals()
{
}

ISysInternals::~ISysInternals()
{
}

//Dereference Import Table for actual address
int64_t JmpTableToFuncAddr(void *jmpAddr)
{
	BYTE jmpCode[0x4];
	int funcAddr;
	if ((WORD)JMP_TO != *(WORD*)jmpAddr)
		//no jmp table, must be in the function
		return (int64_t)jmpAddr;

	memcpy(jmpCode, (BYTE*)jmpAddr + 3, 0x4);
	funcAddr = jmpCode[3] << 0x18 | jmpCode[2] << 0x10 | jmpCode[1] << 0x8 | jmpCode[0];
	return *(int64_t*)((int64_t)jmpAddr + (funcAddr + 7));
}

bool ISysInternals::RegisterHook(void* hook, std::wstring libName, std::string procName)
{
	void* jmpAddr = GetProcAddress(GetModuleHandle(libName.c_str()), procName.c_str());
	//derive actual openProc function EP by dereferencing JMP address
    targetProcAddr = JmpTableToFuncAddr(jmpAddr);

#ifdef _WIN64
	DWORD oldP;
		VirtualProtect((void*)jmpAddr, sizeof(MOVABS) + sizeof(DWORD64) + sizeof(CALL_EAX), PAGE_EXECUTE_READWRITE, &oldP);
		ZeroMemory((void*)jmpAddr, sizeof(MOVABS) + sizeof(DWORD64) + sizeof(CALL_EAX) - 4);
		//Build eax with address of hook
		*((WORD*)jmpAddr) = MOVABS;
		*(DWORD64*)((BYTE*)jmpAddr + sizeof(MOVABS) - 2) = (int64_t)hook;
		*(DWORD*)((BYTE*)jmpAddr + (sizeof(MOVABS) + sizeof(DWORD64) - 2)) = MOV_R9_R14;
		//call rax
		*(WORD*)((BYTE*)jmpAddr + (sizeof(MOVABS) + sizeof(DWORD64) + sizeof(MOV_R9_R14) - 2)) = CALL_EAX;
	VirtualProtect((void*)jmpAddr, sizeof(MOVABS) + sizeof(DWORD64) + sizeof(CALL_EAX), PAGE_EXECUTE_READ, &oldP);

#else
	//x86 relative jmp
#endif
	FlushInstructionCache(NULL, (void*)jmpAddr, 0x30);
	return true;
}