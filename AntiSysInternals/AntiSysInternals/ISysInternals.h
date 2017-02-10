#pragma once
#include <Windows.h>
#include <string>

#define CALL_EAX 0xE0FF
#define MOVABS 0xb848
#define JMP_TO 0xFF48
#define MOV_R9_R14 0xf1894d

int64_t JmpTableToFuncAddr(void *jmpAddr);

typedef struct Permissions {
	bool admin;
	bool debug;
};

//All tool hacks inherit from this
class ISysInternals
{	
protected:
	static std::wstring fileName;
	Permissions *processRights;
	bool CheckPrivilege(std::wstring privilege);
	bool isAdmin();
public:
	static int64_t targetProcAddr;
	bool RegisterHook(void* hook, std::wstring libName, std::string procName);
	virtual void DoActions()=0;
	Permissions *GetPermissions();
	virtual void Patch(void* hook, void* jmpAddr);
	virtual void CrashTarget(); //attempts to crash target sysinternal program already running after our first launch - forcing a dll load upon tool restart.
	ISysInternals();
	~ISysInternals();
};

