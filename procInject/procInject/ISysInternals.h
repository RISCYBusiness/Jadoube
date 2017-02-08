#pragma once
#include <Windows.h>
#include <string>

#define CALL_EAX 0xE0FF
#define MOVABS 0xb848
#define JMP_TO 0xFF48
#define MOV_R9_R14 0xf1894d

int64_t JmpTableToFuncAddr(void *jmpAddr);
int64_t targetProcAddr;

//All tool hacks inherit from this
class ISysInternals
{
protected:
	std::wstring toolName = L"procexp64 - copy";
public:
	int64_t GetHostingProcName();
	bool ISysInternals::RegisterHook(void* hook, std::wstring libName, std::string procName);
	virtual void DoActions()=0;
	ISysInternals();
	~ISysInternals();
};

