#pragma once
#include <string>

class SysInternalHook
{
private:
	std::wstring injectPayload = L"DbgHelp.dll";
	bool PayloadExists();
protected:
	bool WriteHook(std::wstring toolName);
public:
	
	SysInternalHook(std::wstring dllPath);
	~SysInternalHook();
};