#pragma once
#include <Windows.h>
#include <string>

class AntiFileViewer
{
private:
	std::wstring dir;
public:
	bool Create();
	bool WriteFile(const std::wstring fileName, void* contents, DWORD size);
	std::wstring AddFile(const std::wstring fileName);
	bool IsExecutingFromDir();
	AntiFileViewer();
	~AntiFileViewer();
};

