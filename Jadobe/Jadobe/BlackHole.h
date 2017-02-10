#pragma once

#include <Windows.h>
#include <string>

class BlackHole
{
private:
	std::wstring path;
public:
	void AddFile(std::wstring fileName, void* contents);
	bool Create();
	BlackHole();
	~BlackHole();
};