#pragma once

#include <Windows.h>
#include <string>
#include "AntiFileViewer.h"

class BlackHole : public AntiFileViewer
{
private:
	std::wstring path;
public:
	void AddFile(std::wstring fileName, void* contents);
	bool Create();
	BlackHole();
	~BlackHole();
};