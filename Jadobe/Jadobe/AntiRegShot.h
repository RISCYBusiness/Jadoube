#pragma once
#include <Windows.h>
#include <string>

class AntiRegShot
{
private:
	//XSS vuln, could do some creative things, but default - lets just cut off the regshot output
	std::wstring XSS = L"></html>"; 
public:
	AntiRegShot();
	~AntiRegShot();
};

