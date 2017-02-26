#define DEBUG 1

#include <iostream>
#include <string>

inline void DebugOut(std::wstring msg)
{
	std::wcout << msg << std::endl;
	return;
}
