#pragma once
#include <iostream>
#include "StringEncrypt.h"

#define DEBUG 1

void DebugOut(std::wstring encryptedMessage)
{
#ifdef DEBUG 
	std::cout << encryptedMessage.c_str() << std::endl;
#endif

	return;
}