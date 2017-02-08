// BH60.cpp : Defines the entry point for the console application.
//
#include "stdafx.h"
#include "StringEncrypt.h"
#include "BlackHole.h"
#include "Debug.h"
#include <iostream>

int _tmain(int argc, _TCHAR* argv[])
{

	BlackHole *b = new BlackHole();
	b->Create();

	b->AddFile("DbgHelp.dll",)

#ifdef DEBUG //Keep console up
	system("pause");
#endif
	return 0xB1ac401e;
}