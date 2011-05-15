/*  Copyright (C) 2010-2011  kaosu (qiupf2000@gmail.com)
 *  This file is part of the Interactive Text Hooker.

 *  Interactive Text Hooker is free software: you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License as published
 *  by the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.

 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.

 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "utility.h"
#include "..\AVL.h"
WCHAR mutex[]=L"ITH_GRANT_PIPE";
WCHAR exist[]=L"ITH_PIPE_EXIST";
WCHAR lose_event[0x20];
WCHAR detach_mutex[0x20];
WCHAR write_event[0x20];
WCHAR engine_event[0x20];
WCHAR pipe[]=L"\\??\\pipe\\ITH_PIPE";
WCHAR command[]=L"\\??\\pipe\\ITH_COMMAND";

LARGE_INTEGER wait_time={-100*10000,-1};
LARGE_INTEGER sleep_time={-20*10000,-1};

UINT_PTR engine_type;
HANDLE hPipe,hCommand,hDetach,hLose;
IdentifyEngineFun IdentifyEngine; 
InsertDynamicHookFun InsertDynamicHook;
static UINT_PTR base;
bool hook_inserted=0;
extern "C" UINT_PTR GetModuleBaseByName(LPWSTR name);
inline UINT_PTR GetModuleBase(LPWSTR name)
{
	return GetModuleBaseByName(name);
}
HANDLE IthOpenPipe(LPWSTR name, ACCESS_MASK direction)
{
	UNICODE_STRING us;
	RtlInitUnicodeString(&us,name);
	SECURITY_DESCRIPTOR sd={1};
	OBJECT_ATTRIBUTES oa={sizeof(oa),0,&us,OBJ_CASE_INSENSITIVE,&sd,0};
	HANDLE hFile;
	IO_STATUS_BLOCK isb;
	if (NT_SUCCESS(NtCreateFile(&hFile,direction,&oa,&isb,0,0,FILE_SHARE_READ,FILE_OPEN,0,0,0)))
		return hFile;
	else return INVALID_HANDLE_VALUE;
}
BOOL LoadEngine()
{
	base=GetModuleBase(L"ITH64_engine.dll");
	IdentifyEngine=(IdentifyEngineFun)GetExportAddress(base,GetHash("IdentifyEngine"));
	InsertDynamicHook=(InsertDynamicHookFun)GetExportAddress(base,GetHash("InsertDynamicHook"));
	if (IdentifyEngine==0||InsertDynamicHook==0) return FALSE;
	return TRUE;
}

UINT_PTR WINAPI WaitForPipe(LPVOID lpThreadParameter) //Dynamic detect ITH main module status. 
{
	int i;
	TextHook *man;
	struct
	{
		UINT_PTR pid;
		TextHook *man;
		UINT_PTR module;
		UINT_PTR engine;
	} u;
	HANDLE hMutex,hPipeExist,hEngine;
	swprintf(engine_event,L"ITH_ENGINE_%d",current_process_id);
	swprintf(detach_mutex,L"ITH_DETACH_%d",current_process_id);
	swprintf(lose_event,L"ITH_LOSEPIPE_%d",current_process_id);
	hEngine=IthCreateEvent(engine_event);
	NtWaitForSingleObject(hEngine,0,0);
	NtClose(hEngine);
	LoadEngine();
	u.module=GetModuleBase(L"ITH64.dll");
	u.pid=current_process_id;
	u.man=hookman;
	u.engine=base;
	hPipeExist=IthOpenEvent(exist);
	IO_STATUS_BLOCK ios;
	hLose=IthCreateEvent(lose_event,0,0);
	if (hPipeExist!=INVALID_HANDLE_VALUE)
	while (running)
	{
		hPipe=INVALID_HANDLE_VALUE;
		hCommand=INVALID_HANDLE_VALUE;
		while (NtWaitForSingleObject(hPipeExist,0,&wait_time)==WAIT_TIMEOUT)
			if (!running) goto _release;
		hMutex=IthCreateMutex(mutex,0);
		NtWaitForSingleObject(hMutex,0,0);
		while (hPipe==INVALID_HANDLE_VALUE||
			hCommand==INVALID_HANDLE_VALUE) {
			NtDelayExecution(0,&sleep_time);
			if (hPipe==INVALID_HANDLE_VALUE)
				hPipe=IthOpenPipe(pipe,GENERIC_WRITE);
			if (hCommand==INVALID_HANDLE_VALUE)
				hCommand=IthOpenPipe(command,GENERIC_READ);
		}
		NtClearEvent(hLose);
		NtWriteFile(hPipe,0,0,0,&ios,&u,sizeof(u),0,0);
		live=true;
		for (man=hookman,i=0;i<current_hook;man++)
			if (man->RecoverHook()) i++;
		OutputConsole(dll_mutex+9);
		OutputConsole(L"Pipe connected.");
		OutputDWORD(tree->Count());
		NtReleaseMutant(hMutex,0);
		NtClose(hMutex);
		if (!hook_inserted) {hook_inserted=true;IdentifyEngine();}
		hDetach=IthCreateMutex(detach_mutex,1);
		while (running&&NtWaitForSingleObject(hPipeExist,0,&sleep_time)==WAIT_OBJECT_0) 
			NtDelayExecution(0,&sleep_time);
		live=false;
		for (man=hookman,i=0;i<current_hook;man++)
			if (man->RemoveHook()) i++;
		if (!running)
		{
			NtWriteFile(hPipe,0,0,0,&ios,man,8,0,0);
			IthReleaseMutex(hDetach);					
		}
		NtClose(hDetach);
		NtClose(hPipe);
	}
_release:
	NtClose(hLose);
	NtClose(hPipeExist);
	return 0;
}
void OutputModuleInformation()
{
	WCHAR str[0x100];
	UINT_PTR temp=*(UINT_PTR*)(&peb->Ldr->InLoadOrderModuleList);
	PLDR_DATA_TABLE_ENTRY it=(PLDR_DATA_TABLE_ENTRY) temp;
	while (*(UINT_PTR*)it!=temp)
	{
		swprintf(str,L"0x%08X 0x%08X %s",it->DllBase,it->SizeOfImage,it->BaseDllName.Buffer);
		OutputConsole(str);
		it=(PLDR_DATA_TABLE_ENTRY)it->InLoadOrderModuleList.Flink;
	}
}

UINT_PTR WINAPI CommandPipe(LPVOID lpThreadParameter)
{
	UINT_PTR command;
	BYTE buff[0x200]={};
	HANDLE hPipeExist;
	hPipeExist=IthOpenEvent(exist);
	IO_STATUS_BLOCK ios={};
	NTSTATUS status;
	if (hPipeExist!=INVALID_HANDLE_VALUE)
	while (running)
	{
		while (!live) 
		{
			if (!running) goto _detach;
			NtDelayExecution(0,&sleep_time);
		}
		status=NtReadFile(hCommand,0,0,0,&ios,buff,0x200,0,0);

		if (status==STATUS_PIPE_BROKEN) goto _detach;
		if (status==STATUS_PENDING)
		{
			NtWaitForSingleObject(hCommand,0,0);
			switch (ios.Status)
			{
			case 0:
				break;
			case STATUS_PIPE_BROKEN:
			case STATUS_PIPE_DISCONNECTED:
				NtClearEvent(hPipeExist);
				continue;
				break;
			default:
				if (NtWaitForSingleObject(hDetach,0,&wait_time)==WAIT_OBJECT_0)
				goto _detach;
			}			
		}
		if (ios.uInformation)
		if (live)
		{
			command=*(UINT_PTR*)buff;
			//__debugbreak();
			switch(command)
			{
			case 0:
				NewHook(*(HookParam*)(buff+8),0,0);
				break;
			case 1:
				OutputModuleInformation();
				break;
			case 2:
				{
					UINT_PTR rm_addr=*(UINT_PTR*)(buff+8);
					HANDLE hRemoved=IthOpenEvent(L"ITH_REMOVE_HOOK");

					TextHook* in=hookman;
					int i;
					for (i=0;i<current_hook;in++)
					{
						if (in->Address()) i++;
						if (in->Address()==rm_addr) break;
					}
					if (in->Address()) 
						in->ClearHook();
					IthSetEvent(hRemoved);
					NtClose(hRemoved);
					break;
				}
			case 3:
				{
					__debugbreak();
					UINT_PTR rm_addr=*(UINT_PTR*)(buff+8);
					HANDLE hModify=IthOpenEvent(L"ITH_MODIFY_HOOK");
					TextHook* in=hookman;
					int i;
					for (i=0;i<current_hook;in++)
					{
						if (in->Address()) i++;
						if (in->Address()==rm_addr) break;
					}
					if (in->Address()) 
						in->ModifyHook(*(HookParam*)(buff+8));
					IthSetEvent(hModify);
					NtClose(hModify);
					break;

				}
				break;
			case 4:
				goto _detach;
			case 5:

				break;
			default:
				break;
			}
		}
	}
_detach:
	running=false;
	live=false;
	NtClose(hPipeExist);
	NtClose(hCommand);
	return 0;
}
extern "C" {
void ITHAPI OutputConsole(LPWSTR str)
{
	if (live)
	if (str)
	{
		UINT_PTR len=(wcslen(str)+1)<<1;
		BYTE buffer[0x80];
		BYTE *buff=buffer;
		if (len+HEADER_SIZE>=0x80)
			buff=new BYTE[len+HEADER_SIZE];
		memset(buff,0xFF,HEADER_SIZE);
		wcscpy(LPWSTR(buff+HEADER_SIZE),str);
		IO_STATUS_BLOCK ios;
		NtWriteFile(hPipe,0,0,0,&ios,buff,len+HEADER_SIZE,0,0);
		if (buff!=buffer) delete buff;
	}
}
void ITHAPI OutputDWORD(UINT_PTR d)
{
	WCHAR str[0x10];
	swprintf(str,L"%.8X",d);
	OutputConsole(str);
}
void ITHAPI OutputRegister(UINT_PTR *base)
{
	WCHAR str[0x40];
	swprintf(str,L"EAX:%.8X",base[0]);
	OutputConsole(str);
	swprintf(str,L"ECX:%.8X",base[-1]);
	OutputConsole(str);
	swprintf(str,L"EDX:%.8X",base[-2]);
	OutputConsole(str);
	swprintf(str,L"EBX:%.8X",base[-3]);
	OutputConsole(str);
	swprintf(str,L"ESP:%.8X",base[-4]);
	OutputConsole(str);
	swprintf(str,L"EBP:%.8X",base[-5]);
	OutputConsole(str);
	swprintf(str,L"ESI:%.8X",base[-6]);
	OutputConsole(str);
	swprintf(str,L"EDI:%.8X",base[-7]);
	OutputConsole(str);
}
}