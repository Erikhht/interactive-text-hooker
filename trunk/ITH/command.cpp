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

#include "cmdq.h"
//#include "hookman.h"
//#include <intrin.h>

#define IthTIMING
#ifdef IthTIMING
#define TestTime(x) {\
			LARGE_INTEGER fre,begin,end;\
			NtQueryPerformanceCounter(&begin,&fre);\
			x;\
			NtQueryPerformanceCounter(&end,0);\
			WCHAR str[0x40];\
			swprintf(str,L"Time spent: %.6lfs",(end.QuadPart-begin.QuadPart)/(double)fre.QuadPart);\
			ConsoleOutput(str);\
			}
#else
#define TestTime(x) x;
#endif
static const DWORD table[]={0x100,0x100,0x100,0x100};
BYTE* GetSystemInformation()
{
	DWORD dwSize;
	BYTE *pbBuffer;
	NTSTATUS status;
	status=NtQuerySystemInformation(SystemProcessInformation,&dwSize,0,&dwSize);
	if (status!=STATUS_INFO_LENGTH_MISMATCH) return NULL;
	dwSize=(dwSize&0xFFFFF000)+0x1000;
	pbBuffer=new BYTE[dwSize];
	status=NtQuerySystemInformation(SystemProcessInformation,pbBuffer,dwSize,&dwSize);
	if (NT_SUCCESS(status)) return pbBuffer;
	return NULL;
}
bool PerformSingleThread(DWORD pid, DWORD &dwBase, DWORD addr=0, ThreadOperation op=OutputInformation)
{
	DWORD dwTid=*(DWORD*)dwBase;
	if (dwTid==0) return false;
	HANDLE hThread,hProc;
	CLIENT_ID id;
	NTSTATUS status;
	OBJECT_ATTRIBUTES att={0};
	DWORD right=THREAD_QUERY_INFORMATION;
	id.UniqueThread=dwTid;
	id.UniqueProcess=0;
	att.uLength=sizeof(att);
	switch(op)
	{
	case Suspend:
	case Resume:
		right|=THREAD_SUSPEND_RESUME;
		break;
	case	Terminate:
		right|=THREAD_TERMINATE;
		break;
	}
	if (!NT_SUCCESS(NtOpenThread(&hThread,right,&att,&id))) return false;
	THREAD_WIN32_START_ADDRESS_INFORMATION address;
	status=NtQueryInformationThread(hThread,ThreadQuerySetWin32StartAddress,&address,sizeof(address),0);
	if (!NT_SUCCESS(status)) return false;
	if (addr==0||addr==(DWORD)address.Win32StartAddress)
	{
		switch (op)
		{
		case OutputInformation:
		{
			WCHAR name[0x100];
			id.UniqueProcess=pid;
			id.UniqueThread=0;
			if (!NT_SUCCESS(NtOpenProcess(&hProc,PROCESS_QUERY_INFORMATION,&att,&id)))
				return false;
			if (!NT_SUCCESS(NtQueryVirtualMemory(hProc,address.Win32StartAddress,
				MemorySectionName,name,0x200,0))) return false;
			WCHAR str[0x100];
			swprintf(str,L"%.4X 0x%.8X:%s",dwTid,address.Win32StartAddress,wcsrchr(name,L'\\')+1);
			ConsoleOutput(str);
			status=0;
		}
		break;
		case Suspend:
			status=NtSuspendThread(hThread,0);
			break;
		case Resume:
			status=NtResumeThread(hThread,0);
			break;
		case Terminate:
			status=NtTerminateThread(hThread,0);
			break;
		}
		NtClose(hThread);
		NtClose(hProc);
	}
	dwBase+=0x40;
	if (NT_SUCCESS(status)) return true;
	else return false;
}
SYSTEM_PROCESS_INFORMATION* GetBaseByPid(BYTE* pbBuffer,DWORD dwPid)
{
	SYSTEM_PROCESS_INFORMATION *spiProcessInfo=(SYSTEM_PROCESS_INFORMATION*)pbBuffer;
	for (; spiProcessInfo->dNext;)
	{
		spiProcessInfo=(SYSTEM_PROCESS_INFORMATION*)
			((DWORD)spiProcessInfo+spiProcessInfo->dNext);
		if(dwPid==spiProcessInfo->dUniqueProcessId) break;
	}
	if (dwPid!=spiProcessInfo->dUniqueProcessId) 
		return 0;
	return spiProcessInfo;
}
int PerformThread(DWORD dwPid, DWORD addr=0,ThreadOperation op=OutputInformation)
{
	BYTE *pbBuffer=GetSystemInformation();
	if (pbBuffer==0) return 0;
	SYSTEM_PROCESS_INFORMATION *spiProcessInfo=GetBaseByPid(pbBuffer,dwPid);
	SYSTEM_THREAD* base;
	DWORD dwLimit;
	if (spiProcessInfo)
	{
		base=(SYSTEM_THREAD*)((DWORD)spiProcessInfo+sizeof(SYSTEM_PROCESS_INFORMATION));
		dwLimit=(DWORD)spiProcessInfo->usName.Buffer;
		while ((DWORD)base<dwLimit)
			PerformSingleThread(spiProcessInfo->dUniqueProcessId,base->Cid.UniqueThread,addr,op);
	}
	delete pbBuffer;
	return spiProcessInfo!=0;
}
int GetProcessMemory1(HANDLE hProc, DWORD& size, DWORD& ws)
{
	DWORD len=0x200,retl,s=0;
	DWORD *buffer=0;
	NTSTATUS status=STATUS_INFO_LENGTH_MISMATCH;
	len=0x10000;
	while (status==STATUS_INFO_LENGTH_MISMATCH)
	{
		delete buffer;
		len<<=1;
		buffer=new DWORD[len];
		status=NtQueryVirtualMemory(hProc,0,MemoryWorkingSetList,buffer,len<<2,&retl);
	}
	if (!NT_SUCCESS(status)) 
	{
		delete buffer;
		return 0;
	}
	len=*(DWORD*)buffer;
	ws=len<<2;
	for (DWORD i=1;i<=len;i++)
		s+=(buffer[i]>>8)&1; //Hot spot.
	size=(len-s)<<2;
	delete buffer;
	return 1;
}
int GetProcessMemory(HANDLE hProc, DWORD& mem_size, DWORD& ws)
{
	DWORD len,retl,s;
	LPVOID buffer=0;
	NTSTATUS status;
	len=0x4000;
	status=NtAllocateVirtualMemory(NtCurrentProcess(),&buffer,0,&len,MEM_COMMIT,PAGE_READWRITE);
	if (!NT_SUCCESS(status)) return 0;
	status=NtQueryVirtualMemory(hProc,0,MemoryWorkingSetList,buffer,len,&retl);
	if (status==STATUS_INFO_LENGTH_MISMATCH)
	{
		len=*(DWORD*)buffer;
		len=((len<<2)&0xFFFFF000)+0x1000;
		s=0;
		NtFreeVirtualMemory(NtCurrentProcess(),&buffer,&s,MEM_RELEASE);
		buffer=0;
		status=NtAllocateVirtualMemory(NtCurrentProcess(),&buffer,0,&len,MEM_COMMIT,PAGE_READWRITE);
		if (!NT_SUCCESS(status)) return 0;
		status=NtQueryVirtualMemory(hProc,0,MemoryWorkingSetList,buffer,len,&retl);
		if (!NT_SUCCESS(status)) return 0;
	}
	else if (!NT_SUCCESS(status)) return 0;
	__asm
	{
		mov esi,buffer
		mov edi,[esi]
		mov eax,ws
		lea ebx,[edi*4]
		mov [eax],ebx
		mov ecx,edi

		xor edx,edx
		bt edi,8
		sbb edx,0
		shl edx,8
		lea edi,[esi+ebx+4]
		pxor xmm4,xmm4
		pxor xmm5,xmm5
		pxor xmm6,xmm6
		pxor xmm7,xmm7
		lea eax,[esp-0x20]
		and al,0xF0
		movups xmm0,table
		movaps [eax],xmm0
		prefetcht0 [eax]
		mov ebx,0x40
		lea eax,[eax]
sse_calc:
		movaps xmm0,[esi]
		movaps xmm1,[esi+0x10]
		movaps xmm2,[esi+0x20]
		movaps xmm3,[esi+0x30]
		andps xmm0,[eax]
		andps xmm1,[eax]
		andps xmm2,[eax]
		andps xmm3,[eax]
		addps xmm4,xmm0
		addps xmm5,xmm1
		addps xmm6,xmm2
		addps xmm7,xmm3
		add esi,ebx
		cmp esi,edi
		jb sse_calc

		addps xmm4,xmm5
		addps xmm6,xmm7
		addps xmm4,xmm6
		movaps [eax],xmm4
		add edx,[eax]
		add edx,[eax+0x4]
		add edx,[eax+0x8]
		add edx,[eax+0xC]
		shr edx,8
		sub edx,ecx
		neg edx
		add edx,edx
		mov ecx,mem_size
		add edx,edx
		mov [ecx],edx
	}
	s=0;
	NtFreeVirtualMemory(NtCurrentProcess(),&buffer,&s,MEM_RELEASE);
	return 1;
}
bool GetProcessPath(HANDLE hProc, LPWSTR path)
{
	PROCESS_BASIC_INFORMATION info;
	PEB peb; PEB_LDR_DATA ldr;
	LDR_DATA_TABLE_ENTRY entry;
	if (NT_SUCCESS(NtQueryInformationProcess(hProc,ProcessBasicInformation,&info,sizeof(info),0)))
	if (info.PebBaseAddress)
	if (NT_SUCCESS(NtReadVirtualMemory(hProc,info.PebBaseAddress,&peb,sizeof(peb),0)))
	if (NT_SUCCESS(NtReadVirtualMemory(hProc,peb.Ldr,&ldr,sizeof(ldr),0)))
	if (NT_SUCCESS(NtReadVirtualMemory(hProc,(LPVOID)ldr.InLoadOrderModuleList.Flink,
		&entry,sizeof(LDR_DATA_TABLE_ENTRY),0)))
	if (NT_SUCCESS(NtReadVirtualMemory(hProc,entry.FullDllName.Buffer,
		path,MAX_PATH*2,0))) return true;
	return false;
}
bool GetProcessPath(DWORD pid, LPWSTR path)
{
	CLIENT_ID id;
	OBJECT_ATTRIBUTES oa={0};
	HANDLE hProc; 
	NTSTATUS status;
	id.UniqueProcess=pid;
	id.UniqueThread=0;
	oa.uLength=sizeof(oa);
	status=NtOpenProcess(&hProc,PROCESS_QUERY_INFORMATION|PROCESS_VM_READ,&oa,&id);
	if (NT_SUCCESS(status))
	{
		bool flag=GetProcessPath(hProc,path);
		NtClose(hProc);
		return flag;
	}
	else
		return false;
};
int OutputProcessList(int all=0)
{
	BYTE *pbBuffer=GetSystemInformation();
	if (pbBuffer==0) return 0;
	SYSTEM_PROCESS_INFORMATION *spiProcessInfo;
	HANDLE hProcess;
	DWORD ws,limit,size,total=0,pri=0;
	OBJECT_ATTRIBUTES attr={0};
	CLIENT_ID id;
	WCHAR pwcBuffer[0x100];
	attr.uLength=sizeof(attr);
	id.UniqueThread=0;
	limit=0;
	if (all) limit=0x8000;
	for (spiProcessInfo=(SYSTEM_PROCESS_INFORMATION*)pbBuffer; spiProcessInfo->dNext;)
	{
		spiProcessInfo=(SYSTEM_PROCESS_INFORMATION*)
			((DWORD)spiProcessInfo+spiProcessInfo->dNext);
		id.UniqueProcess=spiProcessInfo->dUniqueProcessId;
		if (NT_SUCCESS(NtOpenProcess(&hProcess,PROCESS_QUERY_INFORMATION|PROCESS_VM_READ,&attr,&id)))
		{
			size=spiProcessInfo->dCommitCharge>>10;
			if (GetProcessMemory(hProcess,size,ws))
			{
				pri+=size;
				total+=ws;
				if (size>=limit)
				{
					swprintf(pwcBuffer,L"%.4d %6dK %s",spiProcessInfo->dUniqueProcessId, 
						size, spiProcessInfo->usName.Buffer);
					ConsoleOutput(pwcBuffer);
				}
			}
			NtClose(hProcess);
		}
	}
	swprintf(pwcBuffer,L"Total\t%dK",total);
	ConsoleOutput(pwcBuffer);
	swprintf(pwcBuffer,L"Private\t%dK",pri);
	ConsoleOutput(pwcBuffer);
	delete pbBuffer;
	return 1;
}
int Convert(LPWSTR str, DWORD *num, LPWSTR delim)
{
	if (num==0) return -1;
	WCHAR t=*str,tc=*(str+0xF);
	WCHAR temp[0x10]={0};
	LPWSTR it=temp,istr=str,id=temp;
	if (delim) 
	{
		id=wcschr(delim,t);
		*(str+0xF)=delim[0];
	}
	else 
		*(str+0xF)=0;
	while (id==0&&t)
	{
		*it++=t;
		t=*++istr;
		if (delim)
			id=wcschr(delim,t);
	}
	swscanf(temp,L"%x",num);
	*(str+0xF)=tc;
	if (id==0||istr-str==0xF) return -1;
	if (t==0) return istr-str;
	else return id-delim;
}
bool Parse(LPWSTR cmd, HookParam& hp)
{
	int t;
	bool accept=false;
	memset(&hp,0,sizeof(hp));
	DWORD *data=&hp.off;
	LPWSTR offset=cmd+1;
	LPWSTR delim_str=L":*@!";
	LPWSTR delim=delim_str;
	if (*offset==L'n') 
	{
		offset++;
		hp.type|=NO_CONTEXT;
	}
	while (!accept)
	{
		t=Convert(offset,data,delim);
		if (t<0) 
		{
_error:
			ConsoleOutput(L"Syntax error.");
			return false;
		}
		offset=wcschr(offset,delim[t]);
		if (offset) offset++;
		else goto _error;
		switch (delim[t])
		{
		case L':':
			data=&hp.split;
			delim=delim_str+1;
			hp.type|=USING_SPLIT;
			break;
		case L'*':
			if (hp.split) 
			{
				data=&hp.split_ind;
				delim=delim_str+2;
				hp.type|=SPLIT_INDIRECT;
			}
			else 
			{
				hp.type|=DATA_INDIRECT;
				data=&hp.ind;
			}
			break;
		case L'@':
			accept=true;
			break;
		}
	}
	t=Convert(offset,&hp.addr,delim_str);
	if (t<0) return false;
	if (hp.off&0x80000000) hp.off-=4;
	if (hp.split&0x80000000) hp.split-=4;
	LPWSTR temp=offset;
	offset=wcschr(offset,L':');
	if (offset)
	{
		hp.type|=MODULE_OFFSET;
		offset++;
		delim=wcschr(offset,L':');
		
		if (delim)
		{
			*delim++=0;
			_wcslwr(offset);
			hp.function=Hash(delim);
			hp.module=Hash(offset,delim-offset-1);
			hp.type|=FUNCTION_OFFSET;
		}			
		else
		{		
			hp.module=Hash(_wcslwr(offset));
		}
	}
	else
	{
		offset=wcschr(temp,L'!');
		if (offset)
		{
			hp.type|=MODULE_OFFSET;
			swscanf(offset+1,L"%x",&hp.module);
			offset=wcschr(offset+1,L'!');
			if (offset)
			{
				hp.type|=FUNCTION_OFFSET;
				swscanf(offset+1,L"%x",&hp.function);
			}
		}
	}
	switch (*cmd)
	{
	case L's':
		hp.type|=USING_STRING;
		break;
	case L'e':
		hp.type|=STRING_LAST_CHAR;
	case L'a':
		hp.type|=BIG_ENDIAN;
		hp.length_offset=1;
		break;
	case L'b':
		hp.length_offset=1;
		break;
	case L'h':
		hp.type|=PRINT_DWORD;
	case L'q':
		hp.type|=USING_STRING|USING_UNICODE;
		break;
	case L'l':
		hp.type|=STRING_LAST_CHAR;
	case L'w':
		hp.type|=USING_UNICODE;
		hp.length_offset=1;
		break;
	default:
		break;
	}
	//ConsoleOutput(L"Try to insert additional hook.");
	return true;
}
BOOL ActiveDetachProcess(DWORD pid)
{
	DWORD module,engine,dwWrite;
	HANDLE hProc,hThread;	
	hProc=GetProcessByPID(pid);
	module=GetModuleByPID(pid);
	if (module==0) return FALSE;
	engine=GetEngineByPID(pid);
	engine&=~0xFF;
	SendParam sp={0};
	sp.type=4;
	cmdq->AddRequest(sp,pid);
	dwWrite=0x1000;
	hThread=IthCreateThread(LdrUnloadDll,engine,hProc);
	if (hThread==0||hThread==INVALID_HANDLE_VALUE) return FALSE;
	NtWaitForSingleObject(hThread,0,0);
	NtClose(hThread);
	hThread=IthCreateThread(LdrUnloadDll,module,hProc);
	if (hThread==0||hThread==INVALID_HANDLE_VALUE) return FALSE;
	NtWaitForSingleObject(hThread,0,0);
	THREAD_BASIC_INFORMATION info;
	NtQueryInformationThread(hThread,ThreadBasicInformation,&info,sizeof(info),0);					
	NtClose(hThread);	
	NtSetEvent(hPipeExist,0);
	dwWrite=0x1000;
	return info.ExitStatus;
}
DWORD CommandQueue::ProcessCommand(LPWSTR cmd)
{
	int t;
	LPWSTR ts=wcsrchr(cmd,L':');
	if (ts) *ts=0;
	_wcslwr(cmd);
	if (ts) *ts=L':';
	DWORD pid=0,current_pid=GetCurrentPID();
	//WCHAR str[0x200];

	switch (cmd[0])
	{
	case L'/':
		switch (cmd[1])
		{
		case L'p':
			{			
				if (cmd[2]==L'n') 
				{
					pid=PIDByName(cmd+3);
					if (pid==0) break;
				}
				else
					swscanf(cmd+2,L"%d",&pid);
				t=InjectByPID(pid);
			}
			break;
		case L'h':
			{
				SendParam sp;
				sp.type=0;
				if (Parse(cmd+2,sp.hp)) AddRequest(sp);
			}
			break;
		default:
			ConsoleOutput(L"Syntax error.");
		}
		break;
	}
	/*case L'm':
		if (current_pid==0)
			ConsoleOutput(L"No process hooked.");
		else
		{
			SendParam sp;
			memset(&sp,0,sizeof(sp));
			sp.type=1;
			ConsoleOutput(L"Target module list:");
			AddRequest(sp);
		}
		break;
	case L'n':
		if (current_pid==0)
			ConsoleOutput(L"No process hooked.");
		else
		{
			SendParam sp;
			memset(&sp,0,sizeof(sp));
			sp.type=2;
			memcpy(&sp.hp,L"test.dll",16);
			ConsoleOutput(L"Target module list:");
			AddRequest(sp);
		}
		break;
	case L't':
		{
			int result;
			switch (cmd[1])
			{
			case L'r':
				swscanf(cmd+2,L"%x",&pid);
				result=PerformThread(current_pid,pid,Resume);
				break;
			case L's':
				swscanf(cmd+2,L"%x",&pid);
				result=PerformThread(current_pid,pid,Suspend);
				break;
			case L't':
				swscanf(cmd+2,L"%x",&pid);
				result=PerformThread(current_pid,pid,Terminate);
				break;
			default:
				result=PerformThread(current_pid);
			}
			if (result==0) ConsoleOutput(L"Can't operate on process.");
			break;
		}
	case L'c':
		if (cmd[1]==L'l') 
			ClearText(0,-1,-1,-1);
		else
		{
			swprintf(str,L"Current PID: %d",current_pid);
			ConsoleOutput(str);
		}
		break;
	case L's':
		{
			swscanf(cmd+1,L"%d",&pid);
			if (GetCmdHandleByPID(pid))
			{
				current_pid=pid;
				swprintf(str,L"Current PID: %d",current_pid);
				ConsoleOutput(str);
			}
			else
				ConsoleOutput(L"Process is not injected.");
		}
		break;
	case L'p':
		{
			int t=0;
			switch (cmd[1])
			{
			case L'a': t=1;break;
			case L'l': break;
			}
			ConsoleOutput(L"Process list:");
			TestTime(OutputProcessList(t));
			break;
		}
	case L'l':
		{
			DWORD from,to;
			swscanf(cmd+1,L"%x-%x",&from,&to);
			AddLink(from&0xFFFF,to&0xFFFF);
		}
		break;
	case L'?':
		ConsoleOutput(L"Command list:");
		ConsoleOutput(L"h: Display this help.");
		ConsoleOutput(L"p: Get a list of process.");
		ConsoleOutput(L"pa: Get a list of process with memory usage above 32M.");
		ConsoleOutput(L"c: Display current select PID.");
		ConsoleOutput(L"cl: Clear the console thread.");
		ConsoleOutput(L"s[pid]: Set current select PID, pid is demical number.");
		ConsoleOutput(L"t: Get a list of thread of current select process.");
		ConsoleOutput(L"t{t/s/r}[addr]:Operate on thread with start address equal addr.");
		ConsoleOutput(L"t-Terminate s-Suspend r-Resume.");
		ConsoleOutput(L"m: Get a list of module loaded by the current select process.");
		break;
	}*/
	return 0;
}
