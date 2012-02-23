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

#include <windows.h>
#include "..\ntdll64.h"
#include "..\sys.h"
#include "asm.h"
#define SEC_BASED 0x200000
WCHAR file_path[MAX_PATH]=L"\\??\\";
LPWSTR current_dir;
LPVOID code_page;
UINT_PTR current_process_id;
HANDLE hHeap, root_obj, codepage_section, thread_man_section, thread_man_mutex;
PEB* peb;
TEB* teb;
__declspec(align(16)) UINT_PTR share_mask[2]={0x100,0x100};
BYTE LeadByteTable[0x100]={
	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
	1,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
	2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
	2,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
	2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
	2,2,2,2,2,2,2,2,2,2,2,2,2,1,1,1
};
BYTE launch_time[0x10];
static BYTE file_info[0x400];
BYTE ThreadStart[0x10]={
	0x48, 0x83, 0xEC, 0x28, //sub rsp, 0x28. Critical.
	0xFF, 0xD0, //call rax, thread
	0x48, 0x89, 0xC2, //mov rcx,rax
	0x6A, 0xFE, 0x59, //mov rdx,=-2; push -2, pop rdx
	0xFF, 0xD3, //call rbx, terminate thread.
	0xCC
};
class ThreadStartManager
{
public:
	LPVOID GetProcessAddr(HANDLE hProc)
	{
		UINT_PTR pid,addr,len;
		if (hProc==NtCurrentProcess()) pid=current_process_id;
		else
		{
			PROCESS_BASIC_INFORMATION info;
			NtQueryInformationProcess(hProc,ProcessBasicInformation,&info,sizeof(info),&len);
			pid=info.uUniqueProcessId;
		}
		pid>>=2;
		for (UINT_PTR i=0;i<count;i++)
		{
			if ((proc_record[i]&0xFFF)==pid)
			{
				addr=proc_record[i]&~0xFFF;
				return (LPVOID)addr;
			}
		}
		len=0x1000;
		NtAllocateVirtualMemory(hProc,(PVOID*)(proc_record+count),0,&len,
			MEM_COMMIT,PAGE_EXECUTE_READWRITE);
		addr=proc_record[count];
		proc_record[count]|=pid;
		NtWriteVirtualMemory(hProc,(PVOID)addr,ThreadStart,0x10,&len);
		count++;
		return (LPVOID)addr;
	}
	void ReleaseProcessMemory(HANDLE hProc)
	{
		UINT_PTR pid,addr,len;
		if (hProc==NtCurrentProcess()) pid=current_process_id;
		else
		{
			PROCESS_BASIC_INFORMATION info;
			NtQueryInformationProcess(hProc,ProcessBasicInformation,&info,sizeof(info),&len);
			pid=info.uUniqueProcessId;
		}
		pid>>=2;
		NtWaitForSingleObject(thread_man_mutex,0,0);
		for (UINT_PTR i=0;i<count;i++)
		{
			if ((proc_record[i]&0xFFF)==pid)
			{
				addr=proc_record[i]&~0xFFF;
				UINT_PTR size=0x1000;
				NtFreeVirtualMemory(hProc,(PVOID*)&addr,&size,MEM_RELEASE);
				count--;
				for (UINT_PTR j=i;j<count;j++)
				{
					proc_record[j]=proc_record[j+1];
				}
				proc_record[count]=0;
				NtReleaseMutant(thread_man_mutex,0);
				return;
			}
		}
		NtReleaseMutant(thread_man_mutex,0);
	}
private:
	UINT_PTR count;
	UINT_PTR proc_record[1];
};
ThreadStartManager* thread_man;
extern "C" {
int FillRange(LPWSTR name,PUINT_PTR lower, PUINT_PTR upper)
{
	LDR_DATA_TABLE_ENTRY *it;
	LIST_ENTRY *begin;
	it=(LDR_DATA_TABLE_ENTRY*)(peb->Ldr->InLoadOrderModuleList.Flink);
	begin=(LIST_ENTRY*)it;
	while (it->SizeOfImage)
	{
		if (name==0||_wcsicmp(it->BaseDllName.Buffer,name)==0)
		{
			*lower=(UINT_PTR)it->DllBase;
			*upper=*lower;
			MEMORY_BASIC_INFORMATION info={0};
			UINT_PTR l,size; 
			size=0;
			do
			{
				NtQueryVirtualMemory(NtCurrentProcess(),(LPVOID)(*upper),MemoryBasicInformation,&info,sizeof(info),&l);
				if (info.Protect&PAGE_NOACCESS) 
				{
					it->SizeOfImage=size;
					break;
				}
				size+=info.RegionSize;
				*upper+=info.RegionSize;
			}while (size<it->SizeOfImage);
			return 1;
		}
		it=(PLDR_DATA_TABLE_ENTRY)it->InLoadOrderModuleList.Flink;
		if (it->InLoadOrderModuleList.Flink==begin) break;
	}
	return 0;
}
UINT_PTR IthGetMemoryRange(LPVOID mem, UINT_PTR* base, UINT_PTR* size)
{
	UINT_PTR r;
	MEMORY_BASIC_INFORMATION info;
	NtQueryVirtualMemory(NtCurrentProcess(),mem,MemoryBasicInformation,&info,sizeof(info),&r);
	if (base) *base=(UINT_PTR)info.BaseAddress;
	if (size) *size=info.RegionSize;
	return (info.Type&PAGE_NOACCESS)==0;
}
void FreeThreadStart(HANDLE hProc)
{
	thread_man->ReleaseProcessMemory(hProc);
}
void IthInitSystemService()
{
	LPWSTR t,obj;
	UNICODE_STRING us;
	UINT_PTR mem,size,heap_info;
	OBJECT_ATTRIBUTES oa={sizeof(oa),0,&us,OBJ_CASE_INSENSITIVE,0,0};
	IO_STATUS_BLOCK ios;
	HANDLE codepage_file;
	LARGE_INTEGER sec_size={0x1000,0};
	GetPebAndTeb(&peb,&teb);
	current_process_id=teb->Cid.UniqueProcess;
	heap_info=2;
	hHeap=RtlCreateHeap(0x1002,0,0,0,0,0);
	RtlSetHeapInformation(hHeap,HeapCompatibilityInformation,&heap_info,sizeof(heap_info));
	mem=GetShareMemory();
	IthGetMemoryRange((LPVOID)mem,0,&size);
	t=(LPWSTR)(mem+SearchPattern(mem,size,L"system32",0x10));
	for (obj=t;*obj!=L'\\';obj++);
	RtlInitUnicodeString(&us,obj);
	NtOpenDirectoryObject(&root_obj,READ_CONTROL|0xF,&oa);
	if (*NlsAnsiCodePage==0x3A4)
	{
		code_page=peb->InitAnsiCodePageData;
		oa.hRootDirectory=root_obj;
		oa.uAttributes|=OBJ_OPENIF;
	}
	else
	{
		while (*t--!=L':');
		wcscpy(file_path+4,t);
		t=file_path;
		while(*++t);
		if (*(t-1)!=L'\\') *t++=L'\\';
		wcscpy(t,L"C_932.nls");
		RtlInitUnicodeString(&us,file_path);
		NtOpenFile(&codepage_file,FILE_READ_DATA,&oa,&ios,FILE_SHARE_READ,0);
		oa.hRootDirectory=root_obj;
		oa.uAttributes|=OBJ_OPENIF;
		RtlInitUnicodeString(&us,L"JPN_CodePage");	
		NtCreateSection(&codepage_section,SECTION_MAP_READ,&oa,0,PAGE_READONLY,SEC_COMMIT,codepage_file);
		NtClose(codepage_file); 
		size=0;
		NtMapViewOfSection(codepage_section,NtCurrentProcess(),&code_page,0,0,0,&size,ViewUnmap,0,PAGE_READONLY);
	}
	wcscpy(file_path+4,GetModulePath());
	current_dir=wcsrchr(file_path,L'\\')+1;
	
	RtlInitUnicodeString(&us,L"ITH_SysSection");
	NtCreateSection(&thread_man_section,SECTION_ALL_ACCESS,&oa,&sec_size,
		PAGE_EXECUTE_READWRITE,SEC_COMMIT,0); 
	size=0;
	NtMapViewOfSection(thread_man_section,NtCurrentProcess(),
		(PVOID*)&thread_man,0,0,0,&size,ViewUnmap,0,PAGE_EXECUTE_READWRITE);
	thread_man_mutex=IthCreateMutex(L"ITH_ThreadMan",0);
}
void IthCloseSystemService()
{
	if (*NlsAnsiCodePage!=0x3A4)
	{
		NtUnmapViewOfSection(NtCurrentProcess(),code_page);
		NtClose(codepage_section);
	}
	NtUnmapViewOfSection(NtCurrentProcess(),thread_man);
	RtlDestroyHeap(hHeap);
	NtClose(root_obj);
	NtClose(thread_man_mutex);
	NtClose(thread_man_section);

}
BOOL IthCheckFile(LPWSTR file)
{
	wcscpy(current_dir,file);
	return IthCheckFileFullPath(file_path);
}
BOOL IthFindFile(LPWSTR file)
{
	NTSTATUS status;
	LPWSTR path=wcsrchr(file,L'\\');
	if (path)
	{
		memcpy(current_dir,file,(path-file)<<1);
		current_dir[path-file]=0;
		file=path+1;
	}
	else current_dir[0]=0;
	HANDLE h;
	UNICODE_STRING us;
	RtlInitUnicodeString(&us,file_path);
	OBJECT_ATTRIBUTES oa={sizeof(oa),0,&us,OBJ_CASE_INSENSITIVE,0,0};
	IO_STATUS_BLOCK ios;
	if (NT_SUCCESS(NtOpenFile(&h,FILE_LIST_DIRECTORY|SYNCHRONIZE,
		&oa,&ios,FILE_SHARE_READ,FILE_DIRECTORY_FILE|FILE_SYNCHRONOUS_IO_NONALERT)))
	{
		RtlInitUnicodeString(&us,file);
		status=NtQueryDirectoryFile(h,0,0,0,&ios,file_info,0x400,FileBothDirectoryInformation,TRUE,&us,0);
		NtClose(h);
		return NT_SUCCESS(status);
	}
	return FALSE;
}
BOOL IthCheckFileFullPath(LPWSTR file)
{
	UNICODE_STRING us;
	RtlInitUnicodeString(&us,file);
	OBJECT_ATTRIBUTES oa={sizeof(oa),0,&us,OBJ_CASE_INSENSITIVE,0,0};
	HANDLE hFile;
	IO_STATUS_BLOCK isb;
	if (NT_SUCCESS(NtCreateFile(&hFile,FILE_READ_DATA,&oa,&isb,0,0,FILE_SHARE_READ,FILE_OPEN,0,0,0)))
	{
		NtClose(hFile);
		return TRUE;
	}
	else return FALSE;
}
HANDLE IthCreateFile(LPWSTR name, DWORD option, UINT_PTR share, UINT_PTR disposition)
{
	wcscpy(current_dir,name);
	UNICODE_STRING us;
	RtlInitUnicodeString(&us,file_path);
	OBJECT_ATTRIBUTES oa={sizeof(oa),0,&us,OBJ_CASE_INSENSITIVE,0,0};
	HANDLE hFile;
	IO_STATUS_BLOCK isb;
	if (NT_SUCCESS(NtCreateFile(&hFile,
		option|FILE_READ_ATTRIBUTES|SYNCHRONIZE
		,&oa,&isb,0,0,share,disposition,
		FILE_SYNCHRONOUS_IO_NONALERT|FILE_NON_DIRECTORY_FILE,0,0)))
		return hFile;
	else return INVALID_HANDLE_VALUE;
}
HANDLE IthCreateFileFullPath(LPWSTR full_path, DWORD option, UINT_PTR share, UINT_PTR disposition)
{
	WCHAR path[MAX_PATH]=L"\\??\\";
	wcscpy(path+4,full_path);
	UNICODE_STRING us;
	RtlInitUnicodeString(&us,path);
	OBJECT_ATTRIBUTES oa={sizeof(oa),0,&us,OBJ_CASE_INSENSITIVE,0,0};
	HANDLE hFile;
	IO_STATUS_BLOCK isb;
	if (NT_SUCCESS(NtCreateFile(&hFile,
		option|FILE_READ_ATTRIBUTES|SYNCHRONIZE
		,&oa,&isb,0,0,share,disposition,
		FILE_SYNCHRONOUS_IO_NONALERT|FILE_NON_DIRECTORY_FILE,0,0)))
		return hFile;
	else return INVALID_HANDLE_VALUE;
}
HANDLE IthPromptCreateFile(DWORD option, UINT_PTR share, UINT_PTR disposition)
{
	OPENFILENAME ofn={sizeof(ofn)};       // common dialog box structure
	WCHAR szFile[MAX_PATH];       // buffer for file name
	wcscpy(current_dir,L"ITH_export.txt");
	wcscpy(szFile,file_path+4);

	//szFile[0]=0;
	ofn.lpstrFile = szFile;
	ofn.nMaxFile = MAX_PATH;
	ofn.lpstrFilter = L"Text\0*.txt";
	BOOL result;
	if (disposition==FILE_OPEN)
		result=GetOpenFileName(&ofn);
	else
		result=GetSaveFileName(&ofn);
	if (result)
	{
		LPWSTR s=szFile+wcslen(szFile)-4;
		if (_wcsicmp(s,L".txt")!=0) wcscpy(s+4,L".txt");
		return IthCreateFileFullPath(szFile,option,share,disposition);
	}
	else return INVALID_HANDLE_VALUE;
}
HANDLE IthCreateSection(LPWSTR name, UINT_PTR size, UINT_PTR right)
{
	HANDLE hSection;
	LARGE_INTEGER s;
	s.QuadPart=size;
	if (name)
	{
		
		UNICODE_STRING us;
		RtlInitUnicodeString(&us,name);
		OBJECT_ATTRIBUTES oa={sizeof(oa),root_obj,&us,OBJ_OPENIF,0,0};
		if (NT_SUCCESS(NtCreateSection(&hSection,GENERIC_ALL,&oa,&s,
			right,SEC_COMMIT,0)))
			return hSection;
		else return INVALID_HANDLE_VALUE;
	}
	else
	{
		if (NT_SUCCESS(NtCreateSection(&hSection,GENERIC_ALL,0,&s,
			right,SEC_COMMIT,0)))
			return hSection;
		else return INVALID_HANDLE_VALUE;
	}
}
HANDLE IthCreateEvent(LPWSTR name, UINT_PTR auto_reset, UINT_PTR init_state)
{
	HANDLE hEvent;
	if (name)
	{
		UNICODE_STRING us;
		RtlInitUnicodeString(&us,name);
		OBJECT_ATTRIBUTES oa={sizeof(oa),root_obj,&us,OBJ_OPENIF,0,0};
		if (NT_SUCCESS(NtCreateEvent(&hEvent,EVENT_ALL_ACCESS,&oa,auto_reset,init_state)))
			return hEvent;
	}
	else if (NT_SUCCESS(NtCreateEvent(&hEvent,EVENT_ALL_ACCESS,0,auto_reset,init_state)))
			return hEvent;
	return INVALID_HANDLE_VALUE;
}
HANDLE IthOpenEvent(LPWSTR name)
{
	UNICODE_STRING us;
	RtlInitUnicodeString(&us,name);
	OBJECT_ATTRIBUTES oa={sizeof(oa),root_obj,&us,0,0,0};
	HANDLE hEvent;
	if (NT_SUCCESS(NtOpenEvent(&hEvent,EVENT_ALL_ACCESS,&oa)))
		return hEvent;
	else return INVALID_HANDLE_VALUE;
}
void IthSetEvent(HANDLE hEvent)
{
	NtSetEvent(hEvent,0);
}
void IthResetEvent(HANDLE hEvent)
{
	NtClearEvent(hEvent);
}
HANDLE IthCreateMutex(LPWSTR name, BOOL InitialOwner, UINT_PTR* exist)
{
	UNICODE_STRING us;
	HANDLE hMutex; NTSTATUS status;
	if (name)
	{
		RtlInitUnicodeString(&us,name);
		OBJECT_ATTRIBUTES oa={sizeof(oa),root_obj,&us,OBJ_OPENIF,0,0};
		status=NtCreateMutant(&hMutex,MUTEX_ALL_ACCESS,&oa,InitialOwner);
	}
	else status=NtCreateMutant(&hMutex,MUTEX_ALL_ACCESS,0,InitialOwner);
	if (NT_SUCCESS(status))
	{
		if (exist) *exist=(STATUS_OBJECT_NAME_EXISTS==status);
		return hMutex;
	}
	else 
		return INVALID_HANDLE_VALUE;
}
HANDLE IthOpenMutex(LPWSTR name)
{
	UNICODE_STRING us;
	RtlInitUnicodeString(&us,name);
	OBJECT_ATTRIBUTES oa={sizeof(oa),root_obj,&us,0,0,0};
	HANDLE hMutex;
	if (NT_SUCCESS(NtOpenMutant(&hMutex,MUTEX_ALL_ACCESS,&oa)))
		return hMutex;
	else return INVALID_HANDLE_VALUE;
}
BOOL IthReleaseMutex(HANDLE hMutex)
{
	return NT_SUCCESS(NtReleaseMutant(hMutex,0));
}
void IthSleep(UINT_PTR time)
{
	LARGE_INTEGER t;
	t.QuadPart=-10000*time;
	NtDelayExecution(0,&t);
}
#define DEFAULT_STACK_LIMIT 0x400000
#define DEFAULT_STACK_COMMIT 0x10000
#define PAGE_SIZE 0x1000

HANDLE IthCreateThread(LPVOID start_addr, UINT_PTR param, HANDLE hProc)
{
	HANDLE hThread;
	CLIENT_ID id;
	LPVOID protect;
	USER_STACK stack={};
	CONTEXT ctx={};
	ctx.ContextFlags=CONTEXT_FULL;
	UINT_PTR size=DEFAULT_STACK_LIMIT;
	UINT_PTR commit=DEFAULT_STACK_COMMIT;
	UINT_PTR x;
	NtAllocateVirtualMemory(hProc,&stack.ExpandableStackBottom,
		0,&size,MEM_RESERVE,PAGE_READWRITE);
	stack.ExpandableStackBase=(char*)stack.ExpandableStackBottom+size;
	stack.ExpandableStackLimit=(char*)stack.ExpandableStackBase-commit;
	size=PAGE_SIZE;
	commit+=size;
	protect=(char*)stack.ExpandableStackBase-commit;
	NtAllocateVirtualMemory(hProc,&protect,0,&commit,MEM_COMMIT,PAGE_READWRITE);
	NtProtectVirtualMemory(hProc,&protect,&size,PAGE_READWRITE|PAGE_GUARD,&x);
	ctx.Rax=(DWORD64)start_addr;
	ctx.Rcx=(DWORD64)param;
	ctx.Rbx=(DWORD64)NtTerminateThread;
	ctx.Rsp=(DWORD64)stack.ExpandableStackBase-0x8;
	NtWaitForSingleObject(thread_man_mutex,0,0);
	ctx.Rip=(UINT_PTR)thread_man->GetProcessAddr(hProc);
	NtReleaseMutant(thread_man_mutex,0);

	if (NT_SUCCESS(NtCreateThread(&hThread,THREAD_ALL_ACCESS,0,hProc,&id,&ctx,&stack,0)))
		return hThread;
	else
		return INVALID_HANDLE_VALUE;
}

UINT_PTR GetExportAddress(UINT_PTR hModule,UINT_PTR hash)
{
	IMAGE_DOS_HEADER *DosHdr;
	IMAGE_NT_HEADERS *NtHdr;
	IMAGE_EXPORT_DIRECTORY *ExtDir;
	UINT uj;
	char* pcExportAddr,*pcFuncPtr,*pcBuffer;
	UINT_PTR dwReadAddr,dwFuncAddr,dwFuncName;
	WORD wOrd;
	DosHdr=(IMAGE_DOS_HEADER*)hModule;
	if (IMAGE_DOS_SIGNATURE==DosHdr->e_magic)
	{
		dwReadAddr=hModule+DosHdr->e_lfanew;
		NtHdr=(IMAGE_NT_HEADERS*)dwReadAddr;
		if (IMAGE_NT_SIGNATURE==NtHdr->Signature)
		{
			pcExportAddr=(char*)((UINT_PTR)hModule+
				(UINT_PTR)NtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
			if (pcExportAddr==0) return 0;
			ExtDir=(IMAGE_EXPORT_DIRECTORY*)pcExportAddr;
			pcExportAddr=(char*)((UINT_PTR)hModule+(UINT_PTR)ExtDir->AddressOfNames);

			for (uj=0;uj<ExtDir->NumberOfNames;uj++)
			{
				dwFuncName=*(DWORD*)pcExportAddr;
				pcBuffer=(char*)(hModule+dwFuncName);
				if (GetHash(pcBuffer)==hash)
				{
					pcFuncPtr=(char*)((UINT_PTR)hModule+(UINT_PTR)ExtDir->AddressOfNameOrdinals+(uj*sizeof(WORD)));
					wOrd=*(WORD*)pcFuncPtr;
					pcFuncPtr=(char*)((UINT_PTR)hModule+(UINT_PTR)ExtDir->AddressOfFunctions+(wOrd*sizeof(DWORD)));
					dwFuncAddr=*(DWORD*)pcFuncPtr;
					return hModule+dwFuncAddr;
				}
				pcExportAddr+=sizeof(DWORD);
			}
		}
	}
	return 0;
}

}
