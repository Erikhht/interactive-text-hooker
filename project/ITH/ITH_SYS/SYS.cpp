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
#include "..\ntdll.h"
#include "..\sys.h"
#define SEC_BASED 0x200000
WCHAR file_path[MAX_PATH]=L"\\??\\";
LPWSTR current_dir;
LPVOID page;
DWORD current_process_id;
HANDLE hHeap, root_obj, codepage_section, thread_man_section, thread_man_mutex;
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
DWORD GetShareMemory()
{
	__asm
	{
		mov eax,fs:[0x30]
		mov eax,[eax+0x4C]
	}
}
LARGE_INTEGER* GetTimeBias()
{
	__asm mov eax,0x7ffe0020
}
__declspec(naked) void ThreadStart()
{
	__asm{
		nop
		call eax
		push eax
		push -2
		call dword ptr [NtTerminateThread]
	}
}
class ThreadStartManager
{
public:
	LPVOID GetProcAddr(HANDLE hProc)
	{
		DWORD pid,addr,len;
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
		BYTE buffer[0x10];

		memcpy(buffer,ThreadStart,0x8);
		*((DWORD*)buffer+3)=(DWORD)NtTerminateThread;
		*((DWORD*)buffer+2)=(DWORD)addr+0xC;
		NtWriteVirtualMemory(hProc,(PVOID)addr,buffer,0x10,&len);
		count++;
		return (LPVOID)addr;
	}
	void ReleaseProcessMemory(HANDLE hProc)
	{
		DWORD pid,addr,len;
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
				DWORD size=0x1000;
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
	void CheckProcessMemory()
	{
		UINT_PTR i,j,flag,addr;
		DWORD len;
		CLIENT_ID id;
		OBJECT_ATTRIBUTES oa={0};
		HANDLE hProc;
		BYTE buffer[8];
		id.UniqueThread=0;
		oa.uLength=sizeof(oa);
		for (i=0;i<count;i++)
		{
			id.UniqueProcess=(proc_record[i]&0xFFF)<<2;
			addr=proc_record[i]&~0xFFF;
			flag=0;
			if (NT_SUCCESS(NtOpenProcess(&hProc,PROCESS_VM_OPERATION|PROCESS_VM_READ,&oa,&id)))	
			{
				if (NT_SUCCESS(NtReadVirtualMemory(hProc,(PVOID)addr,buffer,8,&len)))
					if (memcmp(buffer,ThreadStart,8)==0) flag=1;
				NtClose(hProc);
			}
			if (flag==0)
			{
				for (j=i;j<count;j++) proc_record[j]=proc_record[j+1];
				count--; i--;
			}
		}
	}
private:
	UINT_PTR count;
	DWORD proc_record[1];
};
ThreadStartManager* thread_man;
extern "C" {
int FillRange(LPWSTR name,DWORD* lower, DWORD* upper)
{
	PLDR_DATA_TABLE_ENTRY it;
	LIST_ENTRY *begin;
	__asm
	{
		mov eax,fs:[0x30]
		mov eax,[eax+0xC]
		mov eax,[eax+0xC]
		mov it,eax
		mov begin,eax
	}
	while (it->SizeOfImage)
	{
		if (_wcsicmp(it->BaseDllName.Buffer,name)==0)
		{
			*lower=(DWORD)it->DllBase;
			*upper=*lower;
			MEMORY_BASIC_INFORMATION info={0};
			DWORD l,size; 
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
DWORD SearchPattern(DWORD base, DWORD base_length, LPVOID search, DWORD search_length) //KMP
{
	__asm
	{
		mov eax,search_length
alloc:
		push 0
		sub eax,1
		jnz alloc

		mov edi,search
		mov edx,search_length 
		mov ecx,1
		xor esi,esi
build_table:
		mov al,byte ptr [edi+esi]
		cmp al,byte ptr [edi+ecx]
		sete al
		test esi,esi
		jz pre
		test al,al
		jnz pre
		mov esi,[esp+esi*4-4]
		jmp build_table
pre:
		test al,al
		jz write_table
		inc esi
write_table:
		mov [esp+ecx*4],esi

		inc ecx
		cmp ecx,edx
		jb build_table

		mov esi,base
		xor edx,edx
		mov ecx,edx
matcher:
		mov al,byte ptr [edi+ecx]
		cmp al,byte ptr [esi+edx]
		sete al
		test ecx,ecx
		jz match
		test al,al
		jnz match
		mov ecx, [esp+ecx*4-4]
		jmp matcher
match:
		test al,al
		jz pre2
		inc ecx
		cmp ecx,search_length
		je finish
pre2:
		inc edx
		cmp edx,base_length //search_length
		jb matcher
		mov edx,search_length
		dec edx
finish:
		mov ecx,search_length
		sub edx,ecx
		lea eax,[edx+1]
		lea ecx,[ecx*4]
		add esp,ecx
	}
}
/*DWORD SearchPattern_SSE(DWORD base, DWORD base_length, LPVOID search, DWORD search_length)
{

}
int str_kmp_c(const char* s1, int cnt1, const char* s2, int cnt2 )
{
	int i, j;
	i = 0; j = 0;
	while ( i+j < cnt1)
	{
		if( s2[i] == s1[i+j]) 
		{
			i++;
			if( i == cnt2) break; // found full match
		}
		else
		{
			j = j+i - ovrlap_tbl[i]; // update the offset in s1 to start next round of string compare
			if( i > 0)
			{
				i = ovrlap_tbl[i]; // update the offset of s2 for next string compare should start at
			}
		}
	};
	return j;
}*/
DWORD IthGetMemoryRange(LPVOID mem, DWORD* base, DWORD* size)
{
	DWORD r;
	MEMORY_BASIC_INFORMATION info;
	NtQueryVirtualMemory(NtCurrentProcess(),mem,MemoryBasicInformation,&info,sizeof(info),&r);
	if (base) *base=(DWORD)info.BaseAddress;
	if (size) *size=info.RegionSize;
	return (info.Type&PAGE_NOACCESS)==0;
}
LPWSTR GetModulePath()
{
	__asm
	{
		mov eax,fs:[0x30]
		mov eax,[eax+0xC]
		mov eax,[eax+0xC]
		mov eax,[eax+0x28]
	}
}
int MB_WC(char* mb, wchar_t* wc)
{
	__asm
	{
		mov esi,mb
		mov edi,wc
		mov edx,page
		lea ebx,LeadByteTable
		add edx,0x220
		push 0
_mb_translate:
		movzx eax,word ptr [esi]
		test al,al
		jz _mb_fin
		movzx ecx,al
		xlat
		test al,1
		cmovnz cx, word ptr [ecx*2+edx-0x204]
		jnz _mb_next
		mov cx,word ptr [ecx*2+edx]
		mov cl,ah
		mov cx, word ptr [ecx*2+edx]
_mb_next:
		mov [edi],cx
		add edi,2
		movzx eax,al
		add esi,eax
		inc dword ptr [esp]
		jmp _mb_translate
_mb_fin:
		pop eax
	}
}
int MB_WC_count(char* mb, int mb_length)
{
	__asm
	{
		xor eax,eax
		xor edx,edx
		mov esi,mb
		mov edi,mb_length
		lea ebx,LeadByteTable
_mbc_count:
		mov dl,byte ptr [esi]
		movzx ecx, byte ptr [ebx+edx]
		add esi,ecx
		inc eax
		sub edi,ecx
		ja _mbc_count
	}
}
int WC_MB(wchar_t *wc, char* mb)
{
	__asm
	{
		mov esi,wc
		mov edi,mb
		mov edx,page
		add edx,0x7C22
		xor ebx,ebx
_wc_translate:
		movzx eax,word ptr [esi]
		test eax,eax
		jz _wc_fin
		mov cx,word ptr [eax*2+edx]
		test ch,ch
		jz _wc_single
		mov [edi+ebx],ch
		inc ebx
_wc_single:
		mov [edi+ebx],cl
		inc ebx
		add esi,2
		jmp _wc_translate
_wc_fin:
		mov eax,ebx
	}
}
void FreeThreadStart(HANDLE hProc)
{
	thread_man->ReleaseProcessMemory(hProc);
}
void CheckThreadStart()
{
	thread_man->CheckProcessMemory();
}
void IthInitSystemService()
{
	ULONG b; LPWSTR t,obj;
	UNICODE_STRING us;
	DWORD mem,size;
	OBJECT_ATTRIBUTES oa={sizeof(oa),0,&us,OBJ_CASE_INSENSITIVE,0,0};
	IO_STATUS_BLOCK ios;
	HANDLE codepage_file;
	LARGE_INTEGER sec_size={0x1000,0};
	__asm
	{
		mov eax,fs:[0x18]
		mov ecx,[eax+0x20]
		mov current_process_id,ecx
	}
	b=2;
	hHeap=RtlCreateHeap(0x1002,0,0,0,0,0);
	RtlSetHeapInformation(hHeap,HeapCompatibilityInformation,&b,sizeof(b));
	mem=GetShareMemory();
	IthGetMemoryRange((LPVOID)mem,0,&size);
	t=(LPWSTR)(mem+SearchPattern(mem,size,L"system32",0x10));
	for (obj=t;*obj!=L'\\';obj++);
	RtlInitUnicodeString(&us,obj);
	NtOpenDirectoryObject(&root_obj,READ_CONTROL|0xF,&oa);
	if (*NlsAnsiCodePage==0x3A4)
	{
		__asm
		{
			mov eax,fs:[0x30]
			mov eax,[eax+0x58]
			mov page,eax
		}
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
	NtMapViewOfSection(codepage_section,NtCurrentProcess(),&page,0,0,0,&size,ViewUnmap,0,PAGE_READONLY);
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
	/*LARGE_INTEGER time;
	NtQuerySystemTime(&time);
	time.QuadPart-=GetTimeBias()->QuadPart;
	RtlTimeToTimeFields(&time,(TIME_FIELDS*)&launch_time);*/
}
void IthCloseSystemService()
{
	if (*NlsAnsiCodePage!=0x3A4)
	{
		NtUnmapViewOfSection(NtCurrentProcess(),page);
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
BOOL IthGetFileInfo(LPWSTR file, LPVOID info)
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
		status=NtQueryDirectoryFile(h,0,0,0,&ios,info,0x1000,FileBothDirectoryInformation,0,&us,0);
		status=NT_SUCCESS(status);
	}
	else
		status=FALSE;
	NtClose(h);
	return status;
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
HANDLE IthCreateFile(LPWSTR name, DWORD option, DWORD share, DWORD disposition)
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
HANDLE IthCreateDirectory(LPWSTR name)
{
	wcscpy(current_dir,name);
	UNICODE_STRING us;
	RtlInitUnicodeString(&us,file_path);
	OBJECT_ATTRIBUTES oa={sizeof(oa),0,&us,OBJ_CASE_INSENSITIVE,0,0};
	HANDLE hFile;
	IO_STATUS_BLOCK isb;
	if (NT_SUCCESS(NtCreateFile(&hFile,STANDARD_RIGHTS_REQUIRED,&oa,&isb,0,0,
		FILE_SHARE_READ|FILE_SHARE_WRITE,
		FILE_OPEN_IF,FILE_DIRECTORY_FILE,0,0)))
		return hFile;
	else return INVALID_HANDLE_VALUE;
}
HANDLE IthCreateFileFullPath(LPWSTR full_path, DWORD option, DWORD share, DWORD disposition)
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
HANDLE IthPromptCreateFile(DWORD option, DWORD share, DWORD disposition)
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
HANDLE IthCreateSection(LPWSTR name, DWORD size, DWORD right)
{
	HANDLE hSection;
	LARGE_INTEGER s={size,0};
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
HANDLE IthCreateEvent(LPWSTR name, DWORD auto_reset, DWORD init_state)
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
HANDLE IthCreateMutex(LPWSTR name, BOOL InitialOwner, DWORD* exist)
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
DWORD IthWaitForSingleObject(HANDLE hObject, DWORD dwTime)
{
	__asm{
		sub esp,0x8
		xor ecx,ecx
		cmp dwTime,-1
		cmove eax,ecx
		je _wait
		mov eax,0x2710
		mov ecx,dwTime
		mul ecx
		neg eax
		adc edx,0
		neg edx
		mov [esp],eax
		mov [esp+4],edx
		mov eax,esp
_wait:
		push eax
		push 0
		push hObject
		call dword ptr [NtWaitForSingleObject]
		add esp,0x8
	}
}
#define DEFAULT_STACK_LIMIT 0x400000
#define DEFAULT_STACK_COMMIT 0x10000
#define PAGE_SIZE 0x1000

HANDLE IthCreateThread(LPVOID start_addr, DWORD param, HANDLE hProc)
{
	HANDLE hThread;
	CLIENT_ID id;
	LPVOID protect;
	USER_STACK stack={};
	CONTEXT ctx={CONTEXT_FULL};
	DWORD size=DEFAULT_STACK_LIMIT,commit=DEFAULT_STACK_COMMIT,x;
	NtAllocateVirtualMemory(hProc,&stack.ExpandableStackBottom,
		0,&size,MEM_RESERVE,PAGE_READWRITE);
	
	stack.ExpandableStackBase=(char*)stack.ExpandableStackBottom+size;
	stack.ExpandableStackLimit=(char*)stack.ExpandableStackBase-commit;
	size=PAGE_SIZE;
	commit+=size;
	protect=(char*)stack.ExpandableStackBase-commit;
	NtAllocateVirtualMemory(hProc,&protect,0,&commit,MEM_COMMIT,PAGE_READWRITE);
	NtProtectVirtualMemory(hProc,&protect,&size,PAGE_READWRITE|PAGE_GUARD,&x);
	ctx.SegGs=0;
	ctx.SegFs=0x38;
	ctx.SegEs=0x20;
	ctx.SegDs=0x20;
	ctx.SegSs=0x20;
	ctx.SegCs=0x18;
	ctx.EFlags=0x3000;
	ctx.Eax=(DWORD)start_addr;
	ctx.Esp=(DWORD)stack.ExpandableStackBase-0x10;
	
	NtWaitForSingleObject(thread_man_mutex,0,0);
	ctx.Eip=(DWORD)thread_man->GetProcAddr(hProc);
	NtReleaseMutant(thread_man_mutex,0);

	if (NT_SUCCESS(NtCreateThread(&hThread,THREAD_ALL_ACCESS,0,hProc,&id,&ctx,&stack,1)))
	{
		NtGetContextThread(hThread,&ctx);
		NtWriteVirtualMemory(hProc,(LPVOID)ctx.Esp,&param,4,&size);
		NtResumeThread(hThread,0);
		return hThread;
	}
	return INVALID_HANDLE_VALUE;
}

DWORD GetExportAddress(DWORD hModule,DWORD hash)
{
	IMAGE_DOS_HEADER *DosHdr;
	IMAGE_NT_HEADERS *NtHdr;
	IMAGE_EXPORT_DIRECTORY *ExtDir;
	UINT uj;
	char* pcExportAddr,*pcFuncPtr,*pcBuffer;
	DWORD dwReadAddr,dwFuncAddr,dwFuncName;
	WORD wOrd;
	DosHdr=(IMAGE_DOS_HEADER*)hModule;
	if (IMAGE_DOS_SIGNATURE==DosHdr->e_magic)
	{
		dwReadAddr=hModule+DosHdr->e_lfanew;
		NtHdr=(IMAGE_NT_HEADERS*)dwReadAddr;
		if (IMAGE_NT_SIGNATURE==NtHdr->Signature)
		{
			pcExportAddr=(char*)((DWORD)hModule+
				(DWORD)NtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
			if (pcExportAddr==0) return 0;
			ExtDir=(IMAGE_EXPORT_DIRECTORY*)pcExportAddr;
			pcExportAddr=(char*)((DWORD)hModule+(DWORD)ExtDir->AddressOfNames);

			for (uj=0;uj<ExtDir->NumberOfNames;uj++)
			{
				dwFuncName=*(DWORD*)pcExportAddr;
				pcBuffer=(char*)((DWORD)hModule+dwFuncName);
				if (GetHash(pcBuffer)==hash)
				{
					pcFuncPtr=(char*)((DWORD)hModule+(DWORD)ExtDir->AddressOfNameOrdinals+(uj*sizeof(WORD)));
					wOrd=*(WORD*)pcFuncPtr;
					pcFuncPtr=(char*)((DWORD)hModule+(DWORD)ExtDir->AddressOfFunctions+(wOrd*sizeof(DWORD)));
					dwFuncAddr=*(DWORD*)pcFuncPtr;
					return hModule+dwFuncAddr;
				}
				pcExportAddr+=sizeof(DWORD);
			}
		}
	}
	return 0;
}

void IthSleep(int time)
{
	__asm
	{
		mov eax,0x2710
		mov ecx,time
		mul ecx
		neg eax
		adc edx,0
		neg edx
		push edx
		push eax
		push esp
		push 0
		call dword ptr [NtDelayExecution]
		add esp,8
	}
}
void IthSystemTimeToLocalTime(LARGE_INTEGER* time)
{
	time->QuadPart-=GetTimeBias()->QuadPart;
}
}
