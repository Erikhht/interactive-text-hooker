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
#include <intrin.h>
#include "utility.h"
#include "..\avl.h"
// /HA-40@4e050:cmvs64.exe
SectionRelayBuffer* relay;

#define HOOK_BUFFER_SIZE (MAX_HOOK*sizeof(TextHook))
//#define MAX_HOOK (HOOK_BUFFER_SIZE/sizeof(TextHook))
WCHAR dll_mutex[0x100];
WCHAR hm_mutex[0x100];
WCHAR hm_section[0x100];
HINSTANCE hDLL;
HANDLE hSection;
bool running,live=false,trigger=false;
int current_hook=0,user_hook_count=0;
HANDLE hSendThread,hCmdThread,hFile,hMutex,hmMutex;
UINT_PTR hook_buff_len=HOOK_BUFFER_SIZE;
//DWORD current_process_id;

extern UINT_PTR enter_count;
extern LPWSTR current_dir;
extern UINT_PTR engine_type;
AVLTree<char, FunctionInfo, SCMP, SCPY, SLEN> *tree;
void AddModule(UINT_PTR hModule, UINT_PTR size, LPWSTR name)
{
	IMAGE_DOS_HEADER *DosHdr;
	IMAGE_NT_HEADERS *NtHdr;
	IMAGE_EXPORT_DIRECTORY *ExtDir;
	UINT uj;
	FunctionInfo info={0,hModule,size,name};
	char* pcFuncPtr,*pcBuffer;
	UINT_PTR dwReadAddr,dwFuncName,dwExportAddr;
	WORD wOrd;
	DosHdr=(IMAGE_DOS_HEADER*)hModule;
	if (IMAGE_DOS_SIGNATURE==DosHdr->e_magic)
	{
		dwReadAddr=hModule+DosHdr->e_lfanew;
		NtHdr=(IMAGE_NT_HEADERS*)dwReadAddr;
		if (IMAGE_NT_SIGNATURE==NtHdr->Signature)
		{
			dwExportAddr=NtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
			if (dwExportAddr==0) return;
			dwExportAddr+=hModule;
			ExtDir=(IMAGE_EXPORT_DIRECTORY*)dwExportAddr;
			dwExportAddr=hModule+ExtDir->AddressOfNames;
			for (uj=0;uj<ExtDir->NumberOfNames;uj++)
			{
				dwFuncName=*(DWORD*)dwExportAddr;
				pcBuffer=(char*)(hModule+dwFuncName);
				pcFuncPtr=(char*)(hModule+(DWORD)ExtDir->AddressOfNameOrdinals+(uj*sizeof(WORD)));
				wOrd=*(WORD*)pcFuncPtr;
				pcFuncPtr=(char*)(hModule+(DWORD)ExtDir->AddressOfFunctions+(wOrd*sizeof(DWORD)));
				info.addr=hModule+*(DWORD*)pcFuncPtr;
				tree->Insert(pcBuffer,info);
				dwExportAddr+=sizeof(DWORD);
			}
		}
	}
}
void GetFunctionNames()
{
	tree=new AVLTree<char, FunctionInfo, SCMP,SCPY,SLEN>;
	UINT_PTR temp=*(UINT_PTR*)(&peb->Ldr->InLoadOrderModuleList);
	PLDR_DATA_TABLE_ENTRY it=(PLDR_DATA_TABLE_ENTRY) temp;
	while (it->SizeOfImage)
	{
		AddModule((UINT_PTR)it->DllBase,it->SizeOfImage,it->BaseDllName.Buffer);
		it=(PLDR_DATA_TABLE_ENTRY)it->InLoadOrderModuleList.Flink;
		if (*(UINT_PTR*)it==temp) break;
	}
}
UINT_PTR ITHAPI GetFunctionAddr(char* name, UINT_PTR* addr, UINT_PTR* base, UINT_PTR* size, LPWSTR* base_name)
{
	TreeNode<char*,FunctionInfo>* node=tree->Search(name);
	if (node)
	{
		if (addr) *addr=node->data.addr;
		if (base) *base=node->data.module;
		if (size) *size=node->data.size;
		if (base_name) *base_name=node->data.name;
		return 1;
	}
	else return 0;
}
void RequestRefreshProfile()
{
	if (live)
	{
		BYTE buffer[0x80];
		*(UINT_PTR*)buffer=-1;
		*(UINT_PTR*)(buffer+8)=1;
		*(UINT_PTR*)(buffer+0x10)=0;
		IO_STATUS_BLOCK ios;
		NtWriteFile(hPipe,0,0,0,&ios,buffer,HEADER_SIZE,0,0);
	}
}
BOOL WINAPI DllMain(HINSTANCE hinstDLL, UINT_PTR fdwReason, LPVOID lpvReserved)
{
	switch (fdwReason) 
	{ 
	case DLL_PROCESS_ATTACH:
		{
			UINT_PTR size=0x1000,s;
			LdrDisableThreadCalloutsForDll(hinstDLL);
			IthInitSystemService();
			swprintf(hm_section,L"ITH_SECTION_%d",current_process_id);
			hSection=IthCreateSection(hm_section,sizeof(TextHook)*MAX_HOOK,PAGE_EXECUTE_READWRITE);	
			NtMapViewOfSection(hSection,NtCurrentProcess(),(PVOID*)&hookman,0,
				hook_buff_len,0,&hook_buff_len,ViewUnmap,0,PAGE_EXECUTE_READWRITE);
			NtAllocateVirtualMemory(NtCurrentProcess(),(PVOID*)&relay,0,&size,MEM_COMMIT,PAGE_READWRITE);
			swprintf(dll_mutex,L"ITH_%.4d_%s",current_process_id,current_dir);
			swprintf(hm_mutex,L"ITH_HOOKMAN_%d",current_process_id);
			hmMutex=IthCreateMutex(hm_mutex,0);
			hMutex=IthCreateMutex(dll_mutex,1,&s);
			if (s) return FALSE;
			hDLL=hinstDLL; running=true;
			current_available=hookman;
			GetFunctionNames();
			InitFilterTable();
			InitDefaultHook();
			hSendThread=IthCreateThread(WaitForPipe,0);
			hCmdThread=IthCreateThread(CommandPipe,0);
		}
		break; 
	case DLL_PROCESS_DETACH:
		{
			running=false;
			live=false;
			NtWaitForSingleObject(hSendThread,0,0);
			NtWaitForSingleObject(hCmdThread,0,0);
			NtClose(hCmdThread);
			NtClose(hSendThread);
			for (TextHook* man=hookman;man->RemoveHook();man++);
			LARGE_INTEGER lint={-10000,-1};
			for (TextHook* man=hookman;man<hookman+MAX_HOOK;man++) man->ClearHook();
			NtUnmapViewOfSection(NtCurrentProcess(),hookman);
			NtClose(hSection);
			NtClose(hmMutex);
			NtClose(hMutex);
			delete tree;
			relay->Release();
			UINT_PTR size=0x1000;
			NtFreeVirtualMemory(NtCurrentProcess(),(PVOID*)&relay,&size,MEM_RELEASE);
			IthCloseSystemService();
		}
		break;
	default: 
		break; 
	 } 
	return TRUE; 
}
UINT_PTR PrintUnsignedPtr(LPWSTR str, UINT_PTR ptr)
{
	LARGE_INTEGER p;
	p.QuadPart=ptr;
	UINT_PTR l;
	if (p.HighPart!=0)
		l=swprintf(str,L"%X%.8X",p.HighPart,p.LowPart);
	else
		l=swprintf(str,L"%X",p.LowPart);
	return l;
}
extern "C" {
void ITHAPI RegisterEngineType(UINT_PTR type)
{
	if (live)
	{
		engine_type=type;
		BYTE buffer[0x80];
		*(UINT_PTR*)buffer=-1;
		*(UINT_PTR*)(buffer+8)=2;
		*(UINT_PTR*)(buffer+0x10)=type;
		IO_STATUS_BLOCK ios;
		NtWriteFile(hPipe,0,0,0,&ios,buffer,HEADER_SIZE,0,0);
	}
}
void ITHAPI RegisterHookName(LPWSTR str, UINT_PTR addr)
{
	if (live)
	if (str)
	{
		size_t len=(wcslen(str))<<1;
		BYTE buffer[0x80];
		BYTE *buff=buffer;
		if (len+HEADER_SIZE>=0x80)
			buff=new BYTE[len+HEADER_SIZE];
		*(UINT_PTR*)buffer=-1;
		*(UINT_PTR*)(buffer+8)=0;
		*(UINT_PTR*)(buffer+0x10)=addr;
		wcscpy(LPWSTR(buff+HEADER_SIZE),str);
		IO_STATUS_BLOCK ios;
		NtWriteFile(hPipe,0,0,0,&ios,buff,len+HEADER_SIZE,0,0);
		if (buff!=buffer) delete buff;
	}
}
void ITHAPI NewHook(const HookParam& hp, LPWSTR name, UINT_PTR flag)
{
	size_t current; WCHAR str[0x80];
	//__debugbreak();
	current=current_available-hookman;
	if (current>=MAX_HOOK) OutputConsole(L"Too many hooks.");
	else {
		if (name==0)
		{
			name=str;
			swprintf(name,L"UserHook%d",user_hook_count++);
		}
		hookman[current].InitHook(hp,name,HOOK_ADDITIONAL|(flag&0xFFFF));
		if (hookman[current].InsertHook()==0)
		{
			OutputConsole(L"Additional hook inserted.");
			LARGE_INTEGER p;
			p.QuadPart=hookman[current].Address();
			wcscpy(str,L"Insert address ");
			PrintUnsignedPtr(str+15,hookman[current].Address());
			//swprintf(str,L"Insert address %p.",hookman[current].Address());
			OutputConsole(str);
			RequestRefreshProfile();
		}
		else OutputConsole(L"Unable to insert hook.");
	}
}
void ITHAPI RemoveHook(UINT_PTR addr)
{
	for (int i=0;i<MAX_HOOK;i++)
	{
		if (hookman[i].Address()==addr)
		{
			hookman[i].ClearHook();
			return;
		}
	}
}
void ITHAPI SwitchTrigger(bool t) {trigger=t;}
}

static int filter_count;

int GuardRange(LPWSTR module, UINT_PTR* a, UINT_PTR* b)
{
	int flag=0;
	__try{
		flag=FillRange(module,a,b);
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		flag=0;
	}
	return flag;
}
void AddRange(LPWSTR dll)
{
	if (GuardRange(dll,&filter[filter_count].lower,&filter[filter_count].upper))
		filter_count++;
}
void InitFilterTable()
{
	filter_count=0;
	AddRange(L"uxtheme.dll");
	AddRange(L"usp10.dll");
	AddRange(L"msctf.dll");
	AddRange(L"gdiplus.dll");
	AddRange(L"lpk.dll");
	AddRange(L"psapi.dll");
	AddRange(L"user32.dll");
}
