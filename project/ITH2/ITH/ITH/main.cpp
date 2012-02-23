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

#include "main.h"
#include "cmdq.h"
#include "profile.h"
#include "hookman.h"
#include <CommCtrl.h>
WCHAR name[]=L"ith.exe";

static WCHAR exist[]=L"ITH_PIPE_EXIST";
static WCHAR mutex[]=L"ITH_RUNNING";
extern LPCWSTR ClassName,ClassNameAdmin;
HINSTANCE hIns;
TextBuffer		*texts;
HookManager		*man;
ProfileManager	*pfman;
CommandQueue	*cmdq;
BitMap			*pid_map;
CustomFilterMultiByte *mb_filter;
CustomFilterUnicode *uni_filter;
BYTE* static_large_buffer;
HANDLE hPipeExist;
RECT window;
bool running=true,admin=false;
ATOM MyRegisterClass(HINSTANCE hInstance);
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow, RECT *rc);

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
void GetDebugPriv(void)
{
	HANDLE	hToken;
	DWORD	dwRet;
	TOKEN_PRIVILEGES Privileges={1,{0x14,0}};
	Privileges.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;
	NtOpenProcessToken(NtCurrentProcess(), TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&hToken);	
	if (STATUS_SUCCESS==NtAdjustPrivilegesToken(hToken,FALSE,&Privileges,sizeof(Privileges),NULL,&dwRet))
		admin=true;
	else MessageBox(0,NotAdmin,L"Warning!",0);

	NtClose(hToken);
}
wchar_t* setting_string[]={L"split_time",L"process_time",L"inject_delay",L"insert_delay",
	L"auto_inject",L"auto_insert",L"auto_copy",L"auto_suppress", L"global_filter",
	L"window_left",L"window_right",L"window_top",L"window_bottom"};
DWORD window_left,window_right,window_top,window_bottom;
DWORD* setting_variable[]={&split_time,&process_time,&inject_delay,&insert_delay,
	&auto_inject,&auto_insert,&clipboard_flag,&cyclic_remove,&global_filter,
	&window_left,&window_right,&window_top,&window_bottom};
DWORD default_setting[]={200,50,3000,500,1,1,0,0,0,100,800,100,600};
MyVector<wchar_t,0x1000>* settings;
void RecordUniChar(WORD uni_char)
{
	char mb[4];
	wchar_t uni[0x10]={uni_char,0};
	int mask=2;
	WC_MB(uni,mb);
	if (mb_filter->Check(*(WORD*)mb)) 
	{
		mask|=1;
		mb_filter->Clear(*(WORD*)mb);
	}
	mask=swprintf(uni,L"%.4x,%d,%c\r\n",uni_char,mask,uni_char);
	settings->AddToStore(uni,mask);
}
void RecordMultiByte(WORD mb_char)
{
	wchar_t buffer[0x10];
	char mb[4];
	*(WORD*)mb=mb_char;
	mb[2]=0;
	MB_WC(mb,buffer);

	int i=swprintf(buffer,L"%.4x,1,%c\r\n",buffer[0],buffer[0]);
	settings->AddToStore(buffer,i);
}
void SaveSettings()
{
	HANDLE hFile=IthCreateFile(L"ITH.ini",FILE_WRITE_DATA,FILE_SHARE_READ,FILE_OVERWRITE_IF);
	if (hFile!=INVALID_HANDLE_VALUE)
	{
		wchar_t buffer[0x100];
		int i=0;
		IO_STATUS_BLOCK ios;
		settings=new MyVector<wchar_t,0x1000> ;
		buffer[0]=0xFEFF;
		settings->AddToStore(buffer,1);
		i=swprintf(buffer,L"split_time=%d\r\n",split_time);
		settings->AddToStore(buffer,i);
		i=swprintf(buffer,L"split_time=%d\r\n",split_time);
		settings->AddToStore(buffer,i);
		i=swprintf(buffer,L"process_time=%d\r\n",process_time);
		settings->AddToStore(buffer,i);
		i=swprintf(buffer,L"inject_delay=%d\r\n",inject_delay);
		settings->AddToStore(buffer,i);
		i=swprintf(buffer,L"insert_delay=%d\r\n",insert_delay);
		settings->AddToStore(buffer,i);
		i=swprintf(buffer,L"auto_inject=%d\r\n",auto_inject);
		settings->AddToStore(buffer,i);
		i=swprintf(buffer,L"auto_insert=%d\r\n",auto_insert);
		settings->AddToStore(buffer,i);
		i=swprintf(buffer,L"auto_copy=%d\r\n",clipboard_flag);
		settings->AddToStore(buffer,i);
		i=swprintf(buffer,L"auto_suppress=%d\r\n",cyclic_remove);
		settings->AddToStore(buffer,i);
		i=swprintf(buffer,L"global_filter=%d\r\n",global_filter);
		settings->AddToStore(buffer,i);
		RECT rc;
		if (IsWindow(hMainWnd))
		{
			GetWindowRect(hMainWnd,&rc);
			i=swprintf(buffer,L"window_left=%d\r\n",rc.left);
			settings->AddToStore(buffer,i);
			i=swprintf(buffer,L"window_right=%d\r\n",rc.right);
			settings->AddToStore(buffer,i);
			i=swprintf(buffer,L"window_top=%d\r\n",rc.top);
			settings->AddToStore(buffer,i);
			i=swprintf(buffer,L"window_bottom=%d\r\n",rc.bottom);
			settings->AddToStore(buffer,i);
		}
		i=swprintf(buffer,L"CF={\r\n");
		settings->AddToStore(buffer,i);
		uni_filter->Traverse(RecordUniChar);
		mb_filter->Traverse(RecordMultiByte);
		settings->AddToStore(L"}\r\n",3);
		NtWriteFile(hFile,0,0,0,&ios,settings->Storage(),settings->Used()<<1,0,0);
		NtClose(hFile);
		delete settings;
	}
}
void LoadSettings()
{
	HANDLE hFile=IthCreateFile(L"ITH.ini",FILE_READ_DATA,FILE_SHARE_READ,FILE_OPEN);
	if (hFile!=INVALID_HANDLE_VALUE)
	{
		IO_STATUS_BLOCK ios;
		FILE_STANDARD_INFORMATION info;
		LPVOID vm_buffer=0;
		NtQueryInformationFile(hFile,&ios,&info,sizeof(info),FileStandardInformation);
		NtAllocateVirtualMemory(NtCurrentProcess(),&vm_buffer,0,&info.AllocationSize.LowPart,MEM_COMMIT,PAGE_READWRITE);
		wchar_t* buffer=(wchar_t*)vm_buffer;
		wchar_t* ptr,*last_ptr;
		NtReadFile(hFile,0,0,0,&ios,vm_buffer,info.AllocationSize.LowPart,0,0);
		if (*(WORD*)vm_buffer!=0xFEFF)
		{
			NtClose(hFile);
			NtFreeVirtualMemory(NtCurrentProcess(),&vm_buffer,&info.AllocationSize.LowPart,MEM_RELEASE);
			goto _no_setting;
		}
		ptr=buffer;
		for (int i=0;i<sizeof(setting_string)/sizeof(wchar_t*);i++)
		{
			if (ptr==0) ptr=last_ptr;
			ptr=wcsstr(ptr,setting_string[i]);
			if (ptr==0||swscanf(wcschr(ptr,'=')+1,L"%d",setting_variable[i])==0) 
				*setting_variable[i]=default_setting[i];
			last_ptr=ptr;
		}
		buffer[(info.AllocationSize.LowPart>>1)-1]='\n';
		while (*ptr!=L'\n') ptr++;
		ptr++;
		if (ptr-buffer+4<info.AllocationSize.LowPart)
		{
			if (*ptr)
			{
				if (*(DWORD*)ptr==0x460043&&*(DWORD*)(ptr+2)==0x7B003D) // CF={
				{
					ptr+=6;
					LPWSTR next=ptr,end;
					DWORD mask;
					WCHAR uni_char[2];
					char mb_char[4];
					for (end=ptr;*end;end++);
					*end=L'\n';
					while (next<end)
					{				
						ptr=next;
						while (*next!=L'\n') next++;
						*next++=0;
						if (next-ptr<8) continue;
						if (swscanf(ptr,L"%x,%d",&uni_char,&mask)==2)
						{

							if (mask&2)	uni_filter->Set(uni_char[0]);
							if (mask&1)
							{
								uni_char[1]=0;
								WC_MB(uni_char,mb_char);
								mb_filter->Set(*(WORD*)mb_char);
							}
						}
					}
				}
			}
		}
		if (auto_inject>1) auto_inject=1;
		if (auto_insert>1) auto_insert=1;
		if (clipboard_flag>1) clipboard_flag=1;
		if (cyclic_remove>1) cyclic_remove=1;
		if ((window_left|window_right|window_top|window_bottom)>>31)
		{
			window_left=100;
			window_top=100;
			window_right=800;
			window_bottom=600;
		}
		else
		{
			if (window_right<window_left || window_right-window_left<600) window_right=window_left+600;
			if (window_bottom<window_top || window_bottom-window_top<200) window_bottom=window_top+200;
		}
		window.left=window_left;
		window.right=window_right;
		window.top=window_top;
		window.bottom=window_bottom;
		NtFreeVirtualMemory(NtCurrentProcess(),&vm_buffer,&info.AllocationSize.LowPart,MEM_RELEASE);
		NtClose(hFile);
	}
	else
	{
_no_setting:
		for (int i=0;i<sizeof(setting_variable)/sizeof(LPVOID);i++)
		{
			*setting_variable[i]=default_setting[i];
		}
		split_time=200;
		process_time=50;
		inject_delay=3000;
		insert_delay=500;
		auto_inject=1;
		auto_insert=1;
		clipboard_flag=0;
		cyclic_remove=0;

		window.left=100;
		window.top=100;
		window.right=800;
		window.bottom=600;
		
	}
}
int Init()
{
	IthInitSystemService();
	DWORD s;
	HANDLE hm=IthCreateMutex(mutex,1,&s);
	if (s)
	{
		HWND hwnd=FindWindow(ClassName,ClassName);
		if (hwnd==0) hwnd=FindWindow(ClassName,ClassNameAdmin);
		if (hwnd)
		{
			ShowWindow(hwnd,SW_SHOWNORMAL);
			SetForegroundWindow(hwnd);
		}
		return 1;
	}
	hPipeExist=IthCreateEvent(exist);
	NtSetEvent(hPipeExist,0);
	GetDebugPriv();
	return 0;
}
DWORD GetModuleBase()
{
	__asm
	{
		mov eax,fs:[0x30]
		mov eax,[eax+0x8]
	}
}
LONG WINAPI ExceptionFilter(EXCEPTION_POINTERS *ExceptionInfo)
{
	WCHAR str[0x40],name[0x100];
	swprintf(str,L"Exception code: 0x%.8X\r\nAddress: 0x%.8X", ExceptionInfo->ExceptionRecord->ExceptionCode, 
		ExceptionInfo->ContextRecord->Eip);
	MessageBox(0,str,0,0);
	MEMORY_BASIC_INFORMATION info;
	if (NT_SUCCESS(NtQueryVirtualMemory(NtCurrentProcess(),(PVOID)ExceptionInfo->ContextRecord->Eip,
		MemoryBasicInformation,&info,sizeof(info),0)))
	{
		if (NT_SUCCESS(NtQueryVirtualMemory(NtCurrentProcess(),(PVOID)ExceptionInfo->ContextRecord->Eip,
			MemorySectionName,name,0x200,0)))
		{
			swprintf(str,L"Exception offset: 0x%.8X:%s",
				ExceptionInfo->ContextRecord->Eip-(DWORD)info.AllocationBase,
				wcsrchr(name,L'\\')+1);
			MessageBox(0,str,0,0);
		}
	}
	//NtTerminateProcess(NtCurrentProcess(),0);
	return 0;
}
extern "C" int printf(const char*,...);
int main()
{
	MSG msg;
	if (Init()) goto _exit;
	SetUnhandledExceptionFilter(ExceptionFilter);
	hIns=(HINSTANCE)GetModuleBase();
	MyRegisterClass(hIns);
	InitCommonControls();
	mb_filter=new CustomFilterMultiByte;
	uni_filter=new CustomFilterUnicode;
	LoadSettings();
	InitInstance(hIns,admin,&window);
	InitializeCriticalSection(&detach_cs);
	pid_map=new BitMap(0x100);	
	texts=new TextBuffer;
	man=new HookManager;
	pfman=new ProfileManager;
	cmdq=new CommandQueue;
	CreateNewPipe();
	if (!admin) ConsoleOutput(NotAdmin);
	while (GetMessage(&msg, NULL, 0, 0))
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}
	NtClearEvent(hPipeExist);
	delete cmdq;
	delete pfman;
	delete man;
	delete texts;
	delete mb_filter;
	delete uni_filter;
	delete pid_map;
	if (static_large_buffer!=0) delete static_large_buffer;
_exit:
	IthCloseSystemService();
	NtTerminateProcess(NtCurrentProcess(),0);
}
