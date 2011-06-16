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
TextBuffer			*texts;
HookManager		*man;
ProfileManager		*pfman;
CommandQueue	*cmdq;
BitMap					*pid_map;
BYTE* static_large_buffer;
HANDLE hPipeExist;
RECT window;
bool	running=true,admin=false;
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
char* setting_string[]={"split_time","process_time","inject_delay","insert_delay",
	"auto_inject",	"auto_insert","auto_copy","auto_suppress",
	"window_left","window_right","window_top","window_bottom"};
DWORD window_left,window_right,window_top,window_bottom;
DWORD* setting_variable[]={&split_time,&process_time,&inject_delay,&insert_delay,
	&auto_inject,&auto_insert,&clipboard_flag,&cyclic_remove,
	&window_left,&window_right,&window_top,&window_bottom};
DWORD default_setting[]={200,50,3000,500,1,1,0,0,100,800,100,600};
void SaveSettings()
{
	HANDLE hFile=IthCreateFile(L"ITH.ini",GENERIC_WRITE,FILE_SHARE_READ,FILE_OVERWRITE_IF);
	if (hFile!=INVALID_HANDLE_VALUE)
	{
		char* buffer=new char[0x1000];
		char* ptr=buffer;
		IO_STATUS_BLOCK ios;
		ptr+=sprintf(ptr,"split_time=%d\r\n",split_time);
		ptr+=sprintf(ptr,"process_time=%d\r\n",process_time);
		ptr+=sprintf(ptr,"inject_delay=%d\r\n",inject_delay);
		ptr+=sprintf(ptr,"insert_delay=%d\r\n",insert_delay);
		ptr+=sprintf(ptr,"auto_inject=%d\r\n",auto_inject);
		ptr+=sprintf(ptr,"auto_insert=%d\r\n",auto_insert);
		ptr+=sprintf(ptr,"auto_copy=%d\r\n",clipboard_flag);
		ptr+=sprintf(ptr,"auto_suppress=%d\r\n",cyclic_remove);
		RECT rc;
		if (IsWindow(hMainWnd))
		{
			GetWindowRect(hMainWnd,&rc);
			ptr+=sprintf(ptr,"window_left=%d\r\n",rc.left);
			ptr+=sprintf(ptr,"window_right=%d\r\n",rc.right);
			ptr+=sprintf(ptr,"window_top=%d\r\n",rc.top);
			ptr+=sprintf(ptr,"window_bottom=%d\r\n",rc.bottom);
		}
		NtWriteFile(hFile,0,0,0,&ios,buffer,ptr-buffer+1,0,0);
		delete buffer;
		NtClose(hFile);
	}
}
void LoadSettings()
{
	HANDLE hFile=IthCreateFile(L"ITH.ini",GENERIC_READ,FILE_SHARE_READ,FILE_OPEN);
	if (hFile!=INVALID_HANDLE_VALUE)
	{
		IO_STATUS_BLOCK ios;
		FILE_STANDARD_INFORMATION info;
		NtQueryInformationFile(hFile,&ios,&info,sizeof(info),FileStandardInformation);
		char* buffer=new char[info.AllocationSize.LowPart];
		char* ptr;
		NtReadFile(hFile,0,0,0,&ios,buffer,info.AllocationSize.LowPart,0,0);
		for (int i=0;i<sizeof(setting_string)/sizeof(char*);i++)
		{
			ptr=strstr(buffer,setting_string[i]);
			if (ptr==0) ptr=buffer;
			if (sscanf(strchr(ptr,'=')+1,"%d",setting_variable[i])==0) 
				*setting_variable[i]=default_setting[i];
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
		delete buffer;
		NtClose(hFile);
	}
	else
	{
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
	swprintf(str,L"Exception code: 0x%.8X", ExceptionInfo->ExceptionRecord->ExceptionCode);
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
	NtTerminateProcess(NtCurrentProcess(),0);
	return 0;
}
int main()
{
	MSG msg;
	if (Init()) goto _exit;
	SetUnhandledExceptionFilter(ExceptionFilter);
	hIns=(HINSTANCE)GetModuleBase();
	MyRegisterClass(hIns);
	InitCommonControls();
	LoadSettings();
	InitInstance(hIns,admin,&window);
	InitializeCriticalSection(&detach_cs);
	pid_map=new BitMap;
	texts=new TextBuffer;
	man=new HookManager;
	pfman=new ProfileManager;
	cmdq=new CommandQueue;
	CreateNewPipe();
	NtClose(IthCreateThread(CmdThread,0));
	if (!admin) ConsoleOutput(NotAdmin);
	while (GetMessage(&msg, NULL, 0, 0))
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}
	NtClearEvent(hPipeExist);
	Sleep(100);
	delete cmdq;
	delete pfman;
	delete man;
	delete texts;
	delete pid_map;
	if (static_large_buffer!=0) delete static_large_buffer;
_exit:
	IthCloseSystemService();
	NtTerminateProcess(NtCurrentProcess(),0);
}
