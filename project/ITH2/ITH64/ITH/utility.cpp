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

#include "hookman.h"
#include "profile.h"
#define MAX_ENTRY 0x40
WCHAR user_entry[0x40];
static LPWSTR init_message=L"Interactive Text Hooker x64 1.0 (2011.5.15)\r\n\
Copyright (C) 2010-2011  kaosu (qiupf2000@gmail.com)\r\n\
Source code <http://code.google.com/p/interactive-text-hooker/>\r\n\
General discussion <http://www.hongfire.com/forum/showthread.php?t=208860>\r\n";
LPWSTR HookNameInitTable[]={
	L"ConsoleOutput",
	L"GetTextExtentPoint32A",
	L"GetGlyphOutlineA",
	L"ExtTextOutA",
	L"TextOutA",
	L"GetCharABCWidthsA",
	L"DrawTextA",
	L"DrawTextExA",
	L"GetTextExtentPoint32W",
	L"GetGlyphOutlineW",
	L"ExtTextOutW",
	L"TextOutW",
	L"GetCharABCWidthsW",
	L"DrawTextW",
	L"DrawTextExW"
	};
LPVOID DefaultHookAddr[14];
size_t GetHookName(LPWSTR str, UINT_PTR pid, UINT_PTR hook_addr)
{
	if (pid==0) 
	{
		wcscpy(str,HookNameInitTable[0]);
		return wcslen(HookNameInitTable[0]);
	}
	UINT_PTR len=0;
	man->LockProcessHookman(pid);
	Hook* hks=(Hook*)man->RemoteHook(pid);
	for (size_t i=0;i<MAX_HOOK;i++)
	{
		if (hks[i].Address()==hook_addr)
		{
			NtReadVirtualMemory(man->GetProcessByPID(pid),hks[i].Name(),str,hks[i].NameLength()<<1,&len);
			len=hks[i].NameLength();
			break;
		}
	}
	man->UnlockProcessHookman(pid);
	return len;
}
size_t GetHookNameByIndex(LPWSTR str, UINT_PTR pid, UINT_PTR index)
{
	if (pid==0) 
	{
		wcscpy(str,HookNameInitTable[0]);
		return wcslen(HookNameInitTable[0]);
	}
	UINT_PTR len=0;
	Hook* hks=(Hook*)man->RemoteHook(pid);
	if (hks[index].Address())
	{
		NtReadVirtualMemory(man->GetProcessByPID(pid),hks[index].Name(),str,hks[index].NameLength()<<1,&len);
		len=hks[index].NameLength();
	}
	return len;
}
size_t GetHookString(LPWSTR str, UINT_PTR pid, UINT_PTR hook_addr, UINT_PTR status)
{
	LPWSTR begin=str;
	str+=swprintf(str,L"%4d:0x%08X:",pid,hook_addr); 
	str+=GetHookName(str,pid,hook_addr);
	return str-begin;
}

void CALLBACK AddFun(HWND hwnd, UINT uMsg, UINT_PTR idEvent, UINT_PTR dwTime)
{
	texts->Flush();
}

void CALLBACK NewLineBuff(HWND hwnd, UINT uMsg, UINT_PTR idEvent, UINT_PTR dwTime)
{
	KillTimer(hwnd,idEvent);
	TextThread *id=(TextThread*)idEvent;
	/*if (id->Status()&USING_UNICODE)
		id->AddToStore((BYTE*)L"\r\n\r\n",8,true);
	else
		id->AddToStore((BYTE*)"\r\n\r\n",4,true);*/
	if (id->Status()&CURRENT_SELECT)
	{
		id->CopyLastToClipboard();
		texts->SetLine();
	}
	id->SetNewLineFlag();
}
void CALLBACK NewLineConsole(HWND hwnd, UINT uMsg, UINT_PTR idEvent, UINT_PTR dwTime)
{
	KillTimer(hwnd,idEvent);
	TextThread *id=(TextThread*)idEvent;
	if (id->Status()&USING_UNICODE)
		id->AddToStore((BYTE*)L"\r\n",4,true,true);
	if (id->Status()&CURRENT_SELECT)
	{
		texts->SetLine();
	}
}
UINT_PTR WINAPI WaitThread(LPVOID lpThreadParameter)
{
	while (hwndEdit==0) IthSleep(10);
	TextBuffer* t=(TextBuffer*)lpThreadParameter;
	t->SetFlushTimer(SetTimer(hMainWnd,0,10,(TIMERPROC)AddFun));
	return 0;
}
BitMap::BitMap()
{
	size=0x20;
	map=new BYTE[size];
}
BitMap::~BitMap(){delete map;}
bool BitMap::Check(UINT_PTR number)
{	
	if ((number>>3)>=size) return false;
	return (map[number>>3]&(1<<(number&7)))!=0;
	}
void BitMap::Set(UINT_PTR number)
{
	if (number>>16) return;
	UINT_PTR s=number>>3;
	UINT_PTR t=s>>2;
	if (s&3) t++; 
	s=t<<2;  //Align to 4 byte.
	if (s>=size)
	{
		t=size;
		while (s>=size) size<<=1;
		BYTE* temp=new BYTE[size];
		memcpy(temp,map,t);
		delete map;
		map=temp;
	}	
	map[number>>3]|=1<<(number&7);
}
void BitMap::Clear(UINT_PTR number)
{
	if ((number>>3)>=size) return;
	map[number>>3]&=~(1<<(number&7));
}

TextBuffer::TextBuffer():line(false),unicode(false)
{
	NtClose(IthCreateThread(WaitThread,(UINT_PTR)this));
	//timer=SetTimer(hMainWnd,0,10,AddFun);
}
TextBuffer::~TextBuffer()
{
	KillTimer(hMainWnd,timer);
}
void TextBuffer::AddText(BYTE* text,size_t len, bool l=false)
{
	if (text==0||len==0) return;
	AddToStore(text,len);
	line=l;
}
void TextBuffer::ReplaceSentence(BYTE* text, size_t len)
{
	EnterCriticalSection(&cs_store);
	UINT_PTR t,l;
	Flush();
	t=GetWindowTextLength(hwndEdit);
	//t=SendMessage(hwndEdit,WM_GETTEXTLENGTH,0,0);
	if (unicode)
	{
		SendMessage(hwndEdit,EM_SETSEL,t-(len>>1),t);
		SendMessage(hwndEdit,WM_CLEAR,0,0);
		//SendMessage(hwndEdit,EM_REPLACESEL,FALSE,(LPARAM)text);
	}
	else
	{
		l=MB_WC_count((char*)text,len);
		SendMessage(hwndEdit,EM_SETSEL,t-l,t);
		SendMessage(hwndEdit,WM_CLEAR,0,0);
	}
	LeaveCriticalSection(&cs_store);
}
void TextBuffer::ClearBuffer()
{
	Reset();
	line=false;
}
void TextBuffer::SetUnicode(bool mode)
{
	unicode=mode;
}
void TextBuffer::Flush()
{
	if (line||used==0) return;
	EnterCriticalSection(&cs_store);
	UINT_PTR t;
	storage[used]=0;
	storage[used+1]=0;
	t=SendMessage(hwndEdit,WM_GETTEXTLENGTH,0,0);
	SendMessage(hwndEdit,EM_SETSEL,t,t);
	if (unicode)
		SendMessage(hwndEdit,EM_REPLACESEL,FALSE,(LPARAM)storage);
	else
	{
		WCHAR temp[0x80];
		LPWSTR uni;
		if (used>=0x80) uni=new WCHAR[used+1];
		else uni=temp;
		t=MB_WC((char*)storage,uni);
		uni[t]=0;
		SendMessage(hwndEdit,EM_REPLACESEL,FALSE,(LPARAM)uni);
		if (uni!=temp) delete uni;
	}
	used=0;
	LeaveCriticalSection(&cs_store);
}
void TextBuffer::SetLine()
{
	line=true;
}
void TextBuffer::SetFlushTimer(UINT_PTR t)
{
	timer=t;
}

void ThreadTable::SetThread(UINT_PTR num, TextThread* ptr)
{
	UINT_PTR number=num;
	if (number>=size)
	{
		while (number>=size) size<<=1;
		TextThread** temp;
		if (size<0x10000)
		{
			temp=new TextThread*[size];
			memcpy(temp,storage,used*sizeof(TextThread*));
		}
		delete []storage;
		storage=temp;
	}
	storage[number]=ptr;
	if (ptr==0)
	{
		if (number==used-1) 
			while (storage[used-1]==0) used--;
	}
	else if (number>=used) used=number+1;
}
TextThread* ThreadTable::FindThread(UINT_PTR number)
{
	if (number<=used)
		return storage[number];
	else return 0;
}

size_t TCmp::operator()(const ThreadParameter* t1, const ThreadParameter* t2)
{
	UINT_PTR t;
	t=t1->pid-t2->pid;
	if (t==0)
	{
		t=t1->hook-t2->hook;
		if (t==0)
		{
			t=t1->retn-t2->retn;
			if (t==0) 
			{
				t=t1->spl-t2->spl;
				if (t==0) return 0;
			}
		}
	}
	return (t&0x80000000)?-1:1;
}
void TCpy::operator()(ThreadParameter* t1, ThreadParameter* t2)
{
	memcpy(t1,t2,sizeof(ThreadParameter));
}
size_t TLen::operator()(ThreadParameter* t) {return 0;}

//Class member of HookManger
HookManager::HookManager()
{
	TextThread* entry;
	head.key=new ThreadParameter;
	head.key->pid=0;
	head.key->hook=-1;
	head.key->retn=-1;
	head.key->spl=-1;
	head.data=0;
	table=new ThreadTable;
	entry=new TextThread(0, -1,-1,-1, new_thread_number++);
	table->SetThread(0,entry);
	SetCurrent(entry);
	entry->Status()|=USING_UNICODE;
	texts->SetUnicode(true);
	entry->AddToCombo();
	entry->ComboSelectCurrent();
	entry->AddToStore((BYTE*)init_message,wcslen(init_message)<<1,0,1);
	InitializeCriticalSection(&hmcs);
}
HookManager::~HookManager()
{
	while (register_count-1)
		UnRegisterProcess(record[0].pid_register);
	delete table;
	delete head.key;
	DeleteCriticalSection(&hmcs);
}
TextThread* HookManager::FindSingle(UINT_PTR pid, UINT_PTR hook, UINT_PTR retn, UINT_PTR split)
{
	if (pid==0) return table->FindThread(0);
	ThreadParameter tp={pid,hook,retn,split};
	return table->FindThread(Search(&tp)->data);
}
TextThread* HookManager::FindSingle(UINT_PTR number)
{
	if (number&0x80008000) return 0;
	return table->FindThread(number);
}
TextThread* HookManager::GetCurrentThread() {return current;}
void HookManager::SetCurrent(TextThread* it)
{
	if (current) current->Status()^=CURRENT_SELECT;
		current=it;
	it->Status()|=CURRENT_SELECT;
}
void HookManager::SelectCurrent(LPWSTR str)
{
	UINT_PTR num;
	TextThread* st;
	swscanf(str,L"%x",&num);
	st=FindSingle(num);
	if (st)
	{
		st->ResetEditText();
		SetCurrent(st);
	}
}
void HookManager::RemoveSingleHook(UINT_PTR pid, UINT_PTR addr)
{
	EnterCriticalSection(&hmcs);
	UINT_PTR max=table->Used();
	TextThread* it;
	bool flag=false;
	UINT_PTR number;
	for (UINT_PTR i=1;i<=max;i++)
	{
		it=table->FindThread(i);
		if (it)
		{
			if (it->PID()==pid&&it->Addr()==addr)
			{
				flag|=it->RemoveFromCombo();
				table->SetThread(i,0);
				if (it->Number()<new_thread_number)
					new_thread_number=it->Number();				
				Delete(it->GetThreadParameter());
				delete it;
			}
		}
	}
	for (UINT_PTR i=0;i<=max;i++)
	{
		it=table->FindThread(i);
		if (it==0) continue;
		UINT_PTR ln=it->LinkNumber();
		if (table->FindThread(ln)==0)
		{
			it->LinkNumber()=-1;
			it->Link()=0;
		}
	}
	if (flag)
	{
		current=0;
		if (head.Left)
			number=head.Left->data;
		else number=0;
		it=table->FindThread(number);
		it->ResetEditText();
	}
	LeaveCriticalSection(&hmcs);
}
void HookManager::RemoveSingleThread(UINT_PTR number)
{
	if (number==0) return;
	bool flag;
	EnterCriticalSection(&hmcs);
	TextThread* it=table->FindThread(number);
	if (it)
	{
		table->SetThread(number,0);
		Delete(it->GetThreadParameter());
		flag=it->RemoveFromCombo();
		if (it->Number()<new_thread_number)
			new_thread_number=it->Number();
		delete it;
		for (size_t i=0;i<=table->Used();i++)
		{
			it=table->FindThread(i);
			if (it==0) continue;
			if (it->LinkNumber()==number)
			{
				it->Link()=0;
				it->LinkNumber()=-1;
			}
		}
		if (flag)
		{
			current=0;
			WCHAR str[0x40];
			if (head.Left)
				number=head.Left->data;
			else number=0;
			swprintf(str,L"%x",number);
			//MessageBox(0,str,str,0);
			it=table->FindThread(number);
			it->ResetEditText();
		}
	}
	LeaveCriticalSection(&hmcs);
}
void HookManager::RemoveProcessContext(UINT_PTR pid)
{
	TextThread* it;
	bool flag=false;
	UINT_PTR ln;
	for (size_t i=1;i<table->Used();i++)
	{
		it=table->FindThread(i);
		if (it)
		{
			if (it->PID()==pid)
			{
				Delete(it->GetThreadParameter());
				flag|=it->RemoveFromCombo();
				if (it->Number()<new_thread_number)
					new_thread_number=it->Number();
				table->SetThread(i,0);
				delete it;
			}
		}
	}
	for (size_t i=0;i<=table->Used();i++)
	{
		it=table->FindThread(i);
		if (it==0) continue;
		if (it->Link()==0) continue;
		ln=it->LinkNumber();
		if (table->FindThread(ln)==0)
		{
			it->LinkNumber()=-1;
			it->Link()=0;
		}
	}
	if (flag)
	{
		current=0;
		if (head.Left)
			ln=head.Left->data;
		else ln=0;
		it=table->FindThread(ln);
		it->ResetEditText();
	}
}
void HookManager::RegisterThread(TextThread* it, UINT_PTR num)
{
	table->SetThread(num,it);
}
void HookManager::RegisterPipe(HANDLE text, HANDLE cmd)
{
	text_pipes[register_count]=text;
	cmd_pipes[register_count++]=cmd;
}
void HookManager::RegisterProcess(UINT_PTR pid, UINT_PTR hookman, UINT_PTR module, UINT_PTR engine)
{
	WCHAR str[0x40],path[MAX_PATH];
	pid_map->Set(pid>>2);
	record[register_count-1].pid_register=pid;
	record[register_count-1].hookman_register=hookman;
	record[register_count-1].module_register=module;
	record[register_count-1].engine_register=engine;
	swprintf(str,L"ITH_SECTION_%d",pid);
	HANDLE hSection=IthCreateSection(str,sizeof(Hook)*MAX_HOOK,PAGE_READONLY);
	LPVOID map=0; 
	UINT_PTR map_size=sizeof(Hook)*MAX_HOOK;
	NtMapViewOfSection(hSection,NtCurrentProcess(),&map,0,
		map_size,0,&map_size,ViewUnmap,0,PAGE_READONLY);
	record[register_count-1].hookman_section=hSection;
	record[register_count-1].hookman_map=map;
	HANDLE hProc;	
	CLIENT_ID id;
	id.UniqueProcess=pid;
	id.UniqueThread=0;
	OBJECT_ATTRIBUTES oa={0};
	oa.uLength=sizeof(oa);
	if (NT_SUCCESS(NtOpenProcess(&hProc,
		PROCESS_QUERY_INFORMATION|
		PROCESS_CREATE_THREAD|
		PROCESS_VM_READ| 
		PROCESS_VM_WRITE|
		PROCESS_VM_OPERATION,
		&oa,&id))) record[register_count-1].process_handle=hProc;
	else
	{
		man->AddConsoleOutput(L"Can't open process");
		return;
	}
	
	swprintf(str,L"ITH_HOOKMAN_%d",pid);
	record[register_count-1].hookman_mutex=IthOpenMutex(str);
	if (GetProcessPath(pid,path)==false) path[0]=0;
	swprintf(str,L"%d:%s",pid,wcsrchr(path,L'\\')+1);
	SendMessage(hwndProc,CB_ADDSTRING,0,(LPARAM)str);
	if (SendMessage(hwndProc,CB_GETCOUNT,0,0)==1)
		SendMessage(hwndProc,CB_SETCURSEL,0,0);
	pfman->RefreshProfileAddr(pid,path);
}
void HookManager::UnRegisterProcess(UINT_PTR pid)
{
	size_t i,j,k;
	EnterCriticalSection(&hmcs);
	WCHAR str[0x10];
	swprintf(str,L"%d",pid);
	i=SendMessage(hwndProc,CB_FINDSTRING,0,(LPARAM)str);
	j=SendMessage(hwndProc,CB_GETCURSEL,0,0);
	if (i!=CB_ERR)
	{
		k=SendMessage(hwndProc,CB_DELETESTRING,i,0);
		if (i==j) SendMessage(hwndProc,CB_SETCURSEL,k-1,0);
	}
	for (i=0;i<MAX_REGISTER;i++) if(record[i].pid_register==pid) break;
	//FreeThreadStart(record[i].process_handle);
	NtClose(text_pipes[i]);
	NtClose(cmd_pipes[i]);
	NtClose(record[i].hookman_mutex);
	NtClose(record[i].process_handle);
	NtClose(record[i].hookman_section);
	NtUnmapViewOfSection(NtCurrentProcess(),record[i].hookman_map);
	if (i<MAX_REGISTER)
	{
		for (;i<MAX_REGISTER;i++)
		{
			record[i]=record[i+1];
			text_pipes[i]=text_pipes[i+1];
			cmd_pipes[i]=cmd_pipes[i+1];
			if (text_pipes[i]==0) break;
		}
		register_count--;
		RemoveProcessContext(pid);
		//entry_table->RemoveProcessHook(pid);
	}
	pid_map->Clear(pid>>2);

	LeaveCriticalSection(&hmcs);
}
void HookManager::SetName(UINT_PTR type)
{
	WCHAR c;
	if (type&PRINT_DWORD) c=L'H';
	else if (type&USING_UNICODE) 
	{
		if (type&STRING_LAST_CHAR) c=L'L';
		else if (type&USING_STRING) c=L'Q';
		else c=L'W';
	}
	else
	{
		if (type&USING_STRING) c=L'S';
		else if (type&BIG_ENDIAN) c=L'A';
		else c=L'B';
	}
	swprintf(user_entry,L"UserHook%c",c);
}
void HookManager::AddLink(UINT_PTR from, UINT_PTR to)
{
	bool flag=false;
	TextThread *from_thread, *to_thread;
	EnterCriticalSection(&hmcs);
	from_thread=table->FindThread(from);
	to_thread=table->FindThread(to);
	if (to_thread&&from_thread)
	{
		if (from_thread->Link()==to_thread) 
		{
			AddConsoleOutput(L"Link exist");
			return;
		}
		if (to_thread->CheckCycle(from_thread))
			AddConsoleOutput(L"Link failed. No cyclic link allowed.");
		else
		{
			from_thread->Link()=to_thread;
			from_thread->LinkNumber()=to;
			WCHAR str[0x40];
			swprintf(str,L"Link from thread%.4x to thread%.4x.",from,to);
			AddConsoleOutput(str);
		}
	}
	else 
		AddConsoleOutput(L"Link failed. Source or/and destination thread not found.");
	LeaveCriticalSection(&hmcs);
}
void HookManager::AddText(UINT_PTR pid, BYTE* text, UINT_PTR hook, UINT_PTR retn, UINT_PTR spl, size_t len)
{
	bool flag=false;
	TextThread *it;
	UINT_PTR number;
	if (text==0) return;
	if (len==0) return;
	EnterCriticalSection(&hmcs);
	ThreadParameter tp={pid,hook,retn,spl};
	TreeNode<ThreadParameter*,UINT_PTR> *in;
	number=-1;
	if (pid)
	{
		in=Search(&tp);
		if (in) number=in->data;
	}
	else number=0;
	if (number!=-1)
	{
		it=table->FindThread(number);
		it->AddToStore(text,len,false,number==0);
	}
	else
	{
		Insert(&tp,new_thread_number);
		it=new TextThread(pid, hook,retn,spl,new_thread_number);
		while (table->FindThread(++new_thread_number));
		it->AddToStore(text,len);
		WCHAR entstr[0x200];
		it->GetEntryString(entstr);
		AddConsoleOutput(entstr);
	}
	LeaveCriticalSection(&hmcs);
}
void HookManager::AddConsoleOutput(LPWSTR text)
{
	if (text)
	{
		size_t len=wcslen(text)<<1;
		AddText(0,(BYTE*)text,-1,-1,-1,len);
		AddConsoleOutputNewLine();
	}
}
void HookManager::AddConsoleOutputNewLine()
{
	AddText(0,(BYTE*)L"\r\n",-1,-1,-1,4);
}
void HookManager::ClearText(UINT_PTR pid, UINT_PTR hook, UINT_PTR retn, UINT_PTR spl)
{
	bool flag=false;
	TextThread *it;
	EnterCriticalSection(&hmcs);
	ThreadParameter tp={pid,hook,retn,spl};
	TreeNode<ThreadParameter*,UINT_PTR> *in;
	in=Search(&tp);
	if (in)
	{
		it=table->FindThread(in->data);
		it->Reset();
		it->ResetEditText();
	}
	LeaveCriticalSection(&hmcs);
}
void HookManager::ClearCurrent()
{
	EnterCriticalSection(&hmcs);
	current->Reset();
	current->ResetEditText();
	LeaveCriticalSection(&hmcs);
}
void HookManager::LockHookman(){EnterCriticalSection(&hmcs);}
void HookManager::UnlockHookman(){LeaveCriticalSection(&hmcs);}
void HookManager::LockProcessHookman(UINT_PTR pid)
{
	size_t i;
	for (i=0;i<MAX_REGISTER;i++)
		if (record[i].pid_register==pid) break;
	if (i<MAX_REGISTER)
		NtWaitForSingleObject(record[i].hookman_mutex,0,0);
}
void HookManager::UnlockProcessHookman(UINT_PTR pid)
{
	size_t i;
	for (i=0;i<MAX_REGISTER;i++)
		if (record[i].pid_register==pid) break;
	if (i<MAX_REGISTER)
		NtReleaseMutant(record[i].hookman_mutex,0);
}
void HookManager::SetProcessEngineType(UINT_PTR pid, UINT_PTR type)
{
	size_t i;
	for (i=0;i<MAX_REGISTER;i++)
		if (record[i].pid_register==pid) break;
	if (i<MAX_REGISTER)
	{
		record[i].engine_register|=type;
	}
}
bool HookManager::GetProcessPath(UINT_PTR pid, LPWSTR path)
{
	HANDLE hProc=GetProcessByPID(pid);
	return ::GetProcessPath(hProc,path);

}
bool HookManager::GetProcessName(UINT_PTR pid, LPWSTR str)
{
	WCHAR path[MAX_PATH];
	if (GetProcessPath(pid,path))
	{
		wcscpy(str,wcsrchr(path,L'\\')+1);
		return true;
	}
	return false;
}
LPVOID HookManager::RemoteHook(UINT_PTR pid)
{
	size_t i;
	for (i=0;i<MAX_REGISTER;i++)
		if (record[i].pid_register==pid) break;
	return i<MAX_REGISTER?record[i].hookman_map:0;
}
UINT_PTR HookManager::GetProcessIDByPath(LPWSTR str)
{
	WCHAR path[MAX_PATH];
	for (size_t i=0;i<8&&record[i].process_handle;i++)
	{
		::GetProcessPath(record[i].process_handle,path);
		if (_wcsicmp(path,str)==0)
			return record[i].pid_register;
	}
	return 0;
}
UINT_PTR HookManager::GetCurrentPID()
{
	UINT_PTR pid=0;
	WCHAR str[0x20];
	if (GetWindowText(hwndProc,str,0x20))
		swscanf(str,L"%d",&pid);
	return pid;
}
UINT_PTR HookManager::GetPIDByHandle(HANDLE h)
{
	size_t i;
	for (i=0;i<MAX_REGISTER;i++)
		if (text_pipes[i]==h) break;
	return i<MAX_REGISTER?record[i].pid_register:0;
}
UINT_PTR HookManager::GetHookManByPID(UINT_PTR pid)
{
	size_t i;
	for (i=0;i<MAX_REGISTER;i++)
		if (record[i].pid_register==pid) break;
	return i<MAX_REGISTER?record[i].hookman_register:0;
}
UINT_PTR HookManager::GetModuleByPID(UINT_PTR pid)
{
	size_t i;
	for (i=0;i<MAX_REGISTER;i++)
		if (record[i].pid_register==pid) break;
	return i<MAX_REGISTER?record[i].module_register:0;
}
UINT_PTR HookManager::GetEngineByPID(UINT_PTR pid)
{
	size_t i;
	for (i=0;i<MAX_REGISTER;i++)
		if (record[i].pid_register==pid) break;
	return i<MAX_REGISTER?record[i].engine_register:0;
}
HANDLE HookManager::GetTextHandleByPID(UINT_PTR pid)
{
	size_t i;
	for (i=0;i<MAX_REGISTER;i++)
		if (record[i].pid_register==pid) break;
	return i<MAX_REGISTER?text_pipes[i]:0;
}
HANDLE HookManager::GetCmdHandleByPID(UINT_PTR pid)
{
	size_t i;
	for (i=0;i<MAX_REGISTER;i++)
		if (record[i].pid_register==pid) break;
	return i<MAX_REGISTER?cmd_pipes[i]:0;
}
HANDLE HookManager::GetMutexByPID(UINT_PTR pid)
{
	size_t i;
	for (i=0;i<MAX_REGISTER;i++)
		if (record[i].pid_register==pid) break;
	return i<MAX_REGISTER?record[i].hookman_mutex:0;
}
HANDLE HookManager::GetProcessByPID(UINT_PTR pid)
{
	size_t i;
	for (i=0;i<MAX_REGISTER;i++)
		if (record[i].pid_register==pid) break;
	return i<MAX_REGISTER?record[i].process_handle:0;
}

//Class member of TextThread
static UINT_PTR MIN_DETECT=0x20;
static UINT_PTR MIN_REDETECT=0x80;
//#define MIN_DETECT		0x20
//#define MIN_REDETECT	0x80
#ifndef CURRENT_SELECT
#define CURRENT_SELECT				0x1000
#endif
#ifndef REPEAT_NUMBER_DECIDED
#define REPEAT_NUMBER_DECIDED	0x2000
#endif

TextThread::TextThread(UINT_PTR id, UINT_PTR hook, UINT_PTR retn, UINT_PTR spl, UINT_PTR num) : number(num)
{
	tp.pid=id;
	tp.hook=hook;
	tp.retn=retn;
	tp.spl=spl;
	head=new RepeatCountNode;
	head->count=head->repeat=0;
	link_number=-1;	
	if (tp.pid)
	{
		AddToCombo();
		man->RegisterThread(this,num);
		man->LockProcessHookman(id);	
		LPVOID temp=man->RemoteHook(id);
		TextHook* hookman=(TextHook*)temp;
		TextHook* hookend=hookman+MAX_HOOK;
		while (hookman!=hookend) 
		{
			if (hookman->Address()==hook)
			{
				status=hookman->Type()&0xFFF;
				break;
			}
			hookman++;
		}
		man->UnlockProcessHookman(id);
		WCHAR path[MAX_PATH];
		ThreadParam *tpm; size_t i,j;
		man->GetProcessPath(id,path);
		ProfileNode* pfn=pfman->GetProfile(path);
		if (pfn)
		{
			Profile *pf=&pfn->data;
			for (i=0;i<pf->thread_count;i++)
			{
				tpm=pf->threads+i;
				if (tpm->hook_addr==hook)
				{
					UINT_PTR flag=0;
					if (tpm->status&THREAD_MASK_RETN) 
						flag+= ( (tpm->retn & 0xFFFF) == (retn & 0xFFFF) );
					else flag+=(tpm->retn == retn);
					if (tpm->status&THREAD_MASK_SPLIT) 
						flag+=( (tpm->split & 0xFFFF) == (spl & 0xFFFF) );
					else flag+=(tpm->split == spl);
					if (flag==2)
					{
						tpm->hm_index=num;
						for (j=0;j<pf->comment_count;j++) //Rename/Add comment
							if (pf->comments[j].thread_index==i+1)
							{
								RemoveFromCombo();
								comment=new WCHAR[wcslen(pf->comments[j].comment)+1];
								wcscpy(comment,pf->comments[j].comment);
								AddToCombo();
								break;
							}
						for (j=0;j<pf->link_count;j++) //Add link
						{
							LinkParam* lp=pf->links+j;
							if (lp->from_index==i+1)
							{
								size_t to_index=pf->threads[lp->to_index-1].hm_index;
								if (to_index)
									man->AddLink(num,to_index);
								else
									pf->threads[i].hm_index=num;
								break;
							}
							if (lp->to_index==i+1)
							{
								size_t from_index=pf->threads[lp->from_index-1].hm_index;
								if (from_index)
									man->AddLink(from_index,num);
								else
									pf->threads[i].hm_index=num;
								break;
							}
						}
						if (pf->select_index==i+1) //Select
							ResetEditText();
					}
				}
			}
		}
	}
}
TextThread::~TextThread()
{
	KillTimer(hMainWnd,timer);
	RepeatCountNode *t=head,*tt;
	while (t)
	{
		tt=t;
		t=tt->next;
		delete tt;
	}
	if (comment) {delete comment;comment=0;}
	if (thread_string) {delete thread_string;thread_string=0;}
}
void TextThread::Reset()
{
	timer=0;
	last_sentence=0;
	if (comment) {delete comment;comment=0;}
	MyVector::Reset();
}
void TextThread::AdjustPrevRepeat(UINT_PTR len)
{
	UINT_PTR i;
	BYTE tmp[MAX_PREV_REPEAT_LENGTH];
	for (i=0;i<len;i++)
		tmp[i]=storage[used-len+i];
	for (i=used-1;i>=last_sentence+len;i--)
		storage[i]=storage[i-len];
	for (i=0;i<len;i++)
		storage[last_sentence+i]=tmp[i];
	repeat_index+=len;
	if (repeat_index>=sentence_length) repeat_index-=sentence_length;
}
void TextThread::RemoveSingleRepeat(BYTE* con,size_t &len)
{
	WORD* text=(WORD*)con;
	if (len<=2)
	{
		if (repeat_single)
		{
			if (repeat_single_count<repeat_single&&
				last==*text) {
					len=0;
					repeat_single_count++;
			}
			else 
			{
				last=*text;
				repeat_single_count=0;
			}
		}
		if (status&REPEAT_NUMBER_DECIDED)
		{
			if (++repeat_detect_count>MIN_REDETECT)
			{
				repeat_detect_count=0;
				status^=REPEAT_NUMBER_DECIDED;
				RepeatCountNode *t=head,*tt;
				while (t)
				{
					tt=t;
					t=tt->next;
					delete tt;
				}
				head=new RepeatCountNode;
			}
		}
		else
		{
			repeat_detect_count++;
			if (last==*text) repeat_single_current++;
			else 
			{
				last=*text;
				RepeatCountNode* it=head;
				if (repeat_detect_count>MIN_DETECT)
				{
					while (it=it->next)
					{
						if (it->count>head->count)
						{
							head->count=it->count;
							head->repeat=it->repeat;
						}
					}
					repeat_single=head->repeat;
					repeat_single_current=0;
					repeat_detect_count=0;
					status|=REPEAT_NUMBER_DECIDED;
					UINT_PTR repeat_sc=repeat_single*4;
					if (repeat_sc>MIN_DETECT)
					{
						MIN_DETECT<<=1;
						MIN_REDETECT<<=1;
					}
				}
				else
				{
					bool flag=true;
					while (it)
					{
						if (it->repeat==repeat_single_current)
						{
							it->count++;
							flag=false;
							break;
						}
						it=it->next;
					}
					if (flag)
					{
						RepeatCountNode *n=new RepeatCountNode;
						n->count=1;
						n->repeat=repeat_single_current;
						n->next=head->next;
						head->next=n;
					}
					repeat_single_current=0;
				} //Decide repeat_single
			} //Check Repeat
		} //repeat_single decided?
	} //len
}
void TextThread::RemoveCyclicRepeat(BYTE* &con, size_t &len)
{
	UINT_PTR currnet_time=GetTickCount();
	if (status&REPEAT_SUPPRESS)
	{
		if (currnet_time-last_time<split_time&&
			memcmp(storage+last_sentence+repeat_index,con,len)==0)
		{
			repeat_index+=len;
			if (repeat_index>=sentence_length) repeat_index-=sentence_length;
			len=0;
		}
		else
		{
			repeat_index=0;
			status&=~REPEAT_SUPPRESS;
		}
	}
	else if (status&REPEAT_DETECT)
	{
		if (memcmp(storage+last_sentence+repeat_index,con,len)==0)
		{
			UINT_PTR half_length=repeat_index+len;
			if (memcmp(storage+last_sentence,storage+last_sentence+half_length,repeat_index)==0)
			{
				//half_length=repeat_index+len;				
				len=0;
				//used-=repeat_index;

				//memset(storage+last_sentence+half_length,0,half_length);
				sentence_length=half_length;
				status&=~REPEAT_DETECT;
				status|=REPEAT_SUPPRESS;

				if (status&CURRENT_SELECT)
					texts->ReplaceSentence(storage+last_sentence+half_length,repeat_index);
				ClearMemory(last_sentence+half_length,repeat_index);
				used-=repeat_index;
				repeat_index=0;
			}
			else repeat_index+=len;
		}		
		else
		{
			repeat_index=0;
			status&=~REPEAT_DETECT;
		}
	}
	else
	{
		if (sentence_length==0) return;
		if (len<sentence_length)
		{
			if (memcmp(storage+last_sentence,con,len)==0)
			{
				status|=REPEAT_DETECT;
				repeat_index=len;
			}
			else if (sentence_length>repeat_detect_limit)
			{
				if (len>2)
				{
					size_t u=used;
					while (memcmp(storage+u-len,con,len)==0) u-=len;
					ClearMemory(u,used-u);
					used=u;
					repeat_index=0;
					if (status&CURRENT_SELECT)
						texts->ReplaceSentence(storage+last_sentence,used-u);
					status|=REPEAT_SUPPRESS;
					len=0;
				}
				else if (len<=2)
				{
					WORD tmp=*(WORD*)(storage+last_sentence);
					UINT_PTR index,last_index,tmp_len;
					index=used-len;
					if (index<last_sentence) index=last_sentence;
_again:
					*(WORD*)(storage+last_sentence)=*(WORD*)con;
					while (*(WORD*)(storage+index)!=*(WORD*)con) index--;
					*(WORD*)(storage+last_sentence)=tmp;
					if (index>last_sentence)
					{
						tmp_len=used-index;
						if  (memcmp(storage+index-tmp_len,storage+index,tmp_len)==0)
						{
							repeat_detect_limit=0x80;
							sentence_length=tmp_len;
							index-=tmp_len;
							while (memcmp(storage+index-sentence_length,storage+index,sentence_length)==0)
								index-=sentence_length;
							repeat_index=2;
							len=0;
							last_index=index;
							if (status&USING_UNICODE)
							{							
								while (storage[index]==storage[index+sentence_length]) index-=2;
								index+=2;
								while (1)
								{
									tmp=*(WORD*)(storage+index);
									if (tmp>=0x3000&&tmp<0x3020) index+=2;
									else break;
								}								
							}
							else
							{
								UINT_PTR last_char_len;
								while (storage[index]==storage[index+sentence_length]) 
								{
									last_char_len=LeadByteTable[storage[index]];
									index-=last_char_len;
								}
								index+=last_char_len;
								while (storage[index]==0x81)
								{
									if ((storage[index+1]>>4)==4) index+=2;
									else break;
								}
							}
							repeat_index+=last_index-index;
							status|=REPEAT_SUPPRESS;
							last_sentence=index;

							index+=sentence_length;
							if (status&CURRENT_SELECT) 
								texts->ReplaceSentence(storage+index,used-index);
							ClearMemory(index,used-index);
							//memset(storage+index,0,used-index);
							used=index;
						}
						else 
						{
							index--;
							goto _again;
						}
					}
					else repeat_detect_limit+=0x40;
				}
			}
		}
	}
	last_time=currnet_time;
}
void TextThread::PrevRepeatLength(UINT_PTR &len)
{
	BYTE *p1=storage+used;
	BYTE *p2=storage+prev_sentence;
	bool flag;
	len=1;
	UINT_PTR j,k,l;
	l=last_sentence-prev_sentence;
	l=l<MAX_PREV_REPEAT_LENGTH? l:MAX_PREV_REPEAT_LENGTH;
	if (last_sentence!=prev_sentence)
	{
		for (j=2;j<l;j++)
		{
			flag=true;
			for (k=0;k<j;k++)
				if (p2[k]!=p1[k-j]) {flag=false;break;}
			if (flag) len=j;
		}
	}
}
void TextThread::AddLineBreak()
{
	if (status&BUFF_NEWLINE)
	{
		prev_sentence=last_sentence;
		sentence_length=0;
		if (status&USING_UNICODE)
		{
			MyVector::AddToStore((BYTE*)L"\r\n\r\n",8);	
			if (status&CURRENT_SELECT)
				texts->AddText((BYTE*)L"\r\n\r\n",8,true);
		}
		else
		{
			MyVector::AddToStore((BYTE*)"\r\n\r\n",4);
			if (status&CURRENT_SELECT)
				texts->AddText((BYTE*)"\r\n\r\n",4,true);
		}
		last_sentence=used;
		status&=~BUFF_NEWLINE;
	}
}
void TextThread::AddToStore(BYTE* con,size_t len, bool new_line,bool console)
{
	if (con==0) return;
	if (!new_line&&!console) RemoveSingleRepeat(con,len);
	if (len<=0) return;
	if(cyclic_remove&&!console) RemoveCyclicRepeat(con,len);
	if (len<=0) return;
	if (status&BUFF_NEWLINE) AddLineBreak();
	if (new_line)
	{
		prev_sentence=last_sentence;
		last_sentence=used+4;
		if (status&USING_UNICODE) last_sentence+=4;
		sentence_length=0;
	}
	else
	{
		SetNewLineTimer();
		if (link)
		{
			BYTE* send=con;
			size_t l=len;
			if (status&USING_UNICODE)
			{
				if ((link->Status()&USING_UNICODE)==0)
				{
					send=new BYTE[l];
					l=WC_MB((LPWSTR)con,(char*)send);
				}
				link->AddToStore(send,l);
			}
			else
			{
				if (link->Status()&USING_UNICODE)
				{
					send=new BYTE[len*2+2];
					l=MB_WC((char*)con,(LPWSTR)send)<<1;
				}
				link->AddToStore(send,l);
			}
			link->SetNewLineTimer();
			if (send!=con) delete send;
		}
	}
	sentence_length+=len;
	MyVector::AddToStore(con,len);
	if (status&CURRENT_SELECT) texts->AddText((BYTE*)con,len);
}
void TextThread::ResetEditText()
{
	size_t len;
	WCHAR *wc,null[2]={0};
	bool uni=(status&USING_UNICODE)>0;
	bool flag=false;
	if (uni) 
	{
		wc=(LPWSTR)storage;
		if (used>=8)
			flag=(wcscmp((LPWSTR)(storage+used-8),L"\r\n\r\n")==0);
		if (flag) 
		{
			used-=8;
			memset(storage+used,0,8);
		}
	}
	else
	{
		EnterCriticalSection(&cs_store);
		len=used+(used>>1);
		if (len) wc=new WCHAR[len];
		else wc=null;
		if (used>=4)
			flag=(strcmp((char*)(storage+used-4),"\r\n\r\n")==0);
		if (flag) 
		{
			used-=4;
			memset(storage+used,0,4);
		}
		wc[MB_WC((char*)storage,wc)]=0;
		LeaveCriticalSection(&cs_store);
	}
	if (man)
	man->SetCurrent(this);
	texts->SetUnicode(uni);
	texts->ClearBuffer();
	texts->SetLine();

	SendMessage(hwndEdit, WM_SETTEXT, 0, (LPARAM)wc);
	len=SendMessage(hwndEdit, EM_GETLINECOUNT, 0, 0);
	SendMessage(hwndEdit, EM_LINESCROLL, 0, len);
	ComboSelectCurrent();
	if (flag)
	{
		if (uni)
		{
			memcpy(storage+used,L"\r\n\r\n",10);
			used+=8;
			texts->AddText((BYTE*)L"\r\n\r\n",8,true);
		}
		else
		{
			memcpy(storage+used,"\r\n\r\n",5);
			used+=4;
			texts->AddText((BYTE*)"\r\n\r\n",4,true);
		}
	}
	if (wc!=(LPWSTR)storage&&wc!=null) delete wc;
}
void TextThread::ComboSelectCurrent()
{
	size_t index;
	WCHAR temp[0x200];
	GetEntryString(temp);
	index=SendMessage(hwndCombo, CB_FINDSTRINGEXACT , 0 , (LPARAM)temp);
	if (index==CB_ERR) return;
	SendMessage(hwndCombo, CB_SETCURSEL, index , 0);
}
void TextThread::GetEntryString(LPWSTR str)
{
	if (str)
	{
		if (thread_string)
		{
			wcscpy(str,thread_string);
			str+=wcslen(thread_string);
		}
		else
		{
			LPWSTR begin=str;
			str+=swprintf(str,L"%.4X:%.4d:0x%08X:0x%08X:0x%08X:",number,tp.pid,tp.hook,tp.retn,tp.spl); 
			str+=GetHookName(str,tp.pid,tp.hook);
			thread_string=new WCHAR[str-begin+1];
			wcscpy(thread_string,begin);
		}
		if (comment) {*str++=L'-';wcscpy(str,comment);}
	}
}
void TextThread::CopyLastSentence(LPWSTR str)
{
	__int64 i,j,l;
	if (status&USING_UNICODE)
	{
		if (used>8)
		{
			j=used>0xF0?(used-0xF0):0;
			for (i=used-0xA;i>=j;i-=2)
			{
				if (*(DWORD*)(storage+i)==0xA000D) break;
			}
			if (i>=j)
			{
				l=used-i;
				if (i>j) l-=4;			
				j=4;
			}
			else
			{
				i+=2;
				l=used-i;
				j=0;
			}
			memcpy(str,storage+i+j,l);
			str[l>>1]=0;
		}
		else 
		{
			memcpy(str,storage,used);
			str[used>>1]=0;
		}
	}
	else
	{
		if (used>4)
		{
			j=used>0x80?(used-0x80):0;
			for (i=used-5;i>=j;i--)
			{
				if (*(DWORD*)(storage+i)==0xA0D0A0D) break;
			}
			if (i>=j)
			{
				l=used-i;
				if (i>j) l-=4;
				j=4;
			}
			else
			{
				i++;
				l=used-i;
				j=0;
			}
			char* buff=new char[(l|0xF)+1];
			memcpy(buff,storage+i+j,l);
			buff[l]=0;		
			str[MB_WC(buff,str)]=0;
			delete buff;
		}
		else 
		{
			storage[used]=0;
			str[MB_WC((char*)storage,str)]=0;
		}
	}
}
void TextThread::CopyLastToClipboard()
{
	CopyToClipboard(storage+last_sentence,(status&USING_UNICODE)>0,used-last_sentence);
}
void TextThread::SetComment(LPWSTR str)
{
	if (comment) delete comment;
	comment=new WCHAR[wcslen(str)+1];
	wcscpy(comment,str);
}
void TextThread::SetNewLineTimer()
{
	if (number==0)
		timer=SetTimer(hMainWnd,(UINT_PTR)this,split_time,(TIMERPROC)NewLineConsole);
	else
		timer=SetTimer(hMainWnd,(UINT_PTR)this,split_time,(TIMERPROC)NewLineBuff);
}
bool TextThread::AddToCombo()
{
	size_t i;
	WCHAR entry[0x200];
	GetEntryString(entry);
	if (SendMessage(hwndCombo,CB_FINDSTRING,0,(LPARAM)entry)==CB_ERR)
		i=SendMessage(hwndCombo,CB_ADDSTRING,0,(LPARAM)entry);
	else return false;
	if (status&CURRENT_SELECT) SendMessage(hwndCombo,CB_SETCURSEL,0,(LPARAM)entry);
	return true;
}
bool TextThread::RemoveFromCombo()
{
	size_t i,j;
	WCHAR entry[0x200];
	GetEntryString(entry);

	i=SendMessage(hwndCombo,CB_FINDSTRING,0,(LPARAM)entry);
	j=SendMessage(hwndCombo,CB_GETCURSEL,0,0);
	if (i==CB_ERR) return false;
	if (SendMessage(hwndCombo,CB_DELETESTRING,i,0)==CB_ERR) 
		man->AddConsoleOutput(L"Error delete from combo.");
	return (i==j);
}
bool TextThread::CheckCycle(TextThread* start)
{
	if (link==start||this==start) return true;
	if (link==0) return false;
	return link->CheckCycle(start);
}
inline void TextThread::SetNewLineFlag() {status|=BUFF_NEWLINE;}
inline void TextThread::SetRepeatFlag() {status|=CYCLIC_REPEAT;}
inline void TextThread::ClearNewLineFlag() {status&=~BUFF_NEWLINE;}
inline void TextThread::ClearRepeatFlag() {status&=~CYCLIC_REPEAT;}

MK_FUNDA_TYPE(DWORD)
MK_FUNDA_TYPE(UINT_PTR)
MK_FUNDA_TYPE(BYTE)
MK_FUNDA_TYPE(LPVOID)
MK_FUNDA_TYPE(ThreadParameter)


UINT_PTR Hash(LPWSTR module, size_t length)
{
	if (length==-1) return GetHash(module);
	LPWSTR str=new WCHAR[length+1];
	memcpy(str,module,length*2);
	str[length]=0;
	UINT_PTR hash=GetHash(str);
	delete str;
	return hash;
	/*bool flag=(length==-1);
	UINT_PTR hash=0;
	for (;*module&&(flag||length--);module++)
	{
		hash=((hash>>7)|(hash<<25))+(*module);
	}*/
}
void CopyToClipboard(void* str,bool unicode, size_t len)
{
	static char clipboard_buffer[0x400];
	if (clipboard_flag)
		if (str)
		{
			size_t size=(len*2+0x10)&~0xF;
			if (len>=0x3FE) return;
			memcpy(clipboard_buffer,str,len);
			*(WORD*)(clipboard_buffer+len)=0;
			HGLOBAL hCopy;
			LPWSTR copy;
			if (OpenClipboard(0))
			{
				if (hCopy=GlobalAlloc(GMEM_MOVEABLE,size))
				{
					if (copy=(LPWSTR)GlobalLock(hCopy))
					{
						if (unicode)
						{
							memcpy(copy,clipboard_buffer,len+2);
						}
						else
							copy[MB_WC(clipboard_buffer,copy)]=0;					
						GlobalUnlock(hCopy);
						EmptyClipboard();
						SetClipboardData(CF_UNICODETEXT,hCopy);
					}
				}
				CloseClipboard();
			}
		}
}
void ConsoleOutput(LPWSTR text)
{
	man->AddConsoleOutput(text);
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
UINT_PTR PrintSignedPtr(LPWSTR str, UINT_PTR d)
{
	UINT_PTR l=0;
	if (d>>63)
	{
		str[0]=L'-';
		d=-d;
		str++;
		l=1;
	}
	return l+PrintUnsignedPtr(str,d);
}

void GetCode(const HookParam& hp, LPWSTR buffer, UINT_PTR pid)
{
	WCHAR c;
	LPWSTR ptr=buffer;
	if (hp.type&PRINT_DWORD) c=L'H';
	else if (hp.type&USING_UNICODE)
	{
		if (hp.type&USING_STRING) c=L'Q';
		else if (hp.type&STRING_LAST_CHAR) c=L'L';
		else c=L'W';
	}
	else
	{
		if (hp.type&USING_STRING) c=L'S';
		else if (hp.type&BIG_ENDIAN) c=L'A';
		else if (hp.type&STRING_LAST_CHAR) c=L'E';
		else c=L'B';
	}
	ptr+=swprintf(ptr,L"/H%c",c);
	if(hp.type&NO_CONTEXT) *ptr++=L'N';
	ptr+=PrintSignedPtr(ptr,hp.off);
	//if (hp.off>>63) ptr+=swprintf(ptr,L"-%p",-(hp.off+4));
	//else ptr+=swprintf(ptr,L"%X",hp.off);
	if (hp.type&DATA_INDIRECT)
	{
		ptr+=PrintSignedPtr(ptr,hp.ind);
		//if (hp.ind>>31) ptr+=swprintf(ptr,L"*-%X",-hp.ind);
		//else ptr+=swprintf(ptr,L"*%X",hp.ind);
	}
	if (hp.type&USING_SPLIT)
	{
		ptr+=PrintSignedPtr(ptr,hp.split);
		//if (hp.split>>31) ptr+=swprintf(ptr,L":-%X",-(4+hp.split));
		//else ptr+=swprintf(ptr,L":%X",hp.split);
	}
	if (hp.type&SPLIT_INDIRECT)
	{
		ptr+=PrintSignedPtr(ptr,hp.split_ind);
		//if (hp.split_ind>>31) ptr+=swprintf(ptr,L"*-%X",-hp.split_ind);
		//else ptr+=swprintf(ptr,L"*%X",hp.split_ind);
	}
	if (hp.module)
	{
		if (pid)
		{
			BYTE path[MAX_PATH*2];
			PUNICODE_STRING us=(PUNICODE_STRING)path;
			MEMORY_BASIC_INFORMATION info;
			HANDLE hProc=man->GetProcessByPID(pid);
			if (NT_SUCCESS(NtQueryVirtualMemory(hProc,(PVOID)hp.addr,MemorySectionName,path,MAX_PATH*2,0)))
			if (NT_SUCCESS(NtQueryVirtualMemory(hProc,(PVOID)hp.addr,MemoryBasicInformation,&info,sizeof(info),0)))
			{
				*ptr++=L'@';
				ptr+=PrintUnsignedPtr(ptr,hp.addr-(UINT_PTR)info.BaseAddress);
				ptr+=swprintf(ptr,L":%s",wcsrchr(us->Buffer,L'\\')+1);
			}
		}
		else
		{
			*ptr++=L'@';
			ptr+=PrintUnsignedPtr(ptr,hp.addr);
			*ptr++=L'!';
			ptr+=PrintUnsignedPtr(ptr,hp.module);
			//ptr+=swprintf(ptr,L"@%p!%p",hp.addr,hp.module);
			if (hp.function) 
			{
				*ptr++=L'!';
				ptr+=PrintUnsignedPtr(ptr,hp.function);
				//ptr+=swprintf(ptr,L"!%p",hp.function);
			}
		}
	}
	else
	{
		*ptr++=L'@';
		PrintUnsignedPtr(ptr,hp.addr);
		//ptr+=swprintf(ptr,L"@%p",hp.addr);
	}

}
