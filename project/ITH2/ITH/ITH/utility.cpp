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
#include "..\version.h"
#include <emmintrin.h>
#define MAX_ENTRY 0x40
//#include <richedit.h>
WCHAR user_entry[0x40];
static BYTE null_buffer[4]={0,0,0,0};
static BYTE static_small_buffer[0x100];
static DWORD zeros[4]={0,0,0,0};
extern BYTE* static_large_buffer;
extern DWORD repeat_count,background;
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
int GetHookName(LPWSTR str, DWORD pid, DWORD hook_addr)
{
	if (pid==0) 
	{
		wcscpy(str,HookNameInitTable[0]);
		return wcslen(HookNameInitTable[0]);
	}
	DWORD len=0;
	man->LockProcessHookman(pid);
	Hook* hks=(Hook*)man->RemoteHook(pid);
	for (int i=0;i<MAX_HOOK;i++)
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
int GetHookNameByIndex(LPWSTR str, DWORD pid, DWORD index)
{
	if (pid==0) 
	{
		wcscpy(str,HookNameInitTable[0]);
		return wcslen(HookNameInitTable[0]);
	}
	DWORD len=0;
	Hook* hks=(Hook*)man->RemoteHook(pid);
	if (hks[index].Address())
	{
		NtReadVirtualMemory(man->GetProcessByPID(pid),hks[index].Name(),str,hks[index].NameLength()<<1,&len);
		len=hks[index].NameLength();
	}
	return len;
}
int GetHookString(LPWSTR str, DWORD pid, DWORD hook_addr, DWORD status)
{
	LPWSTR begin=str;
	str+=swprintf(str,L"%4d:0x%08X:",pid,hook_addr); 
	str+=GetHookName(str,pid,hook_addr);
	return str-begin;
}

void CALLBACK NewLineBuff(HWND hwnd, UINT uMsg, UINT_PTR idEvent, DWORD dwTime)
{
	KillTimer(hwnd,idEvent);
	TextThread *id=(TextThread*)idEvent;
			
	if (id->Status()&CURRENT_SELECT)
	{
		texts->SetLine();
		id->CopyLastToClipboard();
	}
	id->SetNewLineFlag();
}
void CALLBACK NewLineConsole(HWND hwnd, UINT uMsg, UINT_PTR idEvent, DWORD dwTime)
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
DWORD WINAPI FlushThread(LPVOID lpThreadParameter)
{
	LARGE_INTEGER sleep_interval={-100000,-1};
	while (hwndEdit==0) NtDelayExecution(0,&sleep_interval);
	TextBuffer* t=(TextBuffer*)lpThreadParameter;
	while (running) {
		t->Flush();
		NtDelayExecution(0,&sleep_interval);
	}
	return 0;
}
BitMap::BitMap(): size(0x20)
{
	//map=new BYTE[size];
}
BitMap::BitMap(DWORD init_size): size(init_size>>3)
{
	map=new BYTE[size];
}
BitMap::~BitMap()
{
	if (map) 
	{
		delete map;
		map=0;
	}
}
bool BitMap::Check(DWORD number)
{	
	if ((number>>3)>=size) return false;
	return (map[number>>3]&(1<<(number&7)))!=0;
	}
void BitMap::Set(DWORD number)
{
	if (number>>16) return;
	DWORD s=number>>3;
	DWORD t=s>>2;
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
void BitMap::Reset()
{
	memset(map,0,size);
}
void BitMap::Clear(DWORD number)
{
	if ((number>>3)>=size) return;
	map[number>>3]&=~(1<<(number&7));
}

CustomFilterUnicode::CustomFilterUnicode()
{
	map=0;
	size=0x2000;
	NtAllocateVirtualMemory(NtCurrentProcess(),(PVOID*)&map,0,&size,MEM_COMMIT,PAGE_READWRITE);
}
CustomFilterUnicode::~CustomFilterUnicode()
{
	NtFreeVirtualMemory(NtCurrentProcess(),(PVOID*)&map,&size,MEM_RELEASE);
	map=0;
}
void CustomFilterUnicode::Set(WORD number)
{
	map[number>>3]|=1<<(number&7);

}
void CustomFilterUnicode::Clear(WORD number)
{
	map[number>>3]&=~(1<<(number&7));

}
bool CustomFilterUnicode::Check(WORD number)
{
	return (map[number>>3]>>(number&7))&1;
}
void CustomFilterUnicode::Traverse(CustomFilterCallBack callback)
{
	union{ __m128d m0; __m128i i0;};
	union{ __m128d m1; __m128i i1;};
	DWORD mask,i,j,k,t,ch;
	m1=_mm_loadu_pd((const double*)zeros);
	BYTE* ptr=map;
	BYTE* end=map+size;
	while (ptr<end) //multi byte
	{
		m0=_mm_load_pd((const double*)ptr);
		i0=_mm_cmpeq_epi8(i0,i1); //SSE zero test, 16 bytes/loop, 256 bit/loop, overall 256 loop.
		mask=_mm_movemask_epi8(i0);
		if (mask!=0xFFFF)
		{
			for (i=0;i<0x10;i+=4)
			{
				if (*(DWORD*)(ptr+i)==0) continue; //dword compare, 4 bytes/loop
				for (j=0;j<4;j++)
				{
					if (ptr[i+j]) //byte compare, one byte/loop
					{
						t=1;
						for (k=0;k<8;k++)//test bit, one bit/loop
						{
							if (ptr[i+j]&t) 
							{
								ch=((ptr-map+i+j)<<3)+k;			
								callback(ch&0xFFFF);
							}
							t<<=1;
						}
					}
				}
			}
		}
		ptr+=0x10;
	}
}

CustomFilterMultiByte::CustomFilterMultiByte()
{
	map=0;
	size=0x1000;
	NtAllocateVirtualMemory(NtCurrentProcess(),(PVOID*)&map,0,&size,MEM_COMMIT,PAGE_READWRITE);

}
CustomFilterMultiByte::~CustomFilterMultiByte()
{
	NtFreeVirtualMemory(NtCurrentProcess(),(PVOID*)&map,&size,MEM_RELEASE);
	map=0;
}
void CustomFilterMultiByte::Set(WORD number)
{
	BYTE c=number&0xFF;
	if (LeadByteTable[c]==1) ascii_map[c>>3]|=1<<(c&7);
	else
	{
		number>>=8;
		number|=(c-0x80)<<8;
		map[number>>3]|=1<<(number&7);
	}

}
void CustomFilterMultiByte::Clear(WORD number)
{
	BYTE c=number&0xFF;
	if (LeadByteTable[c]==1) ascii_map[c>>3]&=~(1<<(c&7));
	else
	{
		number>>=8;
		number|=(c-0x80)<<8;
		map[number>>3]&=~(1<<(number&7));
	}
}
bool CustomFilterMultiByte::Check(WORD number)
{
	BYTE c=number&0xFF;
	if (LeadByteTable[c]==1)
		return (ascii_map[c>>3]>>(c&7))&1;
	else
	{
		number=(number>>8)+((c-0x80)<<8);
		return (map[number>>3]>>(number&7))&1;
	}
}
void CustomFilterMultiByte::Reset()
{
	BitMap::Reset();
	memset(ascii_map,0,0x20);
}
void CustomFilterMultiByte::Traverse(CustomFilterCallBack callback)
{
	union{ __m128d m0; __m128i i0;};
	union{ __m128d m1; __m128i i1;};
	DWORD mask,i,j,k,t,ch,cl;
	m1=_mm_loadu_pd((const double*)zeros);
	BYTE* ptr=map;
	BYTE* end=map+size;
	while (ptr<end) //multi byte
	{
		m0=_mm_load_pd((const double*)ptr);
		i0=_mm_cmpeq_epi8(i0,i1); //SSE zero test, 16 bytes/loop, 256 bit/loop, overall 256 loop.
		mask=_mm_movemask_epi8(i0);
		if (mask!=0xFFFF)
		{
			for (i=0;i<0x10;i+=4)
			{
				if (*(DWORD*)(ptr+i)==0) continue; //dword compare, 4 bytes/loop
				for (j=0;j<4;j++)
				{
					if (ptr[i+j]) //byte compare, one byte/loop
					{
						t=1;
						for (k=0;k<8;k++)//test bit, one bit/loop
						{
							if (ptr[i+j]&t) 
							{
								ch=((ptr-map+i+j)<<3)+k;			
								cl=(ch&0xFF)<<8;
								ch=(ch>>8)+0x80;
								ch|=cl;
								callback(ch&0xFFFF);
							}
							t<<=1;
						}
					}
				}
			}
		}
		ptr+=0x10;
	}

	for (i=0;i<0x20;i+=4) //single byte
	{
		if (*(DWORD*)(ascii_map+i))
		{
			for (j=0;j<4;j++)
			{
				if (ascii_map[i+j])
				{
					t=1;
					for (k=0;k<8;k++)
					{
						if (ascii_map[i+j]&t)
						{
							ch=((i+j)<<3)+k;
							callback(ch&0xFFFF);
						}
						t<<=1;
					}
				}
			}
		}
	}
}

TextBuffer::TextBuffer():line(false),unicode(false)
{
	NtClose(IthCreateThread(FlushThread,(DWORD)this));

}
TextBuffer::~TextBuffer()
{
}
void TextBuffer::AddText(BYTE* text,int len, bool l=false)
{
	if (text==0||len==0) return;
	AddToStore(text,len);
	line=l;
}
void TextBuffer::AddNewLIne()
{

}
void TextBuffer::ReplaceSentence(BYTE* text, int len)
{
	if (len==0) return;
	EnterCriticalSection(&cs_store);
	Flush();
	DWORD t,l;
	t=GetWindowTextLength(hwndEdit);
	if (unicode)
	{
		SendMessage(hwndEdit,EM_SETSEL,t-(len>>1),t);
		SendMessage(hwndEdit,WM_CLEAR,0,0);
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
	DWORD t;
	t=SendMessage(hwndEdit,WM_GETTEXTLENGTH,0,0);
	SendMessage(hwndEdit,EM_SETSEL,t,-1);
	EnterCriticalSection(&cs_store);
	storage[used]=0;
	storage[used+1]=0;

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

void ThreadTable::SetThread(DWORD num, TextThread* ptr)
{
	int number=num;
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
TextThread* ThreadTable::FindThread(DWORD number)
{
	if ((int)number<=used)
		return storage[number];
	else return 0;
}

static const char sse_table_eq[0x100]={
	-1,1,-1,1, -1,1,-1,1, -1,1,-1,1, -1,1,-1,1, //0, compare 1
	-1,-1,1,1, -1,-1,1,1, -1,-1,1,1, -1,-1,1,1, //1, compare 2
	-1,1,-1,1, -1,1,-1,1, -1,1,-1,1, -1,1,-1,1, //0, compare 1
	-1,-1,-1,-1, 1,1,1,1, -1,-1,-1,-1, 1,1,1,1, //3, compare 3
	-1,1,-1,1, -1,1,-1,1, -1,1,-1,1, -1,1,-1,1, //0, compare 1
	-1,-1,1,1, -1,-1,1,1, -1,-1,1,1, -1,-1,1,1, //1, compare 2
	-1,1,-1,1, -1,1,-1,1, -1,1,-1,1, -1,1,-1,1, //0, compare 1
	-1,-1,-1,-1, -1,-1,-1,-1, 1,1,1,1, 1,1,1,1, //7, compare 4
	-1,1,-1,1, -1,1,-1,1, -1,1,-1,1, -1,1,-1,1, //0, compare 1
	-1,-1,1,1, -1,-1,1,1, -1,-1,1,1, -1,-1,1,1, //1, compare 2
	-1,1,-1,1, -1,1,-1,1, -1,1,-1,1, -1,1,-1,1, //0, compare 1
	-1,-1,-1,-1, 1,1,1,1, -1,-1,-1,-1, 1,1,1,1, //3, compare 3
	-1,1,-1,1, -1,1,-1,1, -1,1,-1,1, -1,1,-1,1, //0, compare 1
	-1,-1,1,1, -1,-1,1,1, -1,-1,1,1, -1,-1,1,1, //1, compare 2
	-1,1,-1,1, -1,1,-1,1, -1,1,-1,1, -1,1,-1,1, //0, compare 1
	0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0 //f, equal
};
char original_cmp(const ThreadParameter* t1, const ThreadParameter* t2)
{
	int t;
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
				return t1->spl>t2->spl?1:-1;
			}
			else return t1->retn>t2->retn?1:-1;
		}
		else return t1->hook>t2->hook?1:-1;
	}
	else return t1->pid>t2->pid?1:-1;
	//return t>0?1:-1;
}
char TCmp::operator()(const ThreadParameter* t1, const ThreadParameter* t2)
	//SSE speed up. Compare 4 integer in const time without branching.
	//The AVL tree branching needs 2 bit of information.
	//One bit for equality and one bit for "less than" or "greater than".

{
	union{__m128 m0;__m128i i0;};
	union{__m128 m1;__m128i i1;};
	union{__m128 m2;__m128i i2;};
	int k0,k1;
	i1 = _mm_loadu_si128((const __m128i*)t1);
	i2 = _mm_loadu_si128((const __m128i*)t2);
	i0 = _mm_cmpgt_epi32(i1,i2);
	k0 = _mm_movemask_ps(m0);
	i1 = _mm_cmpeq_epi32(i1,i2);
	k1 = _mm_movemask_ps(m1);
	return sse_table_eq[k1*16+k0];
}
void TCpy::operator()(ThreadParameter* t1, ThreadParameter* t2)
{
	memcpy(t1,t2,sizeof(ThreadParameter));
}
int TLen::operator()(ThreadParameter* t) {return 0;}

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
	thread_table=new ThreadTable;
	entry=new TextThread(0, -1,-1,-1, new_thread_number++);
	thread_table->SetThread(0,entry);
	SetCurrent(entry);
	entry->Status()|=USING_UNICODE;
	texts->SetUnicode(true);
	entry->AddToCombo();
	entry->ComboSelectCurrent();
	entry->AddToStore((BYTE*)version,wcslen(version)<<1,0,1);
	entry->AddToStore((BYTE*)InitMessage,wcslen(InitMessage)<<1,0,1);
	if (background==0) entry->AddToStore((BYTE*)BackgroundMsg,wcslen(BackgroundMsg)<<1,0,1);

	InitializeCriticalSection(&hmcs);
	destroy_event=IthCreateEvent(0,0,0);
}
HookManager::~HookManager()
{
	LARGE_INTEGER timeout={-1000*1000,-1};
	NtWaitForSingleObject(destroy_event,0,&timeout);
	delete thread_table;
	delete head.key;
	DeleteCriticalSection(&hmcs);
}
TextThread* HookManager::FindSingle(DWORD pid, DWORD hook, DWORD retn, DWORD split)
{
	if (pid==0) return thread_table->FindThread(0);
	ThreadParameter tp={pid,hook,retn,split};
	return thread_table->FindThread(Search(&tp)->data);
}
TextThread* HookManager::FindSingle(DWORD number)
{
	if (number&0x80008000) return 0;
	return thread_table->FindThread(number);
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
	DWORD num;
	TextThread* st;
	swscanf(str,L"%x",&num);
	st=FindSingle(num);
	if (st)
	{
		st->ResetEditText();
		SetCurrent(st);
	}
}
void HookManager::RemoveSingleHook(DWORD pid, DWORD addr)
{
	EnterCriticalSection(&hmcs);
	DWORD max=thread_table->Used();
	TextThread* it;
	bool flag=false;
	DWORD number;
	for (DWORD i=1;i<=max;i++)
	{
		it=thread_table->FindThread(i);
		if (it)
		{
			if (it->PID()==pid&&it->Addr()==addr)
			{
				flag|=it->RemoveFromCombo();
				thread_table->SetThread(i,0);
				if (it->Number()<new_thread_number)
					new_thread_number=it->Number();				
				Delete(it->GetThreadParameter());
				delete it;
			}
		}
	}
	for (DWORD i=0;i<=max;i++)
	{
		it=thread_table->FindThread(i);
		if (it==0) continue;
		WORD ln=it->LinkNumber();
		if (thread_table->FindThread(ln)==0)
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
		it=thread_table->FindThread(number);
		it->ResetEditText();
	}
	LeaveCriticalSection(&hmcs);
}
void HookManager::RemoveSingleThread(DWORD number)
{
	if (number==0) return;
	bool flag;
	EnterCriticalSection(&hmcs);
	TextThread* it=thread_table->FindThread(number);
	if (it)
	{
		thread_table->SetThread(number,0);
		Delete(it->GetThreadParameter());
		flag=it->RemoveFromCombo();
		if (it->Number()<new_thread_number)
			new_thread_number=it->Number();
		delete it;
		for (int i=0;i<=thread_table->Used();i++)
		{
			it=thread_table->FindThread(i);
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
			if (head.Left)
				number=head.Left->data;
			else number=0;

			it=thread_table->FindThread(number);
			it->ResetEditText();
		}
	}
	LeaveCriticalSection(&hmcs);
}
void HookManager::RemoveProcessContext(DWORD pid)
{
	TextThread* it;
	bool flag=false;
	DWORD ln;
	for (int i=1;i<thread_table->Used();i++)
	{
		it=thread_table->FindThread(i);
		if (it)
		{
			if (it->PID()==pid)
			{
				if (false==Delete(it->GetThreadParameter()))
					if (nt_flag) __asm int 3
				flag|=it->RemoveFromCombo();
				if (it->Number()<new_thread_number)
					new_thread_number=it->Number();
				thread_table->SetThread(i,0);
				delete it;
			}
		}
	}
	for (int i=0;i<thread_table->Used();i++)
	{
		it=thread_table->FindThread(i);
		if (it==0) continue;
		if (it->Link()==0) continue;
		ln=it->LinkNumber();
		if (thread_table->FindThread(ln)==0)
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
		it=thread_table->FindThread(ln);
		if (it) it->ResetEditText();
	}
}
void HookManager::RegisterThread(TextThread* it, DWORD num)
{
	thread_table->SetThread(num,it);
}
void HookManager::RegisterPipe(HANDLE text, HANDLE cmd, HANDLE thread)
{
	text_pipes[register_count]=text;
	cmd_pipes[register_count]=cmd;
	recv_threads[register_count]=thread;
	register_count++;
	if (register_count==1) NtSetEvent(destroy_event,0);
	else NtClearEvent(destroy_event);
}
void HookManager::RegisterProcess(DWORD pid, DWORD hookman, DWORD module, DWORD engine)
{
	WCHAR str[0x40],path[MAX_PATH];	
	pid_map->Set(pid>>2);
	record[register_count-1].pid_register=pid;
	record[register_count-1].hookman_register=hookman;
	record[register_count-1].module_register=module;
	record[register_count-1].engine_register=engine;
	swprintf(str,L"ITH_SECTION_%d",pid);
	HANDLE hSection=IthCreateSection(str,0x2000,PAGE_READONLY);
	LPVOID map=0; 
	DWORD map_size=0x1000;
	NtMapViewOfSection(hSection,NtCurrentProcess(),&map,0,
		0x1000,0,&map_size,ViewUnmap,0,PAGE_READONLY);
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
		man->AddConsoleOutput(ErrorOpenProcess);
		return;
	}

	swprintf(str,L"ITH_HOOKMAN_%.4d",pid);
	record[register_count-1].hookman_mutex=IthOpenMutex(str);
	if (GetProcessPath(pid,path)==false) path[0]=0;
	swprintf(str,L"%.4d:%s",pid,wcsrchr(path,L'\\')+1);
	SendMessage(hwndProc,CB_ADDSTRING,0,(LPARAM)str);
	if (SendMessage(hwndProc,CB_GETCOUNT,0,0)==1)
		SendMessage(hwndProc,CB_SETCURSEL,0,0);
	pfman->RefreshProfileAddr(pid,path);
}
void HookManager::UnRegisterProcess(DWORD pid)
{
	int i,j,k;
	EnterCriticalSection(&hmcs);
	WCHAR str[0x10];
	swprintf(str,L"%.4d",pid);
	i=SendMessage(hwndProc,CB_FINDSTRING,0,(LPARAM)str);
	j=SendMessage(hwndProc,CB_GETCURSEL,0,0);
	if (i!=CB_ERR)
	{
		k=SendMessage(hwndProc,CB_DELETESTRING,i,0);
		if (i==j) SendMessage(hwndProc,CB_SETCURSEL,k-1,0);
	}
	else 
	{
		MessageBox(0,L"Internal error.",str,0);
		goto _unregistered;
	}
	for (i=0;i<MAX_REGISTER;i++) if(record[i].pid_register==pid) break;
	//FreeThreadStart(record[i].process_handle);

	if (i<MAX_REGISTER)
	{
		NtClose(text_pipes[i]);
		NtClose(cmd_pipes[i]);
		NtClose(recv_threads[i]);
		NtClose(record[i].hookman_mutex);
		NtClose(record[i].process_handle);
		NtClose(record[i].hookman_section);
		NtUnmapViewOfSection(NtCurrentProcess(),record[i].hookman_map);
		for (;i<MAX_REGISTER;i++)
		{
			record[i]=record[i+1];
			text_pipes[i]=text_pipes[i+1];
			cmd_pipes[i]=cmd_pipes[i+1];
			recv_threads[i]=recv_threads[i+1];
			if (text_pipes[i]==0) break;
		}
		register_count--;
		RemoveProcessContext(pid);
		//entry_table->RemoveProcessHook(pid);
	}
	pid_map->Clear(pid>>2);
_unregistered:
	if (register_count==1) NtSetEvent(destroy_event,0);
	LeaveCriticalSection(&hmcs);
}
void HookManager::SetName(DWORD type)
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
void HookManager::AddLink(WORD from, WORD to)
{
	bool flag=false;
	TextThread *from_thread, *to_thread;
	EnterCriticalSection(&hmcs);
	from_thread=thread_table->FindThread(from);
	to_thread=thread_table->FindThread(to);
	if (to_thread&&from_thread)
	{
		if (from_thread->Link()==to_thread) 
			AddConsoleOutput(ErrorLinkExist);
		else if (to_thread->CheckCycle(from_thread))
			AddConsoleOutput(ErrorCylicLink);
		else
		{
			from_thread->Link()=to_thread;
			from_thread->LinkNumber()=to;
			WCHAR str[0x40];
			swprintf(str,FormatLink,from,to);
			AddConsoleOutput(str);
		}
	}
	else 
		AddConsoleOutput(ErrorLink);
	LeaveCriticalSection(&hmcs);
}
void HookManager::DispatchText(DWORD pid, BYTE* text, DWORD hook, DWORD retn, DWORD spl, int len)
{
	bool flag=false;
	TextThread *it;
	DWORD number;
	if (text==0) return;
	if (len==0) return;
	EnterCriticalSection(&hmcs);
	ThreadParameter tp={pid,hook,retn,spl};
	TreeNode<ThreadParameter*,DWORD> *in;
	number=-1;
	if (pid)
	{
		in=Search(&tp);
		if (in) number=in->data;
	}
	else number=0;
	if (number!=-1)
	{
		it=thread_table->FindThread(number);
	}
	else
	{
		Insert(&tp,new_thread_number);
		it=new TextThread(pid, hook,retn,spl,new_thread_number);
		while (thread_table->FindThread(++new_thread_number));	
		WCHAR entstr[0x200];
		it->GetEntryString(entstr);
		AddConsoleOutput(entstr);
	}
	LeaveCriticalSection(&hmcs);
	it->AddToStore(text,len,false,number==0);
}
void HookManager::AddConsoleOutput(LPCWSTR text)
{
	if (text)
	{
		int len=wcslen(text)<<1;
		TextThread *console=thread_table->FindThread(0);
		//EnterCriticalSection(&hmcs);
		console->AddToStore((BYTE*)text,len,false,true);
		console->AddToStore((BYTE*)L"\r\n",4,true,true);
		//LeaveCriticalSection(&hmcs);
	}
}
void HookManager::ClearText(DWORD pid, DWORD hook, DWORD retn, DWORD spl)
{
	bool flag=false;
	TextThread *it;
	EnterCriticalSection(&hmcs);
	ThreadParameter tp={pid,hook,retn,spl};
	TreeNode<ThreadParameter*,DWORD> *in;
	in=Search(&tp);
	if (in)
	{
		it=thread_table->FindThread(in->data);
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
void HookManager::ResetRepeatStatus()
{
	EnterCriticalSection(&hmcs);
	int i;
	TextThread* t;
	for (i=1;i<thread_table->Used();i++)
	{
		t=thread_table->FindThread(i);
		if (t==0) continue;
		t->ResetRepeatStatus();
	}
	LeaveCriticalSection(&hmcs);
}
void HookManager::LockHookman(){EnterCriticalSection(&hmcs);}
void HookManager::UnlockHookman(){LeaveCriticalSection(&hmcs);}
void HookManager::LockProcessHookman(DWORD pid)
{
	int i;
	for (i=0;i<MAX_REGISTER;i++)
		if (record[i].pid_register==pid) break;
	if (i<MAX_REGISTER)
		NtWaitForSingleObject(record[i].hookman_mutex,0,0);
}
void HookManager::UnlockProcessHookman(DWORD pid)
{
	int i;
	for (i=0;i<MAX_REGISTER;i++)
		if (record[i].pid_register==pid) break;
	if (i<MAX_REGISTER)
		NtReleaseMutant(record[i].hookman_mutex,0);
}
void HookManager::SetProcessEngineType(DWORD pid, DWORD type)
{
	int i;
	for (i=0;i<MAX_REGISTER;i++)
		if (record[i].pid_register==pid) break;
	if (i<MAX_REGISTER)
	{
		record[i].engine_register|=type;
	}
}
bool HookManager::GetProcessPath(DWORD pid, LPWSTR path)
{
	HANDLE hProc=GetProcessByPID(pid);
	return ::GetProcessPath(hProc,path);

}
bool HookManager::GetProcessName(DWORD pid, LPWSTR str)
{
	WCHAR path[MAX_PATH];
	if (GetProcessPath(pid,path))
	{
		wcscpy(str,wcsrchr(path,L'\\')+1);
		return true;
	}
	return false;
}
LPVOID HookManager::RemoteHook(DWORD pid)
{
	int i;
	for (i=0;i<MAX_REGISTER;i++)
		if (record[i].pid_register==pid) break;
	return i<MAX_REGISTER?record[i].hookman_map:0;
}
DWORD HookManager::GetProcessIDByPath(LPWSTR str)
{
	WCHAR path[MAX_PATH];
	for (int i=0;i<8&&record[i].process_handle;i++)
	{
		::GetProcessPath(record[i].process_handle,path);
		if (_wcsicmp(path,str)==0)
			return record[i].pid_register;
	}
	return 0;
}
DWORD HookManager::GetCurrentPID()
{
	DWORD pid=0;
	WCHAR str[0x20];
	if (GetWindowText(hwndProc,str,0x20))
		swscanf(str,L"%d",&pid);
	return pid;
}
DWORD HookManager::GetPIDByHandle(HANDLE h)
{
	int i;
	for (i=0;i<MAX_REGISTER;i++)
		if (text_pipes[i]==h) break;
	return i<MAX_REGISTER?record[i].pid_register:0;
}
DWORD HookManager::GetHookManByPID(DWORD pid)
{
	int i;
	for (i=0;i<MAX_REGISTER;i++)
		if (record[i].pid_register==pid) break;
	return i<MAX_REGISTER?record[i].hookman_register:0;
}
DWORD HookManager::GetModuleByPID(DWORD pid)
{
	int i;
	for (i=0;i<MAX_REGISTER;i++)
		if (record[i].pid_register==pid) break;
	return i<MAX_REGISTER?record[i].module_register:0;
}
DWORD HookManager::GetEngineByPID(DWORD pid)
{
	int i;
	for (i=0;i<MAX_REGISTER;i++)
		if (record[i].pid_register==pid) break;
	return i<MAX_REGISTER?record[i].engine_register:0;
}
HANDLE HookManager::GetTextHandleByPID(DWORD pid)
{
	int i;
	for (i=0;i<MAX_REGISTER;i++)
		if (record[i].pid_register==pid) break;
	return i<MAX_REGISTER?text_pipes[i]:0;
}
HANDLE HookManager::GetCmdHandleByPID(DWORD pid)
{
	int i;
	for (i=0;i<MAX_REGISTER;i++)
		if (record[i].pid_register==pid) break;
	return i<MAX_REGISTER?cmd_pipes[i]:0;
}
HANDLE HookManager::GetMutexByPID(DWORD pid)
{
	int i;
	for (i=0;i<MAX_REGISTER;i++)
		if (record[i].pid_register==pid) break;
	return i<MAX_REGISTER?record[i].hookman_mutex:0;
}
HANDLE HookManager::GetProcessByPID(DWORD pid)
{
	int i;
	for (i=0;i<MAX_REGISTER;i++)
		if (record[i].pid_register==pid) break;
	return i<MAX_REGISTER?record[i].process_handle:0;
}

//Class member of TextThread
static DWORD MIN_DETECT=0x20;
static DWORD MIN_REDETECT=0x80;
//#define MIN_DETECT		0x20
//#define MIN_REDETECT	0x80
#ifndef CURRENT_SELECT
#define CURRENT_SELECT				0x1000
#endif
#ifndef REPEAT_NUMBER_DECIDED
#define REPEAT_NUMBER_DECIDED	0x2000
#endif

TextThread::TextThread(DWORD id, DWORD hook, DWORD retn, DWORD spl, WORD num) : number(num)
{
	tp.pid=id;
	tp.hook=hook;
	tp.retn=retn;
	tp.spl=spl;
	head=new RepeatCountNode;
	head->count=head->repeat=0;
	link_number=-1;	
	repeat_detect_limit=0x80;
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
		ThreadParam *tpm; int i,j;
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
					DWORD flag=0;
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
								int to_index=pf->threads[lp->to_index-1].hm_index;
								if (to_index)
									man->AddLink(num,to_index);
								else
									pf->threads[i].hm_index=num;
								break;
							}
							if (lp->to_index==i+1)
							{
								int from_index=pf->threads[lp->from_index-1].hm_index;
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
	head=0;
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
void TextThread::AdjustPrevRepeat(DWORD len)
{
	/*DWORD i;
	BYTE tmp[MAX_PREV_REPEAT_LENGTH];
	for (i=0;i<len;i++)
		tmp[i]=storage[used-len+i];
	for (i=used-1;i>=last_sentence+len;i--)
		storage[i]=storage[i-len];
	for (i=0;i<len;i++)
		storage[last_sentence+i]=tmp[i];
	repeat_index+=len;
	if (repeat_index>=sentence_length) repeat_index-=sentence_length;*/
}
void TextThread::RemoveSingleRepeatAuto(BYTE* con,int &len)
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
				last=0;
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
				if (last==0) 
				{
					last=*text;
					return;
				}
				if (repeat_single_current==0)
				{
					status|=REPEAT_NUMBER_DECIDED;
					repeat_single=0;
					return;
				}
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
					DWORD repeat_sc=repeat_single*4;
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
	else
	{
		status|=REPEAT_NUMBER_DECIDED;
		repeat_single=0;
	}
}
void TextThread::RemoveSingleRepeatForce(BYTE* con,int &len)
{
	WORD* text=(WORD*)con;
	if (repeat_single_count<repeat_count&&last==*text) 
	{	
		len=0;		
		repeat_single_count++;
	}
	else 
	{
		last=*text;
		repeat_single_count=0;
	}
}
void TextThread::RemoveCyclicRepeat(BYTE* &con, int &len)
{
	DWORD currnet_time=GetTickCount();
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
			int half_length=repeat_index+len;
			if (memcmp(storage+last_sentence,storage+last_sentence+half_length,repeat_index)==0)
			{
				len=0;
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
		else if (len<=(int)sentence_length)
		{
			if (memcmp(storage+last_sentence,con,len)==0)
			{
				status|=REPEAT_DETECT;
				repeat_index=len;
				if (repeat_index==sentence_length)
				{
					repeat_index=0;
					len=0;
				}
			}
			else if (sentence_length>repeat_detect_limit)
			{
				if (len>2)
				{
					DWORD u=used;
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
					DWORD index,last_index,tmp_len;
					index=used-len;
					if (index<last_sentence) index=last_sentence;
					//Locate position of current input.
_again:
					*(WORD*)(storage+last_sentence)=*(WORD*)con;
					while (*(WORD*)(storage+index)!=*(WORD*)con) index--;
					*(WORD*)(storage+last_sentence)=tmp;
					if (index>last_sentence)
					{
						tmp_len=used-index;
						if (tmp_len<=2)
						{
							repeat_detect_limit+=0x40;
							last_time=currnet_time;
							return;
						}
						if  (index-last_sentence>=tmp_len&&
							memcmp(storage+index-tmp_len,storage+index,tmp_len)==0)
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
								DWORD last_char_len;
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
void TextThread::ResetRepeatStatus()
{
	last=0;
	repeat_single=0;
	repeat_single_current=0;
	repeat_single_count=0;
	repeat_detect_count=0;
	RepeatCountNode *t=head->next,*tt;
	while (t)
	{
		tt=t;
		t=tt->next;
		delete tt;
	}
	//head=new RepeatCountNode;
	head->count=head->repeat=0;
	status&=~REPEAT_NUMBER_DECIDED;
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
void TextThread::PrevRepeatLength(DWORD &len)
{
	BYTE *p1=storage+used;
	BYTE *p2=storage+prev_sentence;
	bool flag;
	len=1;
	DWORD j,k,l;
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
void TextThread::AddToStore(BYTE* con,int len, bool new_line,bool console)
{
	if (con==0) return;
	if (!console)
	{
		if (global_filter)
		{
			int i,j,k;
			union {WORD ch;BYTE cb[2];};
			if (status&USING_UNICODE)
			{
				for (i=0,j=0;i<len;i+=2)
				{
					ch=*(WORD*)(con+i);
					if (!uni_filter->Check(ch))
					{
						*(WORD*)(con+j)=ch;
						j+=2;
					}
				}
			}
			else
			{
				for (i=0,j=0;i<len;i+=k)
				{
					ch=*(WORD*)(con+i);
					k=LeadByteTable[con[i]];					
					if (k==2)
					{
						if (!mb_filter->Check(ch))
						{
							*(WORD*)(con+j)=ch;
							j+=2;
						}
					}
					else
					{
						if (!mb_filter->Check(cb[0]))
						{
							con[j]=cb[0];
							j++;
						}
					}
				}
			}
			len=j;
		}
		if (len<=0) return;
		if (!new_line) 
		{
			if (repeat_count) 
			{
				status|=REPEAT_NUMBER_DECIDED;
				RemoveSingleRepeatForce(con,len);
			}
			else RemoveSingleRepeatAuto(con,len);
		}
		if (len<=0) return;
		if(cyclic_remove) 
		{
			//if (status&REPEAT_NUMBER_DECIDED)
				RemoveCyclicRepeat(con,len);
		}
	}
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
			int l=len;
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
		sentence_length+=len;
	}
	
	if (MyVector::AddToStore(con,len))
	{
		ResetRepeatStatus();
		last_sentence=0;
		prev_sentence=0;
		sentence_length=len;
		repeat_index=0;
		status&=~REPEAT_DETECT|REPEAT_SUPPRESS;
		

	}
	if (status&CURRENT_SELECT) texts->AddText((BYTE*)con,len);
}
void TextThread::ResetEditText()
{
	int len;
	WCHAR *wc,null[2]={0};
	bool uni=(status&USING_UNICODE)>0;
	bool flag=false;
	EnterCriticalSection(&cs_store);
	if (uni) 
	{
		
		//wc=(LPWSTR)storage;
		if (used>=8)
			flag=(wcscmp((LPWSTR)(storage+used-8),L"\r\n\r\n")==0);
		if (flag) 
		{
			used-=8;
			memset(storage+used,0,8);
		}
		wc=new WCHAR[(used>>1)+1];
		memcpy(wc,storage,used);
		wc[used>>1]=0;
	}
	else
	{
		len=used;
		if (len) wc=new WCHAR[len+1];
		else wc=null;
		if (used>=4)
			flag=(strcmp((char*)(storage+used-4),"\r\n\r\n")==0);
		if (flag) 
		{
			used-=4;
			memset(storage+used,0,4);
		}
		wc[MB_WC((char*)storage,wc)]=0;	
	}
	LeaveCriticalSection(&cs_store);
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
			MyVector::AddToStore((BYTE*)L"\r\n\r\n",8);
			texts->AddText((BYTE*)L"\r\n\r\n",8,true);
		}
		else
		{
			MyVector::AddToStore((BYTE*)"\r\n\r\n",4);
			texts->AddText((BYTE*)"\r\n\r\n",4,true);
		}
	}
	if (wc!=null) delete wc;
}
void TextThread::ComboSelectCurrent()
{
	int index;
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
	int i,j,l;
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
void TextThread::ExportTextToFile(LPWSTR filename)
{
	HANDLE hFile=IthCreateFile(filename,FILE_WRITE_DATA,0,FILE_OPEN_IF);
	if (hFile==INVALID_HANDLE_VALUE) return;
	EnterCriticalSection(&cs_store);
	IO_STATUS_BLOCK ios;
	LPVOID buffer=storage;
	DWORD len=used;
	BYTE bom[4]={0xFF,0xFE,0,0};
	LARGE_INTEGER offset={2,0};
	if ((status&USING_UNICODE)==0)
	{
		len=MB_WC_count((char*)storage,used);
		buffer=new WCHAR[len+1];
		MB_WC((char*)storage,(wchar_t*)buffer);
		len<<=1;
	}
	NtWriteFile(hFile,0,0,0,&ios,bom,2,0,0);
	NtWriteFile(hFile,0,0,0,&ios,buffer,len,&offset,0);
	NtFlushBuffersFile(hFile,&ios);
	if (buffer!=storage) delete buffer;
	NtClose(hFile);
	LeaveCriticalSection(&cs_store);
}
void TextThread::SetComment(LPWSTR str)
{
	if (comment) delete comment;
	comment=new WCHAR[wcslen(str)+1];
	wcscpy(comment,str);
}
void TextThread::SetNewLineFlag()
{
	status|=BUFF_NEWLINE;
}
void TextThread::SetNewLineTimer()
{
	if (number==0)
		timer=SetTimer(hMainWnd,(UINT_PTR)this,split_time,NewLineConsole);
	else
		timer=SetTimer(hMainWnd,(UINT_PTR)this,split_time,NewLineBuff);
}
bool TextThread::AddToCombo()
{
	int i;
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
	int i,j;
	WCHAR entry[0x200];
	GetEntryString(entry);

	i=SendMessage(hwndCombo,CB_FINDSTRING,0,(LPARAM)entry);
	j=SendMessage(hwndCombo,CB_GETCURSEL,0,0);
	if (i==CB_ERR) return false;
	if (SendMessage(hwndCombo,CB_DELETESTRING,i,0)==CB_ERR) 
		man->AddConsoleOutput(ErrorDeleteCombo);
	return (i==j);
}
bool TextThread::CheckCycle(TextThread* start)
{
	if (link==start||this==start) return true;
	if (link==0) return false;
	return link->CheckCycle(start);
}

inline void TextThread::SetRepeatFlag() {status|=CYCLIC_REPEAT;}
inline void TextThread::ClearNewLineFlag() {status&=~BUFF_NEWLINE;}
inline void TextThread::ClearRepeatFlag() {status&=~CYCLIC_REPEAT;}

MK_FUNDA_TYPE(DWORD)
MK_FUNDA_TYPE(BYTE)
MK_FUNDA_TYPE(LPVOID)
MK_FUNDA_TYPE(ThreadParameter)


DWORD Hash(LPWSTR module, int length)
{
	bool flag=(length==-1);
	DWORD hash=0;
	for (;*module&&(flag||length--);module++)
	{
		hash=((hash>>7)|(hash<<25))+(*module);
	}
	return hash;
}
static char clipboard_buffer[0x400];
void CopyToClipboard(void* str,bool unicode, int len)
{
	if (clipboard_flag)
	if (str)
	{
		int size=(len*2|0xF)+1;
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
void ConsoleOutput(const LPCWSTR text)
{
	if (running) man->AddConsoleOutput(text);
}
DWORD	GetCurrentPID()
{
	return man->GetCurrentPID();
}
DWORD	GetPIDByHandle(HANDLE h)
{
	return man->GetPIDByHandle(h);
}
DWORD	GetHookManByPID(DWORD pid)
{
	return man->GetHookManByPID(pid);
}
DWORD	GetModuleByPID(DWORD pid)
{
	return man->GetModuleByPID(pid);
}
DWORD	GetEngineByPID(DWORD pid)
{
	return man->GetEngineByPID(pid);
}
HANDLE	GetTextHandleByPID(DWORD pid)
{
	return man->GetTextHandleByPID(pid);
}
HANDLE	GetCmdHandleByPID(DWORD pid)
{
	return man->GetCmdHandleByPID(pid);
}
HANDLE	GetMutexByPID(DWORD pid)
{
	return man->GetMutexByPID(pid);
}
HANDLE	GetProcessByPID(DWORD pid)
{
	return man->GetProcessByPID(pid);
}
void GetCode(const HookParam& hp, LPWSTR buffer, DWORD pid)
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
	if (hp.off>>31) ptr+=swprintf(ptr,L"-%X",-(hp.off+4));
	else ptr+=swprintf(ptr,L"%X",hp.off);
	if (hp.type&DATA_INDIRECT)
	{
		if (hp.ind>>31) ptr+=swprintf(ptr,L"*-%X",-hp.ind);
		else ptr+=swprintf(ptr,L"*%X",hp.ind);
	}
	if (hp.type&USING_SPLIT)
	{
		if (hp.split>>31) ptr+=swprintf(ptr,L":-%X",-(4+hp.split));
		else ptr+=swprintf(ptr,L":%X",hp.split);
	}
	if (hp.type&SPLIT_INDIRECT)
	{
		if (hp.split_ind>>31) ptr+=swprintf(ptr,L"*-%X",-hp.split_ind);
		else ptr+=swprintf(ptr,L"*%X",hp.split_ind);
	}
	if (hp.module)
	{
		if (pid)
		{
			WCHAR path[MAX_PATH];
			MEMORY_BASIC_INFORMATION info;
			HANDLE hProc=man->GetProcessByPID(pid);
			if (NT_SUCCESS(NtQueryVirtualMemory(hProc,(PVOID)hp.addr,MemorySectionName,path,MAX_PATH*2,0)))
			if (NT_SUCCESS(NtQueryVirtualMemory(hProc,(PVOID)hp.addr,MemoryBasicInformation,&info,sizeof(info),0)))
			ptr+=swprintf(ptr,L"@%X:%s",hp.addr-(DWORD)info.AllocationBase,wcsrchr(path,L'\\')+1);
		}
		else
		{
			ptr+=swprintf(ptr,L"@%X!%X",hp.addr,hp.module);
			if (hp.function) ptr+=swprintf(ptr,L"!%X",hp.function);
		}
	}
	else
		ptr+=swprintf(ptr,L"@%X",hp.addr);

}
void AddLink(WORD from, WORD to) {man->AddLink(from,to);}
