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

#pragma once
#include <windows.h>
#include "text.h"
#include "..\AVL.h"
class BitMap
{
public:
	BitMap();
	~BitMap();
	bool Check(DWORD number);
	void Init(BYTE* m, DWORD size);
	void Set(DWORD number);
	void Clear(DWORD number);
private:
	BYTE* map;
	DWORD size;
};

#define MAX_REGISTER 0xF
#define MAX_PREV_REPEAT_LENGTH 0x20
struct ProcessRecord {
	DWORD pid_register;
	DWORD hookman_register;
	DWORD module_register;
	DWORD engine_register;
	HANDLE process_handle;
	HANDLE hookman_mutex;
	HANDLE hookman_section;
	LPVOID hookman_map;
};

class ThreadTable : public MyVector<TextThread*,0x40>
{
public:
	void SetThread(DWORD number, TextThread* ptr);
	TextThread* FindThread(DWORD number);
};
class TCmp
{
public:
	int operator()(const ThreadParameter* t1,const ThreadParameter* t2);
};
class TCpy
{
public:
	void operator()(ThreadParameter* t1, ThreadParameter* t2);
};
class TLen
{
public:
	int operator()(ThreadParameter* t);
};

class HookManager : public AVLTree<ThreadParameter,DWORD,TCmp,TCpy,TLen>
{
public:
	HookManager();
	~HookManager();
	TextThread* FindSingle(DWORD pid, DWORD hook, DWORD retn, DWORD split);
	TextThread* FindSingle(DWORD number);
	TextThread* GetCurrentThread();
	void SetCurrent(TextThread* it);
	void SelectCurrent(LPWSTR str);
	void AddText(DWORD pid, BYTE* text, DWORD hook, DWORD retn, DWORD split, int len);
	void AddConsoleOutput(LPCWSTR text);
	void AddLink(WORD from, WORD to);
	void ClearText(DWORD pid, DWORD hook, DWORD retn, DWORD split);
	void ClearCurrent();
	void LockHookman();
	void UnlockHookman();
	void LockProcessHookman(DWORD pid);
	void UnlockProcessHookman(DWORD pid);
	void RemoveProcessContext(DWORD pid);
	void RemoveSingleHook(DWORD pid, DWORD addr);
	void RemoveSingleThread(DWORD number);
	void RegisterThread(TextThread*, DWORD);
	void RegisterPipe(HANDLE text, HANDLE cmd);
	void RegisterProcess(DWORD pid, DWORD hookman, DWORD module, DWORD engine);
	void UnRegisterProcess(DWORD pid);
	void SetName(DWORD);
	void SetProcessEngineType(DWORD pid, DWORD type);
	bool GetProcessPath(DWORD pid, LPWSTR path);
	bool GetProcessName(DWORD pid, LPWSTR str);
	LPVOID RemoteHook(DWORD pid);
	ProcessRecord* Records() {return record;}
	ThreadTable* Table() {return table;}
	DWORD GetCurrentPID();
	DWORD GetPIDByHandle(HANDLE h);
	DWORD GetHookManByPID(DWORD pid);
	DWORD GetModuleByPID(DWORD pid);
	DWORD GetEngineByPID(DWORD pid);
	DWORD GetProcessIDByPath(LPWSTR str);
	HANDLE GetTextHandleByPID(DWORD pid);
	HANDLE GetCmdHandleByPID(DWORD pid);
	HANDLE GetMutexByPID(DWORD pid);
	HANDLE GetProcessByPID(DWORD pid);
private:
	//void AddConsoleOutputNewLine();
	//IthCriticalSection hmcs;
	CRITICAL_SECTION hmcs; //0x18
	TextThread *current;
	ThreadTable *table;

	ProcessRecord record[MAX_REGISTER+1];
	HANDLE text_pipes[MAX_REGISTER+1];
	HANDLE cmd_pipes[MAX_REGISTER+1];

	WORD register_count, new_thread_number; 
};

