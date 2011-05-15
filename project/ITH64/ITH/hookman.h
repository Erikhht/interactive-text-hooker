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
	bool Check(UINT_PTR number);
	void Set(UINT_PTR number);
	void Clear(UINT_PTR number);
private:
	BYTE* map;
	UINT_PTR size;
};

#define MAX_REGISTER 0xF
#define MAX_PREV_REPEAT_LENGTH 0x20
struct ProcessRecord {
	UINT_PTR pid_register;
	UINT_PTR hookman_register;
	UINT_PTR module_register;
	UINT_PTR engine_register;
	HANDLE process_handle;
	HANDLE hookman_mutex;
	HANDLE hookman_section;
	LPVOID hookman_map;
};

class ThreadTable : public MyVector<TextThread*,0x40>
{
public:
	void SetThread(UINT_PTR number, TextThread* ptr);
	TextThread* FindThread(UINT_PTR number);
};
class TCmp
{
public:
	size_t operator()(const ThreadParameter* t1,const ThreadParameter* t2);
};
class TCpy
{
public:
	void operator()(ThreadParameter* t1, ThreadParameter* t2);
};
class TLen
{
public:
	size_t operator()(ThreadParameter* t);
};

class HookManager : public AVLTree<ThreadParameter,UINT_PTR,TCmp,TCpy,TLen>
{
public:
	HookManager();
	~HookManager();
	TextThread* FindSingle(UINT_PTR pid, UINT_PTR hook, UINT_PTR retn, UINT_PTR split);
	TextThread* FindSingle(UINT_PTR number);
	TextThread* GetCurrentThread();
	void SetCurrent(TextThread* it);
	void SelectCurrent(LPWSTR str);
	void AddText(UINT_PTR pid, BYTE* text, UINT_PTR hook, UINT_PTR retn, UINT_PTR split, size_t len);
	void AddConsoleOutput(LPWSTR text);
	void AddLink(UINT_PTR from, UINT_PTR to);
	void ClearText(UINT_PTR pid, UINT_PTR hook, UINT_PTR retn, UINT_PTR split);
	void ClearCurrent();
	void LockHookman();
	void UnlockHookman();
	void LockProcessHookman(UINT_PTR pid);
	void UnlockProcessHookman(UINT_PTR pid);
	void RemoveProcessContext(UINT_PTR pid);
	void RemoveSingleHook(UINT_PTR pid, UINT_PTR addr);
	void RemoveSingleThread(UINT_PTR number);
	void RegisterThread(TextThread*, UINT_PTR);
	void RegisterPipe(HANDLE text, HANDLE cmd);
	void RegisterProcess(UINT_PTR pid, UINT_PTR hookman, UINT_PTR module, UINT_PTR engine);
	void UnRegisterProcess(UINT_PTR pid);
	void SetName(UINT_PTR);
	void SetProcessEngineType(UINT_PTR pid, UINT_PTR type);
	bool GetProcessPath(UINT_PTR pid, LPWSTR path);
	bool GetProcessName(UINT_PTR pid, LPWSTR str);
	LPVOID RemoteHook(UINT_PTR pid);
	ProcessRecord* Records() {return record;}
	ThreadTable* Table() {return table;}
	UINT_PTR GetCurrentPID();
	UINT_PTR GetPIDByHandle(HANDLE h);
	UINT_PTR GetHookManByPID(UINT_PTR pid);
	UINT_PTR GetModuleByPID(UINT_PTR pid);
	UINT_PTR GetEngineByPID(UINT_PTR pid);
	UINT_PTR GetProcessIDByPath(LPWSTR str);
	HANDLE GetTextHandleByPID(UINT_PTR pid);
	HANDLE GetCmdHandleByPID(UINT_PTR pid);
	HANDLE GetMutexByPID(UINT_PTR pid);
	HANDLE GetProcessByPID(UINT_PTR pid);
private:
	void AddConsoleOutputNewLine();
	//IthCriticalSection hmcs;
	CRITICAL_SECTION hmcs; //0x18
	TextThread *current;
	ThreadTable *table;

	ProcessRecord record[MAX_REGISTER+1];
	HANDLE text_pipes[MAX_REGISTER+1];
	HANDLE cmd_pipes[MAX_REGISTER+1];

	UINT_PTR register_count, new_thread_number; 
};

