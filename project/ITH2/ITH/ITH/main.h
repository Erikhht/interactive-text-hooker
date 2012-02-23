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
#include "..\common.h"
#include "..\ntdll.h"
#include "..\sys.h"
#include "language.h"
#pragma comment(linker,"/manifestdependency:\"type='win32' "\
	"name='Microsoft.Windows.Common-Controls' version='6.0.0.0' "\
	"processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

#define GLOBAL extern
#define SHIFT_JIS 0x3A4
class TextBuffer;
class HookManager;
class CommandQueue;
class TextHook;
class BitMap;
class CustomFilterMultiByte;
class CustomFilterUnicode;
class ProfileManager;
#define TextHook Hook
GLOBAL bool running;

GLOBAL HINSTANCE hIns;
GLOBAL BitMap *pid_map;
GLOBAL CustomFilterMultiByte *mb_filter;
GLOBAL CustomFilterUnicode *uni_filter;
GLOBAL TextBuffer *texts;
GLOBAL HookManager *man;
GLOBAL ProfileManager *pfman;
GLOBAL CommandQueue *cmdq;
GLOBAL HWND hwndCombo,hwndProc,hwndEdit,hMainWnd;
GLOBAL WCHAR pipe[];
GLOBAL WCHAR command[];
GLOBAL HANDLE hPipeExist;
GLOBAL DWORD split_time, process_time, inject_delay, insert_delay;
GLOBAL DWORD auto_inject, auto_insert;
GLOBAL DWORD cyclic_remove,clipboard_flag,global_filter;
GLOBAL CRITICAL_SECTION detach_cs;
DWORD WINAPI RecvThread(LPVOID lpThreadParameter);
DWORD WINAPI CmdThread(LPVOID lpThreadParameter);

void CopyToClipboard(void* str,bool unicode, int len);
void ConsoleOutput(LPCWSTR text);
DWORD	GetCurrentPID();
DWORD	GetPIDByHandle(HANDLE h);
DWORD	GetHookManByPID(DWORD pid);
DWORD	GetModuleByPID(DWORD pid);
DWORD	GetEngineByPID(DWORD pid);
DWORD	GetProcessIDByPath(LPWSTR str);
HANDLE	GetTextHandleByPID(DWORD pid);
HANDLE	GetCmdHandleByPID(DWORD pid);
HANDLE	GetMutexByPID(DWORD pid);
HANDLE	GetProcessByPID(DWORD pid);
DWORD	Inject(HANDLE hProc);
DWORD	InjectByPID(DWORD pid);
DWORD	PIDByName(LPWSTR target);
DWORD	Hash(LPWSTR module, int length=-1);
BOOL ActiveDetachProcess(DWORD pid);
BOOL CheckFile(LPWSTR file);
bool GetProcessPath(HANDLE hProc, LPWSTR path);
bool GetProcessPath(DWORD pid, LPWSTR path);
