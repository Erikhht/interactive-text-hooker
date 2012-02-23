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
#define _INC_SWPRINTF_INL_
#include "..\common.h"
#include "..\ntdll64.h"
#include "..\sys.h"
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
class ProfileManager;
#define TextHook Hook
GLOBAL bool running;

GLOBAL HINSTANCE hIns;
GLOBAL BitMap *pid_map;
GLOBAL TextBuffer *texts;
GLOBAL HookManager *man;
GLOBAL ProfileManager *pfman;
GLOBAL CommandQueue *cmdq;
GLOBAL HWND hwndCombo,hwndProc,hwndEdit,hMainWnd;
GLOBAL WCHAR pipe[];
GLOBAL WCHAR command[];
GLOBAL HANDLE hPipeExist;
GLOBAL UINT_PTR split_time, process_time, inject_delay, insert_delay;
GLOBAL DWORD auto_inject, auto_insert;
GLOBAL DWORD cyclic_remove,clipboard_flag;
GLOBAL CRITICAL_SECTION detach_cs;
UINT_PTR WINAPI RecvThread(LPVOID lpThreadParameter);
UINT_PTR WINAPI CmdThread(LPVOID lpThreadParameter);

void CopyToClipboard(void* str,bool unicode, size_t len);
void ConsoleOutput(LPWSTR text);
UINT_PTR	Inject(HANDLE hProc);
UINT_PTR	InjectByPID(UINT_PTR pid);
UINT_PTR	PIDByName(LPWSTR target);
UINT_PTR	Hash(LPWSTR module, UINT_PTR length=-1);
BOOL ActiveDetachProcess(UINT_PTR pid);
BOOL CheckFile(LPWSTR file);
bool GetProcessPath(HANDLE hProc, LPWSTR path);
bool GetProcessPath(UINT_PTR pid, LPWSTR path);
#include "hookman.h"
