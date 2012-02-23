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
#include "common.h"
#ifdef ITHMAIN
#define ITHAPI __declspec(dllexport) __stdcall
#else
#define ITHAPI __declspec(dllimport) __stdcall
#endif
extern "C" {
void ITHAPI OutputConsole(LPWSTR str);
void ITHAPI OutputDWORD(DWORD d);
void ITHAPI OutputRegister(DWORD *base);
void ITHAPI NewHook(const HookParam& hp, LPWSTR name=0, DWORD flag=HOOK_ENGINE);
void ITHAPI RemoveHook(DWORD addr);
void ITHAPI RegisterEngineType(DWORD type);
void ITHAPI RegisterHookName(LPWSTR str, DWORD addr);
void ITHAPI SwitchTrigger(bool on=true);
DWORD ITHAPI GetFunctionAddr(char* name, DWORD* addr, DWORD *base, DWORD* size, LPWSTR* base_name);
}