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
#include "..\common.h"
#define ITHMAIN
#include "..\sys.h"

#pragma once

#define HEADER_SIZE (sizeof(UINT_PTR)*3)
extern int current_hook;
extern WCHAR dll_mutex[];
extern bool trigger;
//extern DWORD current_process_id;
template <class T,class D, class fComp, class fCopy, class fLength> class AVLTree;
struct FunctionInfo
{
	UINT_PTR addr;
	UINT_PTR module;
	UINT_PTR size;
	LPWSTR name;
};
class SCMP;
class SCPY;
class SLEN;
extern AVLTree<char, FunctionInfo, SCMP, SCPY, SLEN> *tree;
void InitFilterTable();

int disasm(BYTE* opcode0);
class TextHook : public Hook
{
public:
	int InsertHook();
	int InsertHookCode();
	int InitHook(const HookParam&, LPWSTR name=0, WORD set_flag=0);
	int InitHook(LPVOID addr, UINT_PTR data, UINT_PTR data_ind, 
		UINT_PTR split_off, UINT_PTR split_ind, UINT_PTR type, UINT_PTR len_off=0);
	void Send(UINT_PTR stack_ptr, UINT_PTR data, UINT_PTR split);
	int RecoverHook();
	int RemoveHook();
	int ClearHook();
	int ModifyHook(const HookParam&);
	int SetHookName(LPWSTR name);
	int GetLength(UINT_PTR base, UINT_PTR in);
};
#define MAX_SECTION 8
struct SectionRelayRecord
{
	UINT_PTR section_register;
	UINT_PTR section_relay_buffer;
	UINT_PTR section_referenced;
	UINT_PTR reserved;
};
class SectionRelayBuffer
{
public:
	void Release();
	UINT_PTR RegisterSection(UINT_PTR section);
	BOOL UnregisterSection(UINT_PTR section);
private:
	SectionRelayRecord record[MAX_SECTION];
	UINT_PTR section_count;
};
extern SectionRelayBuffer *relay;
extern TextHook *hookman,*current_available;
void InitDefaultHook();
struct FilterRange
{
	UINT_PTR lower,upper;
};
extern FilterRange filter[8];
int FillRange(LPWSTR name,UINT_PTR* lower, UINT_PTR* upper);
extern bool running,live;
extern HANDLE hPipe,hmMutex;
UINT_PTR WINAPI WaitForPipe(LPVOID lpThreadParameter);
UINT_PTR WINAPI CommandPipe(LPVOID lpThreadParameter);
void RequestRefreshProfile();
typedef UINT_PTR (*IdentifyEngineFun)();
typedef void (*InsertDynamicHookFun)(LPVOID addr, UINT_PTR frame, UINT_PTR stack);
extern IdentifyEngineFun IdentifyEngine; 
extern InsertDynamicHookFun InsertDynamicHook;

#include "..\ITHDLL.h"