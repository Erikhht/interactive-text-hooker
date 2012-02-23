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
#include "ntdll64.h"
extern "C" {
int swprintf(wchar_t * _String, const wchar_t * _Format, ...);
int sprintf(char * _String, const char * _Format, ...);
int swscanf(const wchar_t * _Src,  const wchar_t * _Format, ...);
int sscanf(const char * _String, const char * _Format, ...);
}
#define ENGINE64_CMVS 1

#define USING_STRING			0x1
#define USING_UNICODE		0x2
#define BIG_ENDIAN			0x4
#define DATA_INDIRECT		0x8
#define USING_SPLIT			0x10
#define SPLIT_INDIRECT		0x20
#define MODULE_OFFSET		0x40
#define FUNCTION_OFFSET	0x80
#define PRINT_DWORD		0x100
#define STRING_LAST_CHAR 0x200
#define NO_CONTEXT			0x400
#define EXTERN_HOOK		0x800
#define CURRENT_SELECT				0x1000
#define REPEAT_NUMBER_DECIDED	0x2000
#define BUFF_NEWLINE 0x4000
#define CYCLIC_REPEAT 0x8000
#define HOOK_ENGINE 0X4000
#define HOOK_ADDITIONAL 0x8000

#define MAX_HOOK 32

struct HookParam //0x50
{
	UINT_PTR addr;
	UINT_PTR off,ind,split,split_ind;
	UINT_PTR module,function;
	UINT_PTR extern_fun,type;
	DWORD length_offset;
	WORD hook_len,recover_len;
};
struct SendParam
{
	UINT_PTR type;
	HookParam hp;
};
class Hook //0x100
{
public:
	inline UINT_PTR Address() const {return hp.addr;}
	inline UINT_PTR Type() const {return hp.type;}
	inline WORD Length() const {return hp.hook_len;}
	inline LPWSTR Name() const {return hook_name;}
	inline UINT_PTR NameLength() const {return name_length;}
protected:
	HookParam hp;
	LPWSTR hook_name;
	UINT_PTR name_length;
	BYTE recover[0x80];
	BYTE original[0x20];
};

extern HANDLE hHeap;
//HEAP_ZERO_MEMORY flag is critical. All new object are assumed with zero initialized.
inline void * __cdecl operator new(size_t lSize)
{
#ifdef _ITH_DEBUG_MEMORY
	void *p=RtlAllocateHeap(hHeap, HEAP_ZERO_MEMORY, lSize);
	WCHAR str[0x40];
	swprintf(str,L"A:%x:%x\n",p,lSize);
	OutputDebugString(str);
	return p;
#else
	return RtlAllocateHeap(hHeap, HEAP_ZERO_MEMORY, lSize);
#endif
}
inline void __cdecl operator delete(void *pBlock)
{
#ifdef _ITH_DEBUG_MEMORY
	WCHAR str[0x20];
	swprintf(str,L"D:%x\n",pBlock);
	OutputDebugString(str);
#endif
	RtlFreeHeap(hHeap, 0, pBlock);
}
inline void __cdecl operator delete[](void* pBlock)
{
#ifdef _ITH_DEBUG_MEMORY
	WCHAR str[0x20];
	swprintf(str,L"D:%x\n",pBlock);
	OutputDebugString(str);
#endif
	RtlFreeHeap(hHeap, 0, pBlock);
}