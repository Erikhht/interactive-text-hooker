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
extern "C" {
extern WORD* NlsAnsiCodePage;
extern BYTE LeadByteTable[];
extern UINT_PTR share_mask[];
extern LPVOID code_page;
extern PEB* peb;
extern TEB* teb;
int disasm(BYTE* opcode0);
int FillRange(LPWSTR name,PUINT_PTR lower, PUINT_PTR upper);
int MB_WC(char* mb, wchar_t* wc);
int MB_WC_count(char* mb, UINT_PTR len);
int WC_MB(wchar_t *wc, char* mb);
//UINT_PTR SearchPattern(UINT_PTR base, UINT_PTR base_length, LPVOID search, UINT_PTR search_length); //KMP
LPWSTR GetModulePath();
void IthInitSystemService();
void IthCloseSystemService();
UINT_PTR GetMemory(LPVOID workset, UINT_PTR* memory);
UINT_PTR IthGetMemoryRange(LPVOID mem, UINT_PTR* base, UINT_PTR* size);
BOOL IthCheckFile(LPWSTR file);
BOOL IthFindFile(LPWSTR file);
BOOL IthCheckFileFullPath(LPWSTR file);
HANDLE IthCreateFile(LPWSTR name, DWORD option, UINT_PTR share, UINT_PTR disposition);
HANDLE IthCreateFileFullPath(LPWSTR full_path, DWORD option, UINT_PTR share, UINT_PTR disposition);
HANDLE IthPromptCreateFile(DWORD option, UINT_PTR share, UINT_PTR disposition);
HANDLE IthCreateSection(LPWSTR name, UINT_PTR size, UINT_PTR right);
HANDLE IthCreateEvent(LPWSTR name, UINT_PTR auto_reset=0, UINT_PTR init_state=0);
HANDLE IthOpenEvent(LPWSTR name);
void IthSetEvent(HANDLE hEvent);
void IthResetEvent(HANDLE hEvent);
HANDLE IthCreateMutex(LPWSTR name, BOOL InitialOwner, UINT_PTR* exist=0);
HANDLE IthOpenMutex(LPWSTR name);
BOOL IthReleaseMutex(HANDLE hMutex);
UINT_PTR IthWaitForSingleObject(HANDLE hObject, UINT_PTR dwTime);
HANDLE IthCreateThread(LPVOID start_addr, UINT_PTR param, HANDLE hProc=(HANDLE)-1);
UINT_PTR GetExportAddress(UINT_PTR hModule,UINT_PTR hash);
void IthSleep(UINT_PTR time);
void FreeThreadStart(HANDLE hProc);
UINT_PTR GetHashCStr(LPSTR str);
UINT_PTR GetHashWStr(LPWSTR str);
}
extern HANDLE hHeap;
extern UINT_PTR current_process_id;

extern BYTE launch_time[];

inline UINT_PTR GetHash(LPSTR str)
{
	/*UINT_PTR hash=0;
	for (;*str;str++)
	{
		hash=((hash>>7)|(hash<<25))+(*str);
	}
	return hash;*/
	return GetHashCStr(str);
}

inline UINT_PTR GetHash(LPWSTR str)
{
	return GetHashWStr(str);
	/*UINT_PTR hash=0;
	for (;*str;str++)
	{
		hash=((hash>>7)|(hash<<25))+(*str);
	}
	return hash;*/
}
