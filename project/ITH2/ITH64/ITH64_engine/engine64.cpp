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
#include "..\ithdll.h"
#include "..\sys.h"
#include "..\ntdll64.h"
WCHAR process_name[MAX_PATH];
HANDLE hEngineOn;
static WCHAR engine[0x20];
static UINT_PTR module_base, module_limit;
static LPVOID trigger_addr;
static char text_buffer[0x1000];
static char text_buffer_prev[0x1000];
extern BYTE LeadByteTable[0x100];
typedef bool (*tfun)(LPVOID addr, DWORD frame, DWORD stack);
static tfun trigger_fun;
void inline GetName()
{
	PLDR_DATA_TABLE_ENTRY it=(PLDR_DATA_TABLE_ENTRY)peb->Ldr->InLoadOrderModuleList.Flink;
	wcscpy(process_name,it->BaseDllName.Buffer);
}
BOOL WINAPI DllMain(HANDLE hModule, DWORD reason, LPVOID lpReserved)
{
	switch(reason)
	{
	case DLL_PROCESS_ATTACH:
		{
		LdrDisableThreadCalloutsForDll(hModule);	
		IthInitSystemService();
		GetName();
		swprintf(engine,L"ITH_ENGINE_%d",current_process_id);
		hEngineOn=IthCreateEvent(engine);
		NtSetEvent(hEngineOn,0);
		}
		break;
	case DLL_PROCESS_DETACH:	
		NtClearEvent(hEngineOn);
		NtClose(hEngineOn);
		IthCloseSystemService();
		break;
	}
	return TRUE;
}
DWORD GetCodeRange(DWORD hModule,DWORD *low, DWORD *high)
{
	IMAGE_DOS_HEADER *DosHdr;
	IMAGE_NT_HEADERS *NtHdr;
	DWORD dwReadAddr;
	IMAGE_SECTION_HEADER *shdr;
	DosHdr=(IMAGE_DOS_HEADER*)hModule;
	if (IMAGE_DOS_SIGNATURE==DosHdr->e_magic)
	{
		dwReadAddr=hModule+DosHdr->e_lfanew;
		NtHdr=(IMAGE_NT_HEADERS*)dwReadAddr;
		if (IMAGE_NT_SIGNATURE==NtHdr->Signature)
		{
			shdr=(PIMAGE_SECTION_HEADER)((DWORD)(&NtHdr->OptionalHeader)+NtHdr->FileHeader.SizeOfOptionalHeader);
			while ((shdr->Characteristics&IMAGE_SCN_CNT_CODE)==0) shdr++;
			*low=hModule+shdr->VirtualAddress;
				*high=*low+(shdr->Misc.VirtualSize&0xFFFFF000)+0x1000;
		}
	}
	return 0;
}
void InsertCMVSHook()
{
	//FillRange(0,&base,&limit);
	UINT_PTR i,j;
	DWORD k;
	for (i=module_base+0x1000;i<module_limit;i++)
	{
		if (*(WORD*)i==0x15FF)
		{
			k=*(DWORD*)(i+2);
			j=i+k+6;
			if (j>module_base&&j<module_limit)
			{
				if (*(LPVOID*)j==GetGlyphOutlineA)
				{
					for (j=i-0x200;i>j;i--)
					{
						if(*(DWORD*)i==0xCCCCCCCC) 
						{
							HookParam hp={};
							hp.addr=i+4;
							hp.off=-0x40;
							hp.split=-0x48;
							hp.type=BIG_ENDIAN|USING_SPLIT;

							hp.length_offset=1;
							NewHook(hp,L"CMVS");
							RegisterEngineType(ENGINE64_CMVS);
							return;
						}
					}
					return;
				}
			}
		}
	}
}
extern "C" int __declspec(dllexport) InsertDynamicHook(LPVOID addr, DWORD frame, DWORD stack)
{
	return !trigger_fun(addr,frame,stack);
}
extern "C" DWORD __declspec(dllexport) DetermineEngineType()
{
	if (IthFindFile(L"data\\pack\\*.cpz"))
	{
		InsertCMVSHook();
		return 0;
	}
	OutputConsole(L"Unknown engine.");
	return 0;
}
extern "C" DWORD __declspec(dllexport) IdentifyEngine()
{
	FillRange(process_name,&module_base,&module_limit);
	__try{
		DetermineEngineType();
		OutputConsole(L"Initialized successfully.");
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		OutputConsole(L"Fail to identify engine type.");		
	}
	return 0;
}
