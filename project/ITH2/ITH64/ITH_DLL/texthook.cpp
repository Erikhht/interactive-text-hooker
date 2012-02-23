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

#include "utility.h"
TextHook *hookman,*current_available;

FilterRange filter[8];
static const int size_hook=sizeof(TextHook);
UINT_PTR flag, enter_count;
//provide const time hook entry.
#define HOOK_DEBUG_HEAD 0
static int userhook_count;
static const BYTE common_prologue[]={
	0x48, 0x89, 0x04, 0xE4, //mov [rsp], rax
	//Save flag (prgram status).
	0x9C, //pushfq
	//Save volatile registers.
	0x51, 0x52, //push rcx,rdx
	0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, //push r8~r11
};

static const BYTE common_epilogue[]={
	0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, //pop r11~r8
	0x5A, 0x59, //pop rdx,rcx
	//Restore flag (program status).
	0x9D, //popfq
	0x58 //pop rax
};

static const BYTE common_route[]={
	0x48, 0x8B, 0xD4, //mov rdx,rsp; param 1, stack
	0x48, 0x83, 0xC2, 0x40, //add rdx,0x40
	0x48, 0x83, 0xEC, 0x20, //sub rsp,0x20, allocate stack
	0x48, 0xB8, 0,0,0,0,0,0,0,0, //mov rax, @hook, 0x2D
	0x48, 0xB9, 0,0,0,0,0,0,0,0, //mov rcx, this, 0x37
	0xFF, 0xD0, //call rax
	0x48, 0x83, 0xC4, 0x20, //add rsp,0x20, restore stack
};

#define PROLOGUE_LENGTH (sizeof(common_prologue))
#define EPILOGUE_LENGTH (sizeof(common_epilogue))
#define ROUTE_LENGTH (sizeof(common_route))

//copy original instruction
//jmp back


void SectionRelayBuffer::Release()
{
	UINT_PTR i;
	UINT_PTR size;
	LPVOID addr;
	for (i=0;i<section_count;i++)
	{
		size=0;
		addr=(LPVOID)record[i].section_relay_buffer;
		NtFreeVirtualMemory(NtCurrentProcess(),&addr,&size,MEM_RELEASE);
	}
}
UINT_PTR SectionRelayBuffer::RegisterSection(UINT_PTR section)
{
	UINT_PTR i;
	UINT_PTR base=(UINT_PTR)(section)>>31;
	for (i=0;i<section_count;i++)
		if (record[i].section_register==base) break;
	if (i<section_count)
	{
		record[i].section_referenced++;
		return record[i].section_relay_buffer;
	}
	UINT_PTR addr=(base<<31)+0x40000000;
	UINT_PTR size=0x1000,len;
	LPVOID allocate;
	MEMORY_BASIC_INFORMATION info;
	allocate=(LPVOID)addr;
	for (;;)
	{
		allocate=(LPVOID)addr;
			NtQueryVirtualMemory(NtCurrentProcess(),allocate,
			MemoryBasicInformation,&info,sizeof(info),&len);
		if ((info.State&MEM_FREE))
			if ((UINT_PTR)info.BaseAddress+info.RegionSize-addr>=0x1000)
				break;
		addr=(UINT_PTR)info.BaseAddress-0x1000;
	}
	NtAllocateVirtualMemory(NtCurrentProcess(),&allocate,
		0,&size,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);
	addr=(UINT_PTR)allocate;
	record[section_count].section_register=section>>31;
	record[section_count].section_relay_buffer=addr;
	record[section_count].section_referenced=1;
	section_count++;
	return addr;
}
BOOL SectionRelayBuffer::UnregisterSection(UINT_PTR section)
{
	UINT_PTR i,base=section>>31;
	for (i=0;i<section_count;i++)
	{
		if (record[i].section_register==section)
		{
			record[i].section_referenced--;
			if (record[i].section_referenced==0)
			{
				LPVOID addr=(LPVOID)(record[i].section_relay_buffer);
				UINT_PTR size=0x1000;
				NtFreeVirtualMemory(NtCurrentProcess(),&addr,&size,MEM_RELEASE);
				for (;i<section_count;i++)
					record[i]=record[i+1];
				section_count--;
			}
			return TRUE;
		}
	}
	return FALSE;
}


extern "C" UINT_PTR GetModuleBaseByHash(UINT_PTR hash);
inline UINT_PTR GetModuleBase(UINT_PTR hash)
{
	return GetModuleBaseByHash(hash);
}
void NotifyHookInsert()
{
	if (live)
	{
		BYTE buffer[0x10];
		*(UINT_PTR*)buffer=-1;
		*(UINT_PTR*)(buffer+8)=1;
		IO_STATUS_BLOCK ios;
		NtWriteFile(hPipe,0,0,0,&ios,buffer,HEADER_SIZE,0,0);
	}
}

typedef void (*DataFun)(UINT_PTR, const HookParam&, UINT_PTR*, UINT_PTR*, UINT_PTR*);
bool HookFilter(UINT_PTR retn)
{
	UINT_PTR i;
	for (i=0;filter[i].lower;i++)
	if (retn>filter[i].lower&&retn<filter[i].upper) return true;
	return false;
}
#define SMALL_BUFF_SIZE 0x40
typedef void (TextHook::*sendfun)(UINT_PTR,UINT_PTR,UINT_PTR);
void TextHook::Send(UINT_PTR stack_ptr, UINT_PTR data, UINT_PTR split)
{
	__try
	{
		UINT_PTR dwCount,dwAddr;
		BYTE *pbData, pbSmallBuff[SMALL_BUFF_SIZE];
		UINT_PTR dwType=hp.type;
		UINT_PTR dwRetn=*(UINT_PTR*)stack_ptr;
		if (live)	
		{
			if ((dwType&NO_CONTEXT)==0)
				if (HookFilter(dwRetn)) return;
			dwCount=-1;
			dwAddr=hp.addr;
			if (trigger)
			{
				//MessageBox(0,0,0,0);
				trigger=0;
				//InsertDynamicHook((LPVOID)dwAddr,*(UINT_PTR*)(dwDataBase-0x1C),*(UINT_PTR*)(dwDataBase-0x18));
			}
			if (dwType&EXTERN_HOOK) 
			{
				/*DataFun fun=(DataFun)hp.extern_fun;
				if (fun)	fun(dwDataBase,hp,&data,&split,&dwCount);
				else dwCount=0;
				if (dwCount==0) return;*/
			}
			else
			{
				if (data==0) return;
				if (dwType&USING_SPLIT)
				{
					if (dwType&SPLIT_INDIRECT) split=*(UINT_PTR*)(split+hp.split_ind);
				}
				else split=0;
				if (dwType&DATA_INDIRECT)
				{
					data=*(UINT_PTR*)(data+hp.ind);
				}
				if (dwType&PRINT_DWORD) 
				{
					swprintf((WCHAR*)(pbSmallBuff+HEADER_SIZE),L"%.8X ",data);
					data=(UINT_PTR)pbSmallBuff+HEADER_SIZE;
				}
				dwCount=GetLength(stack_ptr, data);
			}
			if (dwCount+HEADER_SIZE>=SMALL_BUFF_SIZE) pbData=new BYTE[dwCount+HEADER_SIZE];
			else pbData=pbSmallBuff;
			if (hp.length_offset==1)
			{
				if (dwType&STRING_LAST_CHAR)
				{
					LPWSTR ts=(LPWSTR)data;
					data=ts[wcslen(ts)-1];
				}
				data&=0xFFFF;
				if (dwType&BIG_ENDIAN) 
					if (data>>8)
						data=_byteswap_ushort(data&0xFFFF);
				if (dwCount==1) data&=0xFF;
				*(WORD*)(pbData+HEADER_SIZE)=data&0xFFFF;
			}
			else memcpy(pbData+HEADER_SIZE,(void*)data,dwCount);
			*(UINT_PTR*)pbData=dwAddr;
			if (dwType&NO_CONTEXT) dwRetn=0;
			*((UINT_PTR*)pbData+1)=dwRetn;
			*((UINT_PTR*)pbData+2)=split;
			if (dwCount)
			{
				IO_STATUS_BLOCK ios={};
				if (STATUS_PENDING==NtWriteFile(hPipe,0,0,0,&ios,pbData,dwCount+HEADER_SIZE,0,0))
				{
					NtWaitForSingleObject(hPipe,0,0);
					NtFlushBuffersFile(hPipe,&ios);
				}
			}
			if (pbData!=pbSmallBuff) delete pbData;
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		OutputConsole(L"except");
		return;
	}
}
int MapInstruction(UINT_PTR original_addr, UINT_PTR new_addr, PWORD hook_len, PWORD original_len)
{
	UINT_PTR flag=0;
	int len=0;
	BYTE *src,*dst;
	src=(BYTE*)original_addr;
	dst=(BYTE*)new_addr;
	while((src-(BYTE*)original_addr)<5)
	{
		len=disasm(src);
		if (len==0) return -1;
		memcpy(dst,src,len);
		if ((dst[0]>>1)==0x74) //E8,E9
		{
			LARGE_INTEGER ptr;
			ptr.QuadPart=(UINT_PTR)src;
			INT_PTR temp=*(int*)(src+1);
			ptr.QuadPart+=temp+5;
			//UINT_PTR point_addr=((UINT_PTR)src)>>32;
			//temp=(UINT_PTR)src+5+temp;
			//point_addr=(point_addr<<32)|temp;		
			dst[1]=0x15|((dst[0]&1)<<5);
			dst[0]=0xFF;
			*(DWORD*)(dst+2)=new_addr+0x18-(UINT_PTR)dst;
			*(UINT_PTR*)(new_addr+0x1E)=ptr.QuadPart;
			dst+=6;
		}
		else if (dst[0]==0xFF)
		{
			if (dst[1]==0x15||dst[1]==0x25)
			{
				BYTE* rel=src+6+*(DWORD*)(src+2);				
				*(DWORD*)(dst+2)=new_addr+0x18-(UINT_PTR)dst;
				*(UINT_PTR*)(new_addr+0x1E)=*(UINT_PTR*)rel;
				dst+=6;
			}
			else dst+=len;
		}
		else dst+=len;
		src+=len;
	}
	if (hook_len) *hook_len=((UINT_PTR)dst-new_addr)&0xFF;
	if (original_len) *original_len=((UINT_PTR)src-original_addr)&0xFF;
	return 0;
}
int MapDataAndSplit(BYTE* current, const HookParam& hp)
{
	BYTE* original=current;
	int data=hp.off; //Resolve data
	int split=hp.split;
	int flag=0;
	if (split==-0x40)
	{
		flag=1;
		if (data==-0x48)
		{
			*(DWORD*)(current)=0xCCC1874D; //xchg r8,r9
			return 3;
		}
		else
		{
			*(DWORD*)(current)=0x00C88B4D; // mov r9,r8
			current+=3;
		}
	}
	if (data>0) 
	{
		*(DWORD*)current=0xE4848B4C;
		*(DWORD*)(current+0x4)=data+0x48; //mov r8, [rsp+$]
		current+=8;
	}
	else 
	{
		data=-data;
		if (data==0x20) //esp, special case
		{
			*(DWORD*)current=0x49C48B4C; //mov r8,rsp
			*(DWORD*)(current+0x4)=0x48C083; //add r8,0x40;
			current+=7;
		}
		else
		{
			if (data!=0x40)
			{
				data>>=3;
				current[0]=0x4C|(data>>3);
				current[1]=0x8B;
				current[2]=0xC0|(data&7); //mov r8,$
				current+=3;
			}
		}
	}
	if (flag==0&&(hp.type&USING_SPLIT))
	{
		data=hp.split; //resolve split
		if (data>0)
		{
			*(DWORD*)current=0xE48C8B4C; 
			*(DWORD*)(current+4)=data+0x48; //mov r9,[rsp+$]
		}
		else 
		{
			data=-data;
			if (data==0x20) //esp, special case
			{
				*(DWORD*)current=0x49CC8B4C; //mov r9,rsp
				*(DWORD*)(current+0x4)=0x48C183; //add r9,0x40;
				current+=7;
			}
			else
			{
				if (data!=0x48)
				{
					data>>=3;
					current[0]=0x4C|(data>>3);
					current[1]=0x8B;
					current[2]=0xC8|data&7;
					current+=3;
				}
			}
		}
	}
	return current-original;
}
int TextHook::InsertHook()
{
	NtWaitForSingleObject(hmMutex,0,0);
	int k=InsertHookCode();
	IthReleaseMutex(hmMutex);	
	if (hp.type&HOOK_ADDITIONAL) 
	{
		NotifyHookInsert();
		OutputConsole(hook_name);
		RegisterHookName(hook_name,hp.addr);
	}
	return k;
}
int TextHook::InsertHookCode()
{
	//__debugbreak();
	if (hp.module&&(hp.type&MODULE_OFFSET)) //Map hook offset to real address. 
	{
		UINT_PTR base=GetModuleBase(hp.module);
		if (base) 
		{
			if (hp.function&&(hp.type&(FUNCTION_OFFSET)))
			{
				base=GetExportAddress(base,hp.function);
				if (base) 
					hp.addr+=base;
				else 
				{
					OutputConsole(L"Function not found in the export table.");
					current_hook--;
					return 1;
				}
			}
			else
				hp.addr+=base;
			hp.type&=~(MODULE_OFFSET|FUNCTION_OFFSET);
		}
		else 
		{
			OutputConsole(L"Module not present.");
			current_hook--;
			return 1;
		}
	}
	TextHook* it;
	int i;
	for (i=0,it=hookman;i<current_hook;it++) //Check if there is a collision.
	{
		if (it->Address()) i++;
		//it=hookman+i;
		if (it==this) continue;
		if (it->Address()<=hp.addr && it->Address()+it->Length()>hp.addr)
		{
			it->ClearHook();
			break;
		}
	}

	//Verify hp.addr. 
	MEMORY_BASIC_INFORMATION info;
	NtQueryVirtualMemory(NtCurrentProcess(),(LPVOID)hp.addr,MemoryBasicInformation,&info,sizeof(info),0);
	if (info.Type&PAGE_NOACCESS) return 1; 

	//Initialize common routine.
	UINT_PTR buffer=relay->RegisterSection((UINT_PTR)hp.addr);
	UINT_PTR inst=hp.addr;
	BYTE jmp_code[8], *ptr;
	while (*(UINT_PTR*)buffer) buffer+=0x10;
	jmp_code[0]=0xE8;
	*(DWORD*)(jmp_code+1)=(buffer-5-inst)&0xFFFFFFFF; //Hook address relative near jump.
	//memcpy(recover,common_hook,0x60); //Copy hook entry code.
	ptr=recover;
	memcpy(ptr,common_prologue,PROLOGUE_LENGTH);
	ptr+=PROLOGUE_LENGTH;
	ptr+=MapDataAndSplit(ptr,hp);
	memcpy(ptr,common_route,ROUTE_LENGTH);
	union
	{
		sendfun sf;
		UINT_PTR fun;
	};
	sf=&TextHook::Send;
	*(UINT_PTR*)(ptr+0xD+HOOK_DEBUG_HEAD)=fun; //Resolve high level function.
	*(UINT_PTR*)(ptr+0x17+HOOK_DEBUG_HEAD)=(UINT_PTR)this; //Resolve this pointer.
	ptr+=ROUTE_LENGTH;
	memcpy(ptr,common_epilogue,EPILOGUE_LENGTH);
	ptr+=EPILOGUE_LENGTH;
	MapInstruction(inst,(UINT_PTR)ptr,&hp.hook_len,&hp.recover_len); //Map hook instruction.
	*(WORD*)(ptr+hp.hook_len+HOOK_DEBUG_HEAD)=0x25FF; //Long jmp back.
	*(DWORD*)(ptr+hp.hook_len+2+HOOK_DEBUG_HEAD)=0x72-(ptr-recover)-hp.hook_len;
	*(UINT_PTR*)(recover+0x78+HOOK_DEBUG_HEAD)=inst+hp.recover_len;
	//*(UINT_PTR*)(recover+hp.hook_len+0x58)=inst+hp.recover_len;

	*(WORD*)buffer=0x25FF; //Relay buffer long jmp.
	*(LPVOID*)(buffer+6)=recover;

	memcpy(original,(LPVOID)hp.addr,hp.recover_len);
	//Check if the new hook range conflict with existing ones. Clear older if conflict.
	for (i=0,it=hookman;i<current_hook;it++)
	{
		if (it->Address()) i++;
		if (it==this) continue;
		if (it->Address()>=hp.addr && it->Address()<hp.hook_len+hp.addr)
		{
			it->ClearHook();
			break;
		}
	}
	//Insert hook and flush instruction cache.
	static DWORD int3[4]={0xCCCCCCCC,0xCCCCCCCC,0xCCCCCCCC,0xCCCCCCCC};
	UINT_PTR t=0x100,old,len;
	NtProtectVirtualMemory(NtCurrentProcess(),(PVOID*)&inst,&t,PAGE_EXECUTE_READWRITE,&old);
	NtWriteVirtualMemory(NtCurrentProcess(),(BYTE*)hp.addr,jmp_code,5,&t);	
	len=hp.recover_len-5;
	if (len) NtWriteVirtualMemory(NtCurrentProcess(),(BYTE*)hp.addr+5,int3,len,&t);
	NtProtectVirtualMemory(NtCurrentProcess(),(PVOID*)&inst,&t,old,&old);
	NtFlushInstructionCache(NtCurrentProcess(),(LPVOID)hp.addr,hp.recover_len);
	NtFlushInstructionCache(NtCurrentProcess(),(LPVOID)hookman,0x1000);
	NtFlushInstructionCache(NtCurrentProcess(),(LPVOID)(buffer&~0xFFF),0x1000);
	return 0;
}
int TextHook::InitHook(LPVOID addr, UINT_PTR data, UINT_PTR data_ind, 
	UINT_PTR split_off, UINT_PTR split_ind, UINT_PTR type, UINT_PTR len_off)
{
	NtWaitForSingleObject(hmMutex,0,0);
	hp.addr=(UINT_PTR)addr;
	hp.off=data;
	hp.ind=data_ind;
	hp.split=split_off;
	hp.split_ind=split_ind;
	hp.type=type;
	hp.hook_len=0;
	hp.module=0;
	hp.length_offset=len_off&0xFFFF;
	current_hook++;
	if (current_available>=this)
		for (current_available=this+1;current_available->Address();current_available++);
	IthReleaseMutex(hmMutex);
	return this-hookman;
}
int TextHook::InitHook(const HookParam& h, LPWSTR name, WORD set_flag)
{
	NtWaitForSingleObject(hmMutex,0,0);
	hp=h;
	hp.type|=set_flag;
	if (name&&name!=hook_name)
	{
		if (hook_name) delete hook_name;
		name_length=wcslen(name)+1;
		hook_name=new WCHAR[name_length];
		wcscpy(hook_name,name);
	}
	current_hook++;
	current_available=this+1;
	while (current_available->Address()) current_available++;
	IthReleaseMutex(hmMutex);
	return 1;
}
int TextHook::RemoveHook()
{
	if (hp.addr)
	{
		NtWaitForSingleObject(hmMutex,0,0);
		UINT_PTR old,l=hp.hook_len,len;
		LPVOID base=(LPVOID)hp.addr;
		NtProtectVirtualMemory(NtCurrentProcess(),&base,&l,PAGE_EXECUTE_READWRITE,&old);
		NtWriteVirtualMemory(NtCurrentProcess(),(LPVOID)hp.addr,original,hp.recover_len,&len);
		NtFlushInstructionCache(NtCurrentProcess(),(LPVOID)hp.addr,hp.recover_len);
		NtProtectVirtualMemory(NtCurrentProcess(),&base,&l,old,&old);
		hp.hook_len=0;
		IthReleaseMutex(hmMutex);
		return 1;
	}
	return 0;
}
int TextHook::ClearHook()
{
	NtWaitForSingleObject(hmMutex,0,0);
	int k=RemoveHook();
	if (hook_name) {delete hook_name;hook_name=0;}
	memset(this,0,sizeof(TextHook));
	//if (current_available>this) current_available=this;
	current_hook--;
	IthReleaseMutex(hmMutex);
	return k;
}
int TextHook::ModifyHook(const HookParam& hp)
{
	WCHAR name[0x40];
	wcscpy(name,hook_name);
	ClearHook();
	InitHook(hp,name);
	InsertHook();
	return 0;
}
int TextHook::RecoverHook()
{
	if (hp.addr)
	{
		InsertHook();
		return 1;
	}
	return 0;
}
int TextHook::SetHookName(LPWSTR name)
{
	name_length=wcslen(name)+1;
	hook_name=new WCHAR[name_length];
	wcscpy(hook_name,name);
	return 0;
}
int TextHook::GetLength(UINT_PTR base, UINT_PTR in)
{
	if (base==0) return 0;
	__int64 len;
	switch (hp.length_offset)
	{
	default:
		len = *((__int64*)base+hp.length_offset);
		if (len>=0) 
		{
			if (hp.type&USING_UNICODE) len<<=1;
			break;
		}
	case 0:
		if (hp.type&USING_UNICODE) len=wcslen((LPWSTR)in)<<1;
		else len=strlen((char*)in);
		break;
	case 1:
		if (hp.type&USING_UNICODE) len=2;
		else 
		{
			if (hp.type&BIG_ENDIAN) in>>=8;
			len=LeadByteTable[in&0xFF];  //Slightly faster than IsDBCSLeadByte
		}
		break;
	case 2:
	case 3:
	case 4:
		len = *((__int64*)base-hp.length_offset-3);
		if (len>=0) 
		{
			if (hp.type&USING_UNICODE) len<<=1;
		}
		else
		{
			if (hp.type&USING_UNICODE) len=wcslen((LPWSTR)in)<<1;
			else len=strlen((char*)in);
		}
		break;
	}
	return len;
}

static LPVOID fun_table[14];
//#define DEFAULT_SPLIT
#ifdef DEFAULT_SPLIT
#define SPLIT_SWITCH USING_SPLIT
#else
#define SPLIT_SWITCH 0
#endif
LPWSTR HookNameInitTable[]={
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
void InitDefaultHook()
{
	fun_table[0]=GetTextExtentPoint32A;
	fun_table[1]=GetGlyphOutlineA;
	fun_table[2]=ExtTextOutA;
	fun_table[3]=TextOutA;
	fun_table[4]=GetCharABCWidthsA;
	fun_table[5]=DrawTextA;
	fun_table[6]=DrawTextExA;
	fun_table[7]=GetTextExtentPoint32W;
	fun_table[8]=GetGlyphOutlineW;
	fun_table[9]=ExtTextOutW;
	fun_table[10]=TextOutW;
	fun_table[11]=GetCharABCWidthsW;
	fun_table[12]=DrawTextW;
	fun_table[13]=DrawTextExW;

	hookman[0].InitHook(  fun_table[0],   -0x10,0,-8,0,USING_STRING|SPLIT_SWITCH ,3);
	hookman[1].InitHook(  fun_table[1],   -0x10,0,-8,0,BIG_ENDIAN|SPLIT_SWITCH, 1);
	hookman[2].InitHook(  fun_table[2],   0x30,0,-8,0,USING_STRING|SPLIT_SWITCH, 7);
	hookman[3].InitHook(  fun_table[3],   -0x48,0,-8,0,USING_STRING|SPLIT_SWITCH, 5);
	hookman[4].InitHook(  fun_table[4],   -0x10,0,-8,0,BIG_ENDIAN|SPLIT_SWITCH, 1);
	hookman[5].InitHook(  fun_table[5],   -0x10,0,-8,0,USING_STRING|SPLIT_SWITCH, 3);
	hookman[6].InitHook(  fun_table[6],   -0x10,0,-8,0,USING_STRING|SPLIT_SWITCH, 3);
	hookman[7].InitHook(  fun_table[7],   -0x10,0,-8,0,USING_UNICODE | USING_STRING|SPLIT_SWITCH, 3);
	hookman[8].InitHook(  fun_table[8],   -0x10,0,-8,0,USING_UNICODE|SPLIT_SWITCH, 1);
	hookman[9].InitHook(  fun_table[9],   0x30,0,-8,0,USING_UNICODE | USING_STRING|SPLIT_SWITCH, 7);
	hookman[10].InitHook(fun_table[10], -0x48,0,-8,0,USING_UNICODE | USING_STRING|SPLIT_SWITCH, 5);
	hookman[11].InitHook(fun_table[11], -0x10,0,-8,0,USING_UNICODE|SPLIT_SWITCH, 1);
	hookman[12].InitHook(fun_table[12], -0x10,0,-8,0,USING_UNICODE | USING_STRING|SPLIT_SWITCH, 3);
	hookman[13].InitHook(fun_table[13], -0x10,0,-8,0,USING_UNICODE | USING_STRING|SPLIT_SWITCH, 3);
	for (int i=0;i<sizeof(HookNameInitTable)/sizeof(LPWSTR);i++)
		hookman[i].SetHookName(HookNameInitTable[i]);
}
