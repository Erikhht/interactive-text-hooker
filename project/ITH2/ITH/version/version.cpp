//#include "..\sys.h"
#include <windows.h>
#include "..\ntdll.h"
extern "C" int sprintf(char * _String, const char * _Format, ...);
char buffer[0x100]="const wchar_t* version=L\"Interactive Text Hooker 2.3 (";
WCHAR path[MAX_PATH]=L"\\??\\";
LPWSTR GetModulePath()
{
	__asm
	{
		mov eax,fs:[0x30]
		mov eax,[eax+0xC]
		mov eax,[eax+0xC]
		mov eax,[eax+0x28]
	}
}
LARGE_INTEGER* GetTimeBias()
{
	__asm mov eax,0x7ffe0020
}
int main()
{
	wcscpy(path+4,GetModulePath());
	LPWSTR p=path;
	while (*p) p++;
	while (*p!=L'\\') p--;
	p--;
	while (*p!=L'\\') p--;
	p++;
	wcscpy(p,L"version.h");
	UNICODE_STRING us;
	RtlInitUnicodeString(&us,path);
	OBJECT_ATTRIBUTES oa={sizeof(oa),0,&us,OBJ_CASE_INSENSITIVE,0,0};
	HANDLE hFile;
	IO_STATUS_BLOCK isb;
	if (!NT_SUCCESS(NtCreateFile(&hFile,
		FILE_SHARE_READ|FILE_WRITE_DATA|FILE_READ_ATTRIBUTES|SYNCHRONIZE
		,&oa,&isb,0,0,FILE_SHARE_READ,FILE_OPEN_IF,
		FILE_SYNCHRONOUS_IO_NONALERT|FILE_NON_DIRECTORY_FILE,0,0)))
		return 1;
	FILE_BASIC_INFORMATION basic;
	NtQueryInformationFile(hFile,&isb,&basic,sizeof(basic),FileBasicInformation);
	
	int l=strlen(buffer);
	char* ptr;
	ptr=buffer+l;
	LARGE_INTEGER current_time;
	TIME_FIELDS tf,ctf;
	NtQuerySystemTime(&current_time);
	current_time.QuadPart-=GetTimeBias()->QuadPart;
	RtlTimeToTimeFields(&current_time,&tf);
	RtlTimeToTimeFields(&basic.LastWriteTime,&ctf);
	if (ctf.wDay!=tf.wDay||ctf.wMonth!=tf.wMonth||ctf.wYear!=tf.wYear){
		l+=sprintf(ptr,"%.4d.%.2d.%.2d)\\r\\n\";",tf.wYear,tf.wMonth,tf.wDay);
		NtWriteFile(hFile,0,0,0,&isb,buffer,l,0,0);
	}
	NtClose(hFile);
	return 0;
	//IthCloseSystemService();
}