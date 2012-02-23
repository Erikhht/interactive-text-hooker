#include <windows.h>
int main()
{
	SetCurrentDirectory(L"..\\Release");
	HANDLE hFile=INVALID_HANDLE_VALUE;
	LPWSTR f=wcsrchr(GetCommandLine(),L' ')+1;
	if (f==0) return 1;
	for (int i=0;i<10;i++)
	{
		hFile=CreateFile(f,GENERIC_WRITE|GENERIC_READ,FILE_SHARE_READ,0,OPEN_EXISTING,0,0);
		if (hFile!=INVALID_HANDLE_VALUE) break;
		Sleep(100);
	}
	if (hFile==INVALID_HANDLE_VALUE) return 1;
	DWORD size=GetFileSize(hFile,0);
	DWORD d;
	char* file=(char*)HeapAlloc(GetProcessHeap(),0, size);
	ReadFile(hFile,file,size,&d,0);
	IMAGE_DOS_HEADER *DosHdr=(IMAGE_DOS_HEADER*)file;
	IMAGE_NT_HEADERS *NtHdr=(IMAGE_NT_HEADERS*)((DWORD)DosHdr+DosHdr->e_lfanew);
	NtHdr->OptionalHeader.DllCharacteristics&=0xFBFF;
	SetFilePointer(hFile,0,0,FILE_BEGIN);
	WriteFile(hFile,file,size,&d,0);
	HeapFree(GetProcessHeap(),0,file);
	CloseHandle(hFile);
	ExitProcess(0);
}