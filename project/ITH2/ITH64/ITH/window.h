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
#include "main.h"
#include "cmdq.h"
#include "profile.h"
BYTE* GetSystemInformation();
size_t GetProcessMemory(HANDLE hProc, UINT_PTR* mem_size, UINT_PTR* ws);
size_t GetHookString(LPWSTR str, UINT_PTR pid, UINT_PTR hook_addr, UINT_PTR status);
SYSTEM_PROCESS_INFORMATION_NT5* GetBaseByPid(BYTE* pbBuffer,UINT_PTR dwPid);
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);
LPWSTR StateString[StateUnknown+1]={
	L"Initialized",L"Ready",L"Running",L"Standby",
	L"Terminated",L"Wait",L"Transition",L"Unknown"
};
LPWSTR WaitReasonString[MaximumWaitReason]={
	L"Executive",L"FreePage",L"PageIn",L"PoolAllocation",
	L"DelayExecution",L"Suspended",L"UserRequest",L"Executive",
	L"FreePage",L"PageIn",L"PoolAllocation",L"DelayExecution",
	L"Suspended",L"UserRequest",L"EventPair",L"Queue",
	L"LpcReceive",L"LpcReply",L"VirtualMemory",L"PageOut",
	L"Rendezvous",L"Spare2",L"Spare3",L"Spare4",
	L"Spare5",L"Spare6",L"Kernel"
};
#define IDC_CHECK_BIGENDIAN		IDC_CHECK1
#define IDC_CHECK_UNICODE			IDC_CHECK2
#define IDC_CHECK_STRING			IDC_CHECK3
#define IDC_CHECK_DATA_IND		IDC_CHECK4
#define IDC_CHECK_SPLIT				IDC_CHECK5
#define IDC_CHECK_SPLIT_IND		IDC_CHECK6
#define IDC_CHECK_MODULE			IDC_CHECK7
#define IDC_CHECK_FUNCTION		IDC_CHECK8
#define IDC_CHECK_HEX					IDC_CHECK9
#define IDC_CHECK_LASTCHAR		IDC_CHECK10
#define IDC_CHECK_NOCONTEXT	IDC_CHECK11

class ProcessWindow
{
public:
	ProcessWindow(HWND hDialog);
	void InitProcessDlg();
	void RefreshProcess();
	void AttachProcess();
	void DetachProcess();
	void OperateThread();
	void AddCurrentToProfile();
	void RefreshThread(int index);
	void RefreshThreadColumns(UINT_PTR pid);
	bool PerformThread(UINT_PTR pid, UINT_PTR tid, ThreadOperation op=OutputInformation, UINT_PTR addr=0);
	UINT_PTR GetSelectPID();
private:
	HWND hDlg;
	HWND hlProcess,hlThread;
	HWND hbRefresh,hbAttach,hbDetach,hbExecute,hbAddProfile;
	HWND heAddr,heOutput;
	HWND hrSuspend,hrResume,hrTerminate;
};

class ThreadWindow
{
public:
	ThreadWindow(HWND hDialog);
	void InitWindow();
	void InitThread(int index);
	void SetThreadInfo(int index);
	void RemoveLink(int index);
	void SetThread();
	void SetLastSentence(UINT_PTR select);
private:
	HWND hDlg;
	HWND hcCurrentThread,hcLinkThread;
	HWND hlFromThread;
	HWND heInfo,heSentence,heComment;
	HWND hsHook,hsRetn,hsSplit;
};

class HookWindow
{
public:
	HookWindow(HWND hDialog);
	inline bool IsBigEndian();
	inline bool IsUnicode();
	inline bool IsString();
	inline bool IsDataInd();
	inline bool IsSplit();
	inline bool IsSplitInd();
	inline bool IsModule();
	inline bool IsFunction();
	inline bool IsHex();
	inline bool IsLastChar();
	inline bool IsNoContext();
	void GenerateCode();
	void GenerateHash(size_t ID);
	void RemoveHook();
	void ModifyHook();
	void ResetDialog(const HookParam& hp);
	void ResetDialog(int index);
	void GetHookParam(HookParam& hp);
	void InitDlg();
	void ResetDlgHooks(UINT_PTR pid, HookParam& hp);

private:
	void PrintUnsignedPtr(LPWSTR str, UINT_PTR d);
	void PrintSignedPtr(LPWSTR str, UINT_PTR d);
	HWND hDlg,hCombo,hText;
	HWND	hcBigEndian,	hcUnicode,	hcString,		hcDataInd,
				hcSplit,			hcSplitInd,	hcModule,	hcFunction,
				hcHex,			hcLastChar,	hcNoContext;
	HWND	heAddr,		heData,			heDataInd,	heSplit,
				heSplitInd,	heModule,	heFunction,	heHash;
	HWND	hbModify,		hbRemove,	hbModule,	hbFunction,	hbCode;
};

class ProfileWindow
{
public:
	ProfileWindow(HWND hDialog);
	void RefreshProfileList();
	void StartProfileProcess();
	void ResetProfile(int index);
	void ResetProfileWindow(int index=-1);
	void SetCurrentProfile(Profile* pf);
	void SaveCurrentProfile();
	void DeleteCurrentProfile();
	void ExportCurrentProfile();
	void ExportAllProfile();
	void ImportCurrentProfile();
	void DeleteItem(size_t last_select);
	void CheckHook(int index, bool check);
	bool IsHook(int index);
	Profile* GetCurrentProfile();
	UINT_PTR GetCurrentSelect();
	HWND hDlg,hlProfileList,hlThread,hlComment,hlLink;
	HWND hePath,heHook1,heHook2,heHook3,heHook4;
	HWND hcHook1,hcHook2,hcHook3,hcHook4;
	HWND hbStart, hbDelete, hbSave;
	HWND hcbSelect;
};

void ExportSingleProfile(ProfileNode* pfn, MyVector<WCHAR,0x1000,WCMP> &export_text);