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

#include "window.h"
#include "resource.h"
#include <commctrl.h>
#include <intrin.h>
//LPCWSTR ClassName=L"ITH";
//LPCWSTR ClassNameAdmin=L"ITH (Administrator)";
LPWSTR import_buffer;
int import_buffer_len;
static WNDPROC proc,proccmd,procChar;
static WCHAR last_cmd[CMD_SIZE];
static CRITICAL_SECTION update_cs;

HWND hMainWnd,hwndCombo,hwndProc,hwndEdit,hwndCmd;
HWND hwndProcess,hwndThread,hwndHook,hwndProfile;
HWND hwndOption,hwndTop,hwndClear,hwndSave;
HWND hProcDlg,hHookDlg,hProfileDlg,hOptionDlg,hThreadDlg,hEditProfileDlg;
HBITMAP hbmp,hBlackBmp;
BITMAP bmp;
HBRUSH hWhiteBrush;
HDC hCompDC,hBlackDC;
BLENDFUNCTION fn;
DWORD split_time, process_time, inject_delay, insert_delay, background;
HookWindow* hkwnd;
ProcessWindow* pswnd;
ThreadWindow* thwnd;
ProfileWindow* pfwnd;
FilterWindow* ftwnd;
ThreadParam edit_tp;
LinkParam edit_lp;
CommentParam edit_cp;
#define COMMENT_BUFFER_LENGTH 0x200
static WCHAR comment_buffer[COMMENT_BUFFER_LENGTH];
DWORD clipboard_flag,cyclic_remove,repeat_count,global_filter;
bool Parse(LPWSTR cmd, HookParam& hp);
void SaveSettings();
extern LPVOID DefaultHookAddr[];
extern LPWSTR EngineHookName[],HookNameInitTable[];
static int last_select,last_edit;
typedef BOOL (CALLBACK* EditFun)(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
typedef BOOL (*PostEditFun)(HWND hlEdit, HWND hcmb);


ATOM MyRegisterClass(HINSTANCE hInstance)
{
	WNDCLASSEX wcex;
	wcex.cbSize = sizeof(WNDCLASSEX);
	wcex.style			= 0;//CS_HREDRAW | CS_VREDRAW;
	wcex.lpfnWndProc	= WndProc;
	wcex.cbClsExtra		= 0;
	wcex.cbWndExtra		= 0;
	wcex.hInstance		= hInstance;
	wcex.hIcon			= 0;
	wcex.hCursor		= 0;
	wcex.hbrBackground	= 0;//(HBRUSH)COLOR_BACKGROUND;
	wcex.lpszMenuName	= 0;
	wcex.lpszClassName	= ClassName;
	wcex.hIconSm		= LoadIcon(hInstance,(LPWSTR)IDI_ICON1);
	return RegisterClassEx(&wcex);
}
BOOL InitInstance(HINSTANCE hInstance, int nAdmin, RECT* rc)
{
	LPCWSTR name= (nAdmin) ? ClassNameAdmin : ClassName;
	hMainWnd = CreateWindow(ClassName, name, WS_OVERLAPPEDWINDOW|WS_CLIPCHILDREN,
		rc->left, rc->top, rc->right-rc->left, rc->bottom-rc->top, 0, 0, hInstance, 0);
	if (!hMainWnd) return FALSE;
	ShowWindow(hMainWnd, SW_SHOW);
	UpdateWindow(hMainWnd);
	InitializeCriticalSection(&update_cs);
	return TRUE;
}
int SaveSingleThread(Profile* pf,TextThread* thread, Hook* hks, DWORD pid)
{
	int i,j;
	ThreadParameter *tpr=thread->GetThreadParameter();
	ThreadParam tp={0,THREAD_MASK_RETN|THREAD_MASK_SPLIT,0,tpr->retn,tpr->spl,0,0};
	for (j=0;j<MAX_HOOK;j++)
	{
		if (hks[j].Address()==0) continue;
		if (hks[j].Address()==tpr->hook)
		{
			tp.hook_index=j+1;
			break;
		}
	}
	if (j<MAX_HOOK)
	{
		i=pf->thread_count;
		j=pf->AddThread(&tp);
		if (i<pf->thread_count)
		{
			pf->AddComment(thread->GetComment(),j+1);
			if (thread->Status()&CURRENT_SELECT) pf->select_index=j+1;
			if (thread->Link())
			{
				LinkParam lp={j+1};
				lp.to_index=SaveSingleThread(pf,thread->Link(),hks,pid)+1;
				pf->AddLink(&lp);
			}
		}
	}
	return j;
}
BOOL SaveCurrentProfile()
{
	WCHAR str[0x400]; DWORD pid=0;
	int i;
	GetWindowText(hwndProc,str,0x400);
	swscanf(str,L"%d",&pid);
	if (pid==0) return 0;
	man->GetProcessPath(pid,str);
	pfman->DeleteProfile(str);
	Profile pf;
	pf.engine_type=man->GetEngineByPID(pid)&0xFF;
	man->LockProcessHookman(pid);
	man->LockHookman();
	ThreadTable* table=man->Table();
	Hook* hooks=(Hook*)man->RemoteHook(pid);
	TextThread* thread;
	for (i=1;i<table->Used();i++)
	{
		thread=table->FindThread(i);
		if (thread==0||thread->PID()!=pid) continue;
		if (thread->GetComment()||thread->Link()||(thread->Status()&CURRENT_SELECT))
			SaveSingleThread(&pf,thread,hooks,pid);
	}
	man->UnlockHookman();	
	HookParam hp;
	for (i=0;i<MAX_HOOK;i++)
	{
		if (hooks[i].Address()==0) continue;
		if (hooks[i].Type()&HOOK_ADDITIONAL)
			if ((hooks[i].Type()&HOOK_ENGINE)==0)
			{

				hp=*(HookParam*)(hooks+i);
				hp.type&=~FUNCTION_OFFSET;
				if (hp.module)
				{
					hp.type|=MODULE_OFFSET;
					MEMORY_BASIC_INFORMATION info;
					HANDLE hProc=man->GetProcessByPID(pid);
					if (NT_SUCCESS(NtQueryVirtualMemory(hProc,(PVOID)hp.addr,
						MemoryBasicInformation,&info,sizeof(info),0)))
					hp.addr-=(DWORD)info.AllocationBase;
				}
				else hp.type&=~MODULE_OFFSET;
				pf.AddHook(hp);
			}
	}
	man->UnlockProcessHookman(pid);
	pfman->AddProfile(str,pf);
	return 0;
}
BOOL CALLBACK ImportProfileDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_INITDIALOG:
		return TRUE;
	case WM_COMMAND:
		{
			DWORD wmId, wmEvent;
			wmId    = LOWORD(wParam);
			wmEvent = HIWORD(wParam);
			switch (wmId)
			{
			case IDOK:
				{
					HWND hEdit=GetDlgItem(hDlg,IDC_EDIT1);
					import_buffer_len=GetWindowTextLength(hEdit)+2;
					if (import_buffer) delete import_buffer;
					import_buffer=new WCHAR[import_buffer_len];
					GetWindowText(hEdit,import_buffer,import_buffer_len);
					import_buffer[import_buffer_len-1]=0;
					import_buffer[import_buffer_len-2]=L'[';
					EndDialog(hDlg,1);
					break;
				}
			case IDCANCEL:
				EndDialog(hDlg,0);
				break;
			}
			return 1;
		}
	default:
		return 0;
	}
	return FALSE;
}
BOOL PostEditThread(HWND hlEdit, HWND hcmb)
{
	WCHAR buf[0x80];
	LPWSTR str=buf;
	int count=SendMessage(hlEdit,LB_GETCOUNT,0,0);
	int select=last_select;
	if (select==-1) select=count-1;
	str+=swprintf(str,L"%.4X:",select);
	GetThreadString(&edit_tp,str);
	Profile* pf=pfwnd->GetCurrentProfile();
	if (pf==0) return 0;
	if (select!=count-1)
	{
		SendMessage(hlEdit,LB_DELETESTRING,select,0);
		int ind=SendMessage(hcmb,CB_FINDSTRINGEXACT,-1,(LPARAM)buf);
		if (ind!=-1) SendMessage(hcmb,CB_DELETESTRING,ind,0);
		SendMessage(hcmb,CB_INSERTSTRING,ind,(LPARAM)buf);
		pf->threads[select]=edit_tp;
	}
	else
	{
		pf->AddThread(&edit_tp);
		SendMessage(hcmb,CB_ADDSTRING,0,(LPARAM)buf);
	}
	SendMessage(hlEdit,LB_INSERTSTRING,select,(LPARAM)buf);
	return 0;
}
BOOL PostEditLink(HWND hlLink, HWND hcmb)
{
	WCHAR buf[0x80];
	int count=SendMessage(hlLink,LB_GETCOUNT,0,0);
	int select=last_select;
	if (select==-1) select=count-1;
	swprintf(buf,L"%.4X:%.4X->%.4X",select,edit_lp.from_index,edit_lp.to_index);
	Profile* pf=pfwnd->GetCurrentProfile();
	if (pf==0) return 0;
	if (select!=count-1)
	{
		SendMessage(hlLink,LB_DELETESTRING,select,0);
		pf->links[select]=edit_lp;
	}
	else
		pf->AddLink(&edit_lp);
	SendMessage(hlLink,LB_INSERTSTRING,select,(LPARAM)buf);
	return 0;
}
BOOL PostEditComment(HWND hlComment, HWND hcmb)
{
	WCHAR buf[0x240];
	int count=SendMessage(hlComment,LB_GETCOUNT,0,0);
	int select=last_select;
	if (select==-1) select=count-1;
	swprintf(buf,L"%.4X:%.4X:%s",select,edit_cp.thread_index,comment_buffer);
	Profile* pf=pfwnd->GetCurrentProfile();
	if (pf==0) return 0;
	if (select!=count-1)
	{
		SendMessage(hlComment,LB_DELETESTRING,select,0);
		delete pf->comments[select].comment;
		pf->comments[select].thread_index=edit_cp.thread_index;
		int l=wcslen(comment_buffer);
		pf->comments[select].comment=new WCHAR[l+1];
		wcscpy(pf->comments[select].comment,comment_buffer);
	}
	else
		pf->AddComment(comment_buffer,edit_cp.thread_index);
	SendMessage(hlComment,LB_INSERTSTRING,select,(LPARAM)buf);
	return 0;
}
BOOL CALLBACK OptionDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_INITDIALOG:
		{
			WCHAR str[0x80];
			swprintf(str,L"%d",split_time);
			SetWindowText(GetDlgItem(hDlg,IDC_EDIT1),str);
			swprintf(str,L"%d",process_time);
			SetWindowText(GetDlgItem(hDlg,IDC_EDIT2),str);
			swprintf(str,L"%d",inject_delay);
			SetWindowText(GetDlgItem(hDlg,IDC_EDIT3),str);
			swprintf(str,L"%d",insert_delay);
			SetWindowText(GetDlgItem(hDlg,IDC_EDIT4),str);
			swprintf(str,L"%d",repeat_count);
			SetWindowText(GetDlgItem(hDlg,IDC_EDIT5),str);
			CheckDlgButton(hDlg,IDC_CHECK1,auto_inject);
			CheckDlgButton(hDlg,IDC_CHECK2,auto_insert);
			CheckDlgButton(hDlg,IDC_CHECK3,clipboard_flag);
			CheckDlgButton(hDlg,IDC_CHECK4,cyclic_remove);
			CheckDlgButton(hDlg,IDC_CHECK5,global_filter);
			hOptionDlg=hDlg;
			ftwnd=new FilterWindow(hDlg);
			ftwnd->Init();
		}
		return TRUE;
	case WM_COMMAND:
		{
			DWORD wmId, wmEvent;
			wmId    = LOWORD(wParam);
			wmEvent = HIWORD(wParam);
			switch (wmId)
			{
			case IDOK:
				{
					DWORD st,pt,jd,sd,repeat;
					WCHAR str[0x80];
					GetWindowText(GetDlgItem(hDlg,IDC_EDIT1),str,0x80);
					swscanf(str,L"%d",&st);
					split_time=st>100?st:100;
					GetWindowText(GetDlgItem(hDlg,IDC_EDIT2),str,0x80);
					swscanf(str,L"%d",&pt);
					process_time=pt>50?pt:50;
					GetWindowText(GetDlgItem(hDlg,IDC_EDIT3),str,0x80);
					swscanf(str,L"%d",&jd);
					inject_delay=jd>1000?jd:1000;
					GetWindowText(GetDlgItem(hDlg,IDC_EDIT4),str,0x80);
					swscanf(str,L"%d",&sd);
					insert_delay=sd>200?sd:200;
					GetWindowText(GetDlgItem(hDlg,IDC_EDIT5),str,0x80);

					swscanf(str,L"%d",&repeat);
					if (repeat!=repeat_count)
					{
						repeat_count=repeat;
						man->ResetRepeatStatus();
					}
					auto_inject=IsDlgButtonChecked(hDlg,IDC_CHECK1);
					auto_insert=IsDlgButtonChecked(hDlg,IDC_CHECK2);
					clipboard_flag=IsDlgButtonChecked(hDlg,IDC_CHECK3);
					cyclic_remove=IsDlgButtonChecked(hDlg,IDC_CHECK4);
					global_filter=IsDlgButtonChecked(hDlg,IDC_CHECK5);
					if (auto_inject==0) auto_insert=0;
					ftwnd->SetCommitFlag();
				}
			case IDCANCEL:
				delete ftwnd;
				EndDialog(hDlg,0);
				hOptionDlg=0;
				
				ftwnd=0;
				break;
			case IDC_BUTTON1: //delete
				ftwnd->DeleteCurrentChar();
				break;
			case IDC_BUTTON2: //Set
				ftwnd->SetCurrentChar();
				break;
			case IDC_BUTTON3: //Add
				ftwnd->AddNewChar();
				break;
			case IDC_EDIT8:
				if (wmEvent==WM_PASTE)
				{
					WCHAR uni_char[4];
					if (GetDlgItemText(hDlg,IDC_EDIT8,uni_char,8)>=1)
						ftwnd->InitWithChar(uni_char[0]);				
				}				
				break;
			}
			return TRUE;
		}
	case WM_NOTIFY:
		{
			LPNMHDR dr=(LPNMHDR)lParam;
			switch (dr->code)
			{
			case NM_CLICK: 
			case LVN_ITEMCHANGED:
				if (dr->idFrom==IDC_LIST1)
				{
					NMLISTVIEW *nmlv=(LPNMLISTVIEW)lParam;
					if (nmlv->uNewState==3)
					{
						ftwnd->SelectCurrentChar(nmlv->iItem);
						return TRUE;
					}
						//pswnd->RefreshThread(nmlv->iItem);
				}
				
			}
		}
	default:
		return FALSE;
	}
	return FALSE;
}
BOOL CALLBACK ThreadDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_INITDIALOG:
		{
			thwnd=new ThreadWindow(hDlg);
			hThreadDlg=hDlg;
		}
		return TRUE;
	case WM_COMMAND:
		{
			DWORD wmId, wmEvent;
			wmId    = LOWORD(wParam);
			wmEvent = HIWORD(wParam);
			switch (wmId)
			{
			case IDOK:
			case IDCANCEL:
				EndDialog(hDlg,0);
				hThreadDlg=0;
				delete thwnd;
				thwnd=0;
				break;
			case IDC_COMBO1:
				if (wmEvent==CBN_SELENDOK)
					thwnd->InitThread(SendMessage((HWND)lParam,CB_GETCURSEL,0,0));
				break;
			case IDC_COMBO2:
				if (wmEvent==CBN_SELENDOK)
					thwnd->SetThreadInfo(SendMessage((HWND)lParam,CB_GETCURSEL,0,0));
				break;
			case IDC_BUTTON1:
				thwnd->SetThread();
				break;
			case IDC_BUTTON2:
				thwnd->ExportSingleThreadText();
				break;
			case IDC_BUTTON3:
				thwnd->ExportAllThreadText();
				break;
			}
			return TRUE;
		}
	default:
		return FALSE;
	}
	return FALSE;
}
BOOL CALLBACK EditThreadDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_INITDIALOG:
		{
			POINT p; RECT r;
			int i;	WCHAR str[0x80];
			DWORD pid=pfwnd->GetCurrentSelect();
			HWND hCom=GetDlgItem(hDlg,IDC_COMBO1);
			GetCursorPos(&p);
			GetWindowRect(hDlg,&r);
			r.right-=r.left;
			r.bottom-=r.top;
			MoveWindow(hDlg,p.x-r.right/2,p.y-r.bottom/2,r.right,r.bottom,1);
			Profile* pf=pfwnd->GetCurrentProfile();			
			if (pid)
			{
				Hook* hks=(Hook*)man->RemoteHook(pid);
				DWORD len;  DWORD count=0;
				HANDLE hProc=man->GetProcessByPID(pid);
				for (i=0;i<MAX_HOOK;i++)
				{
					if (hks[i].Address()==0) {count++;continue;}
					while (count)
					{
						SendMessage(hCom,CB_ADDSTRING,0,(LPARAM)L"");
						count--;
					}
					len=hks[i].NameLength();
					len=len<0x7F?len:0x7F;
					if (hks[i].Name())
						NtReadVirtualMemory(hProc,hks[i].Name(),str,len*2,&len);
					str[len>>1]=0;
					SendMessage(hCom,CB_ADDSTRING,0,(LPARAM)str);
				}
			}
			else
			{
				for (i=1;i<15;i++)
					SendMessage(hCom,CB_ADDSTRING,0,(LPARAM)HookNameInitTable[i]);
				if (pf->engine_type)
				{
					SendMessage(hCom,CB_ADDSTRING,0,(LPARAM)EngineHookName[pf->engine_type]);
					if (pf->engine_type==ENGINE_KIRIKIRI)
						SendMessage(hCom,CB_ADDSTRING,0,(LPARAM)L"KiriKiri2");
					if (pf->engine_type==ENGINE_DOTNET1)
						SendMessage(hCom,CB_ADDSTRING,0,(LPARAM)L"DotNet2");
				}
				for (int i=0;i<pf->hook_count;i++)
				{
					swprintf(str,L"UserHook%d",i);
					SendMessage(hCom,CB_ADDSTRING,0,(LPARAM)str);
				}
			}
			SendMessage(hCom,CB_SETCURSEL,edit_tp.hook_index-1,0);
			swprintf(str,L"%X",edit_tp.retn);
			SendMessage(GetDlgItem(hDlg,IDC_EDIT1),WM_SETTEXT,0,(LPARAM)str);
			swprintf(str,L"%X",edit_tp.split);
			SendMessage(GetDlgItem(hDlg,IDC_EDIT2),WM_SETTEXT,0,(LPARAM)str);
			if (edit_tp.status&THREAD_MASK_RETN)
				CheckDlgButton(hDlg,IDC_CHECK1,TRUE);
			if (edit_tp.status&THREAD_MASK_SPLIT)
				CheckDlgButton(hDlg,IDC_CHECK2,TRUE);
		}
		return TRUE;
	case WM_SYSCOMMAND:
		if (wParam==SC_CLOSE)
		{
			hEditProfileDlg=0;
			EndDialog(hDlg,0);
		}
		break;
	case WM_COMMAND:
		{
			DWORD wmId, wmEvent;
			wmId    = LOWORD(wParam);
			wmEvent = HIWORD(wParam);
			switch (wmId)
			{
			case IDOK:
				{
					edit_tp.hook_index=(SendMessage(GetDlgItem(hDlg,IDC_COMBO1),CB_GETCURSEL,0,0)&0xFFFF)+1;
					WCHAR str[0x80];
					GetWindowText(GetDlgItem(hDlg,IDC_EDIT1),str,0x80);
					swscanf(str,L"%x",&edit_tp.retn);	
					GetWindowText(GetDlgItem(hDlg,IDC_EDIT2),str,0x80);
					swscanf(str,L"%x",&edit_tp.split);
					if (IsDlgButtonChecked (hDlg,IDC_CHECK1))
						edit_tp.status|=1;
					else edit_tp.status&=~1;
					if (IsDlgButtonChecked (hDlg,IDC_CHECK2))
						edit_tp.status|=2;
					else edit_tp.status&=~2;
					hEditProfileDlg=0;
					EndDialog(hDlg,1);
					break;
				}
			case IDCANCEL:
				hEditProfileDlg=0;
				EndDialog(hDlg,2);
				break;
			}
			return 1;
		}
	default:
		return 0;
	}
	return FALSE;
}
BOOL CALLBACK EditLinkDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_INITDIALOG:
		{
			POINT p; RECT r;
			GetCursorPos(&p);
			GetWindowRect(hDlg,&r);
			r.right-=r.left;
			r.bottom-=r.top;
			MoveWindow(hDlg,p.x-r.right/2,p.y-r.bottom/2,r.right,r.bottom,1);
			Profile* pf=pfwnd->GetCurrentProfile();
			HWND hComFrom,hComTo;
			hComFrom=GetDlgItem(hDlg,IDC_COMBO1);
			hComTo=GetDlgItem(hDlg,IDC_COMBO2);
			WCHAR buff[0x80];
			if (pf)
			{
				for (int i=0;i<pf->thread_count;i++)
				{
					swprintf(buff,L"%.4X:",i);
					GetThreadString(pf->threads+i,buff+5);
					SendMessage(hComFrom,CB_ADDSTRING,0,(LPARAM)buff);
					SendMessage(hComTo,CB_ADDSTRING,0,(LPARAM)buff);
				}
				if (edit_lp.from_index)
					SendMessage(hComFrom,CB_SETCURSEL,edit_lp.from_index-1,0);
				if (edit_lp.to_index)
					SendMessage(hComTo,CB_SETCURSEL,edit_lp.to_index-1,0);
			}
		}
		return TRUE;
	case WM_SYSCOMMAND:
		if (wParam==SC_CLOSE)
		{
			hEditProfileDlg=0;
			EndDialog(hDlg,0);
		}
		break;
	case WM_COMMAND:
		{
			DWORD wmId, wmEvent;
			wmId    = LOWORD(wParam);
			wmEvent = HIWORD(wParam);
			switch (wmId)
			{
			case IDOK:
				{
					edit_lp.from_index=(SendMessage(GetDlgItem(hDlg,IDC_COMBO1),CB_GETCURSEL,0,0)&0xFFFF)+1;
					edit_lp.to_index=(SendMessage(GetDlgItem(hDlg,IDC_COMBO2),CB_GETCURSEL,0,0)&0xFFFF)+1;
					hEditProfileDlg=0;
					EndDialog(hDlg,1);
					break;
				}
			case IDCANCEL:
				hEditProfileDlg=0;
				EndDialog(hDlg,2);
				break;
			}
			return 1;
		}
	default:
		return 0;
	}
	return FALSE;
}
BOOL CALLBACK EditCommentDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_INITDIALOG:
		{
			POINT p; RECT r;
			GetCursorPos(&p);
			GetWindowRect(hDlg,&r);
			r.right-=r.left;
			r.bottom-=r.top;
			MoveWindow(hDlg,p.x-r.right/2,p.y-r.bottom/2,r.right,r.bottom,1);
			Profile* pf=pfwnd->GetCurrentProfile();
			if (pf)
			{
				WCHAR buff[0x80];
				HWND hThread=GetDlgItem(hDlg,IDC_COMBO1);
				for (int i=0;i<pf->thread_count;i++)
				{
					swprintf(buff,L"%.4X:",i);
					GetThreadString(pf->threads+i,buff+5);
					SendMessage(hThread,CB_ADDSTRING,0,(LPARAM)buff);
				}
				if (edit_cp.thread_index)
				{
					SendMessage(hThread,CB_SETCURSEL,edit_cp.thread_index-1,0);
					int l=SendMessage(GetDlgItem(hDlg,IDC_EDIT1),WM_SETTEXT,0,(LPARAM)comment_buffer);
					comment_buffer[l]=0;
				}
			}
		}
		return TRUE;
	case WM_SYSCOMMAND:
		if (wParam==SC_CLOSE)
		{
			hEditProfileDlg=0;
			EndDialog(hDlg,0);
		}
		break;
	case WM_COMMAND:
		{
			DWORD wmId, wmEvent;
			wmId    = LOWORD(wParam);
			wmEvent = HIWORD(wParam);
			switch (wmId)
			{
			case IDOK:
				{
					edit_cp.thread_index=(SendMessage(GetDlgItem(hDlg,IDC_COMBO1),CB_GETCURSEL,0,0)&0xFFFF)+1;
					int l=SendMessage(GetDlgItem(hDlg,IDC_EDIT1),WM_GETTEXT,
						COMMENT_BUFFER_LENGTH-1,(LPARAM)comment_buffer);
					comment_buffer[l]=0;
					hEditProfileDlg=0;
					EndDialog(hDlg,1);
					break;
				}
			case IDCANCEL:
				hEditProfileDlg=0;
				EndDialog(hDlg,2);
				break;
			}
			return 1;
		}
	default:
		return 0;
	}
	return FALSE;
}
static EditFun EditFunTable[]={EditThreadDlgProc,EditLinkDlgProc,EditCommentDlgProc};
static PostEditFun PostEditFunTable[]={PostEditThread,PostEditLink,PostEditComment};
BOOL CALLBACK ProfileDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_INITDIALOG:
		pfwnd=new ProfileWindow(hDlg);
		hProfileDlg=hDlg;
		last_select=-1;
		return TRUE;

	case WM_COMMAND:
		{
			DWORD wmId, wmEvent;
			wmId    = LOWORD(wParam);
			wmEvent = HIWORD(wParam);
			switch (wmId)
			{
			case IDC_BUTTON1:
				pfwnd->StartProfileProcess();
			case IDCANCEL:
			case IDOK:
				EndDialog(hDlg,0);
				hProfileDlg=0;
				delete pfwnd;
				pfwnd=0;
				break;
			case IDC_LIST3:
			case IDC_LIST4:
			case IDC_LIST2:
				switch (wmEvent)
				{
				case LBN_SELCHANGE:
					last_select=SendMessage((HWND)lParam,LB_GETCURSEL,0,0);
					last_edit=wmId-IDC_LIST2;
					break;
				case LBN_KILLFOCUS:
					SendMessage((HWND)lParam,LB_SETCURSEL,-1,0);
					//last_select=-1;
					break;
				case LBN_DBLCLK:
					{
						WCHAR buf[0x80];
						if (wmId!=last_edit+IDC_LIST2) last_select=-1;
						if (last_select+1==SendMessage((HWND)lParam,LB_GETCOUNT,0,0)||last_select==-1)
						{
							memset(&edit_tp,0,sizeof(edit_tp));
							memset(&edit_lp,0,sizeof(edit_lp));
							memset(&edit_cp,0,sizeof(edit_cp));
						}
						else if (last_select!=-1)
						{
							SendMessage((HWND)lParam,LB_GETTEXT,last_select,(LPARAM)buf);
							Profile* pf=pfwnd->GetCurrentProfile();
							switch(last_edit)
							{
							case 0:
								if (pf) memcpy(&edit_tp,pf->threads+last_select,sizeof(ThreadParam));
								else
									swscanf(buf,L"%x:%x:%x:%x",&last_select,&edit_tp.hook_index,&edit_tp.retn,&edit_tp.split);
								break;
							case 1:
								if (pf) memcpy(&edit_lp,pf->links+last_select,sizeof(LinkParam));
								else
								{
									swscanf(buf,L"%x:%x->%x",&last_select,&edit_lp.from_index,&edit_lp.to_index);
									edit_lp.from_index++;edit_lp.to_index++;
								}
								break;
							case 2:
								if (pf)
								{
									wcscpy(comment_buffer,pf->comments[last_select].comment);
									edit_cp.thread_index=pf->comments[last_select].thread_index;
								}
								else
								{
									swscanf(buf,L"%x:%x",&last_select,&edit_cp.thread_index);
									edit_cp.thread_index++;
									wcscpy(comment_buffer,buf+10);
								}
								break;
							}
						}
						switch (DialogBoxParam(hIns,(LPWSTR)(IDD_DIALOG6+last_edit),hDlg,EditFunTable[last_edit],0))
						{
						case 1:
							PostEditFunTable[last_edit]((HWND)lParam,GetDlgItem(hDlg,IDC_COMBO1));
							break;
						case 2:
							pfwnd->DeleteItem(last_select);
							break;
						}
					}
					break;
				}
				break;

				break;

			case IDC_BUTTON2:
				pfwnd->DeleteCurrentProfile();
				break;
			case IDC_BUTTON3:
				pfwnd->SaveCurrentProfile();
				break;
			case IDC_BUTTON4:
				pfwnd->ExportCurrentProfile();
				break;
			case IDC_BUTTON5:
				pfwnd->ExportAllProfile();
				break;
			case IDC_BUTTON6:
				pfwnd->ImportCurrentProfile();
				break;
			case IDC_CHECK1:
			case IDC_CHECK2:
			case IDC_CHECK3:
			case IDC_CHECK4:
				{
					int index=wmId-IDC_CHECK1;
					bool c=pfwnd->IsHook(index);
					pfwnd->CheckHook(index,c);
				}
				break;
			default:
				return 1;
			}
			return 1;
		}
	case WM_NOTIFY:
		{
			LPNMHDR dr=(LPNMHDR)lParam;
			switch (dr->code)
			{
			case LVN_ITEMCHANGED:
				if (dr->idFrom==IDC_LIST1)
				{
					NMLISTVIEW *nmlv=(LPNMLISTVIEW)lParam;
					if (nmlv->uNewState==3)
						pfwnd->ResetProfile(nmlv->iItem);
					return TRUE;
				}

			}
			break;
		}
	default:
		return FALSE;
	}
	return TRUE;
}
BOOL CALLBACK ProcessDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_INITDIALOG:
		{
			pswnd=new ProcessWindow(hDlg);
			return TRUE;
		}
	case WM_COMMAND:
		{
			DWORD wmId, wmEvent;
			wmId    = LOWORD(wParam);
			wmEvent = HIWORD(wParam);
			switch (wmId)
			{
			case WM_DESTROY:
			case IDOK:
				EndDialog(hDlg,0);
				hProcDlg=0;
				delete pswnd;
				pswnd=0;
				break;
			case IDC_BUTTON1:
				pswnd->RefreshProcess();
				break;
			case IDC_BUTTON2:
				pswnd->AttachProcess();
				break;
			case IDC_BUTTON3:
				pswnd->DetachProcess();
				break;
			case IDC_BUTTON4:
				pswnd->OperateThread();
				break;
			case IDC_BUTTON5:
				pswnd->AddCurrentToProfile();
				break;
			}
		}
		return TRUE;
	case WM_NOTIFY:
		{
			LPNMHDR dr=(LPNMHDR)lParam;
			switch (dr->code)
			{
			case NM_CLICK: 
			case LVN_ITEMCHANGED:
				if (dr->idFrom==IDC_LIST1)
				{
					NMLISTVIEW *nmlv=(LPNMLISTVIEW)lParam;
					if (nmlv->uNewState==3)
						pswnd->RefreshThread(nmlv->iItem);
				}
				break;
			}
		}
		return TRUE;
	default:
		return FALSE;
	}
}
BOOL CALLBACK HookDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_INITDIALOG:
		hkwnd=new HookWindow(hDlg);
		hkwnd->InitDlg();
		break;
	case WM_COMMAND:
		{
			DWORD wmId, wmEvent;
			wmId    = LOWORD(wParam);
			wmEvent = HIWORD(wParam);
			switch (wmId)
			{
			case WM_DESTROY:
			case IDOK:
				EndDialog(hDlg,0);
				delete hkwnd;
				hHookDlg=0;
				hkwnd=0;
				break;
			case IDC_COMBO1:
				if (wmEvent==CBN_SELENDOK)
					hkwnd->ResetDialog(SendMessage((HWND)lParam,CB_GETCURSEL,0,0));
				break;
			case IDC_CHECK_HEX:
				CheckDlgButton(hDlg,IDC_CHECK_BIGENDIAN,BST_UNCHECKED);
				CheckDlgButton(hDlg,IDC_CHECK_UNICODE,BST_UNCHECKED);
				CheckDlgButton(hDlg,IDC_CHECK_STRING,BST_UNCHECKED);
				CheckDlgButton(hDlg,IDC_CHECK_LASTCHAR,BST_UNCHECKED);
				break;
			case IDC_CHECK_BIGENDIAN:
				CheckDlgButton(hDlg,IDC_CHECK_STRING,BST_UNCHECKED);
				CheckDlgButton(hDlg,IDC_CHECK_LASTCHAR,BST_UNCHECKED);
				CheckDlgButton(hDlg,IDC_CHECK_HEX,BST_UNCHECKED);
				CheckDlgButton(hDlg,IDC_CHECK_UNICODE,BST_UNCHECKED);

				break;
			case IDC_CHECK_STRING:
				CheckDlgButton(hDlg,IDC_CHECK_BIGENDIAN,BST_UNCHECKED);
				CheckDlgButton(hDlg,IDC_CHECK_LASTCHAR,BST_UNCHECKED);
				CheckDlgButton(hDlg,IDC_CHECK_HEX,BST_UNCHECKED);
				break;
			case IDC_CHECK_UNICODE:
				CheckDlgButton(hDlg,IDC_CHECK_HEX,BST_UNCHECKED);
				CheckDlgButton(hDlg,IDC_CHECK_BIGENDIAN,BST_UNCHECKED);
				break;
			case IDC_CHECK_LASTCHAR:
				CheckDlgButton(hDlg,IDC_CHECK_STRING,BST_UNCHECKED);
				CheckDlgButton(hDlg,IDC_CHECK_HEX,BST_UNCHECKED);
				CheckDlgButton(hDlg,IDC_CHECK_BIGENDIAN,BST_UNCHECKED);

				break;
			case IDC_CHECK_SPLIT_IND:
				if (!hkwnd->IsSplit())
				{
					CheckDlgButton(hDlg,wmId,BST_UNCHECKED);
					SetDlgItemText(hDlg,IDC_EDIT9,L"Need to enable split first!");
					break;
				}
				goto common_route;
			case IDC_CHECK_SPLIT:
				if (hkwnd->IsSplitInd())
				{
					CheckDlgButton(hDlg,IDC_CHECK_SPLIT_IND,BST_UNCHECKED);
					EnableWindow(GetDlgItem(hDlg,IDC_EDIT5),FALSE);
				}
				goto common_route;
			case IDC_CHECK_FUNCTION:
				if (!hkwnd->IsModule())
				{
					CheckDlgButton(hDlg,wmId,BST_UNCHECKED);
					SetDlgItemText(hDlg,IDC_EDIT9,L"Need to enable module first!");
					break;
				}
				goto common_route;
			case IDC_CHECK_MODULE:
				if (hkwnd->IsFunction())
				{
					CheckDlgButton(hDlg,IDC_CHECK8,BST_UNCHECKED);
					EnableWindow(GetDlgItem(hDlg,IDC_EDIT7),FALSE);
				}
common_route:
			case IDC_CHECK_DATA_IND:
				{
				int off=IDC_EDIT3-IDC_CHECK4; 
				if (IsDlgButtonChecked(hDlg,wmId))
					EnableWindow(GetDlgItem(hDlg,wmId+off),TRUE);
				else
					EnableWindow(GetDlgItem(hDlg,wmId+off),FALSE);
				break;
				}
			case IDC_BUTTON1:
				hkwnd->ModifyHook();
				break;
			case IDC_BUTTON2:
				hkwnd->RemoveHook();
				break;
			case IDC_BUTTON3:
			case IDC_BUTTON4:
				hkwnd->GenerateHash(wmId);
				break;
			case IDC_BUTTON5:
				hkwnd->GenerateCode();
				break;
			}
		}
		return TRUE;
	case WM_SYSCOMMAND:
	default:
		return FALSE;
	}
	return TRUE;
}
LRESULT CALLBACK EditProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{

	switch (message)
	{
	case WM_CHAR:  //Filter user input.
			if (GetKeyState(VK_CONTROL)&0xFF00)
			{
				if (wParam==1)
				{
					SendMessage(hwndEdit,EM_SETSEL,0,-1);
					SendMessage(hwndEdit,WM_COPY,0,0);
				}
			}
			return 0;
	case WM_ERASEBKGND:
		if (background)
		{
			RECT rc,rc2;
			HDC hDC=(HDC)wParam;
			GetClientRect(hwndEdit,&rc);
			rc2=rc;
			rc2.right=rc2.right<bmp.bmWidth?rc2.right:bmp.bmWidth;
			rc2.bottom=rc2.bottom<bmp.bmHeight?rc2.bottom:bmp.bmHeight;
			//StretchBlt(hDC,0,0,rc.right,rc.bottom,hBlackDC,0,0,bmp.bmWidth,bmp.bmHeight,SRCCOPY);
			BitBlt(hDC,0,0,rc2.right,rc2.bottom,hBlackDC,0,0,SRCCOPY);
			if (rc2.right-rc.right<0)
			{
				rc.left=rc2.right;
				FillRect(hDC,&rc,hWhiteBrush);
				rc.left=0;
			}
			if (rc2.bottom-rc.bottom<0)
			{
				rc.top=rc2.bottom;
				FillRect(hDC,&rc,hWhiteBrush);
			}
			
		}
		return 1;
		//else return proc(hWnd,message,wParam,lParam);
		
	case WM_LBUTTONUP:
			if (hwndEdit) SendMessage(hwndEdit,WM_COPY,0,0);
	default:
		{
			return proc(hWnd,message,wParam,lParam);	
		}
		
	}
	
}
LRESULT CALLBACK EditCmdProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	switch (message)
	{
	case WM_KEYDOWN:
		if (wParam==VK_UP)
		{
			SendMessage(hWnd,WM_SETTEXT,0,(LPARAM)last_cmd);
			SetFocus(hWnd);
			return 0;
		}
		break;
	case WM_CHAR:
		if (wParam==VK_RETURN)
		{
			DWORD s=0,pid=0;
			WCHAR str[0x20];
			if (SendMessage(hWnd,WM_GETTEXTLENGTH,0,0)==0) break;
			SendMessage(hWnd,WM_GETTEXT,CMD_SIZE,(LPARAM)last_cmd);
			if (GetWindowText(hwndProc,str,0x20))
				swscanf(str,L"%d",&pid);
			cmdq->ProcessCommand(last_cmd,pid);
			SendMessage(hWnd,EM_SETSEL,0,-1);
			SendMessage(hWnd,EM_REPLACESEL,FALSE,(LPARAM)&s);
			SetFocus(hWnd);
			return 0;
		}
	default:
		break;
	}
	return CallWindowProc(proccmd,hWnd,message,wParam,lParam);
}
void CreateButtons(HWND hWnd)
{
	hwndProcess = CreateWindow(L"Button", L"Process", WS_CHILD | WS_VISIBLE,
		0, 0, 0, 0, hWnd, 0, hIns, NULL);
	hwndThread = CreateWindow(L"Button", L"Thread", WS_CHILD | WS_VISIBLE,
		0, 0, 0, 0, hWnd, 0, hIns, NULL);
	hwndHook = CreateWindow(L"Button", L"Hook", WS_CHILD | WS_VISIBLE,
		0, 0, 0, 0, hWnd, 0, hIns, NULL);
	hwndProfile = CreateWindow(L"Button", L"Profile", WS_CHILD | WS_VISIBLE,
		0, 0, 0, 0, hWnd, 0, hIns, NULL);
	hwndOption = CreateWindow(L"Button", L"Option", WS_CHILD | WS_VISIBLE,
		0, 0, 0, 0, hWnd, 0, hIns, NULL);
	hwndClear = CreateWindow(L"Button", L"Clear", WS_CHILD | WS_VISIBLE,
		0, 0, 0, 0, hWnd, 0, hIns, NULL);
	hwndSave = CreateWindow(L"Button", L"Save", WS_CHILD | WS_VISIBLE,
		0, 0, 0, 0, hWnd, 0, hIns, NULL);
	hwndTop = CreateWindow(L"Button", L"Top", WS_CHILD | WS_VISIBLE | BS_PUSHLIKE | BS_CHECKBOX,
		0, 0, 0, 0, hWnd, 0, hIns, NULL);

	hwndProc = CreateWindow(L"ComboBox", NULL,
		WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | 
		CBS_SORT | WS_VSCROLL | WS_TABSTOP,
		0, 0, 0, 0, hWnd, 0, hIns, NULL); 
	hwndCmd = CreateWindowEx(WS_EX_CLIENTEDGE, L"Edit", NULL,
		WS_CHILD | WS_VISIBLE | ES_NOHIDESEL| ES_LEFT | ES_AUTOHSCROLL,
		0, 0, 0, 0, hWnd, 0, hIns, NULL);
	hwndEdit = CreateWindowEx(WS_EX_CLIENTEDGE, L"Edit", NULL,
		WS_CHILD | WS_VISIBLE | ES_NOHIDESEL| WS_VSCROLL |
		ES_LEFT | ES_MULTILINE | ES_AUTOVSCROLL, 
		0, 0, 0, 0, hWnd, 0, hIns, NULL);
}
void LoadBMP(HWND hWnd)
{
	HANDLE hFile=IthCreateFile(L"background.bmp",FILE_READ_DATA,FILE_SHARE_READ,FILE_OPEN);
	HDC hDC=GetDC(hwndEdit);	
	if (INVALID_HANDLE_VALUE!=hFile)
	{
		IO_STATUS_BLOCK ios;
		BITMAPFILEHEADER header;
		BITMAPINFOHEADER info;
		LARGE_INTEGER size;
		LPVOID buffer1,buffer2;
		NtReadFile(hFile,0,0,0,&ios,&header,sizeof(header),0,0);
		if (header.bfType!=0x4D42) //BM
			MessageBox(0,L"Not valid bmp file.",0,0);
		else
		{
			size.LowPart=sizeof(header);
			size.HighPart=0;
			NtReadFile(hFile,0,0,0,&ios,&info,sizeof(info),0,0);									
			hCompDC=CreateCompatibleDC(hDC);
			hBlackDC=CreateCompatibleDC(hDC);				
					
			size.LowPart=header.bfOffBits;

			if (info.biBitCount==24)
			{
				info.biBitCount=32;
				hBlackBmp=CreateDIBSection(hBlackDC,(BITMAPINFO*)&info,DIB_RGB_COLORS,&buffer2,0,0);		
				hbmp=CreateDIBSection(hCompDC,(BITMAPINFO*)&info,DIB_RGB_COLORS,&buffer1,0,0);
				NtReadFile(hFile,0,0,0,&ios,buffer2,info.biWidth*info.biHeight*3,&size,0);
				BYTE* ptr1=(BYTE*)buffer1;
				BYTE* ptr2=(BYTE*)buffer2;
				LONG i,j;
				for (i=0;i<info.biHeight;i++)
					for (j=0;j<info.biWidth;j++)
					{
						ptr1[0]=ptr2[0];
						ptr1[1]=ptr2[1];
						ptr1[2]=ptr2[2];
						ptr1[3]=0xFF;
						ptr1+=4;
						ptr2+=3;
					}
					memset(buffer2,0,info.biWidth*info.biHeight*3);
			}
			else 
			{
				hBlackBmp=CreateDIBSection(hBlackDC,(BITMAPINFO*)&info,DIB_RGB_COLORS,&buffer2,0,0);		
				hbmp=CreateDIBSection(hCompDC,(BITMAPINFO*)&info,DIB_RGB_COLORS,&buffer1,0,0);
				NtReadFile(hFile,0,0,0,&ios,buffer1,info.biWidth*info.biHeight*info.biBitCount/8,&size,0);
			}
			
			NtClose(hFile);
			GetObject(hbmp,sizeof(bmp),&bmp);
			SelectObject(hCompDC,hbmp);		
			SelectObject(hBlackDC,hBlackBmp);

			fn.AlphaFormat=AC_SRC_ALPHA;
			fn.BlendOp=AC_SRC_OVER;
			fn.SourceConstantAlpha=0x80;
			GdiAlphaBlend(hBlackDC,0,0,info.biWidth,info.biHeight,hCompDC,0,0,info.biWidth,info.biHeight,fn);
			background=1;
			DeleteDC(hCompDC);
			DeleteObject(hbmp);
		}
	}
	ReleaseDC(hwndEdit,hDC);
}
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	switch (message) 
	{ 
		case WM_CREATE:
			CreateButtons(hWnd);
			// Add text to the window. 
			SendMessage(hwndEdit, EM_SETLIMITTEXT, -1, 0);
			SendMessage(hwndEdit, WM_INPUTLANGCHANGEREQUEST, 0, 0x411);
			proc=(WNDPROC)SetWindowLong(hwndEdit, GWL_WNDPROC, (LONG)EditProc);
			proccmd=(WNDPROC)SetWindowLong(hwndCmd, GWL_WNDPROC, (LONG)EditCmdProc);
			hwndCombo = CreateWindow(L"ComboBox", NULL,
									WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | 
									CBS_SORT | WS_VSCROLL | WS_TABSTOP,
									0, 0, 0, 0, hWnd, 0, hIns, NULL); 
			{
				HFONT hf=CreateFont(18,0,0,0,FW_LIGHT,0,0,0,SHIFTJIS_CHARSET,0,0,ANTIALIASED_QUALITY,0,
					L"MS Gothic");
				hWhiteBrush=CreateSolidBrush(RGB(0xFF,0xFF,0xFF));
				SendMessage(hwndCmd, WM_SETFONT, (WPARAM)hf, 0);
				SendMessage(hwndEdit, WM_SETFONT, (WPARAM)hf, 0);
				SendMessage(hwndCombo, WM_SETFONT, (WPARAM)hf, 0);
				SendMessage(hwndProc, WM_SETFONT, (WPARAM)hf, 0);
				LoadBMP(hWnd);
			}

			return 0; 
		case WM_COMMAND:
			{
				DWORD wmId, wmEvent, dwId;
				wmId    = LOWORD(wParam);
				wmEvent = HIWORD(wParam);
				HWND h=(HWND)lParam;

				switch (wmEvent)
				{
				case EN_VSCROLL:
					{
						SCROLLBARINFO info={sizeof(info)};
						GetScrollBarInfo(hwndEdit,OBJID_VSCROLL,&info);
						InvalidateRect(hwndEdit,0,1);
						ValidateRect(hwndEdit,&info.rcScrollBar);
						RedrawWindow(hwndEdit,0,0,RDW_ERASE);
					}
					break;
				case CBN_SELENDOK:
					{
						if (h==hwndProc) return 0;
						//WCHAR pwcEntry[0x80]={};
						LPWSTR pwcEntry; int len;
						dwId=SendMessage(hwndCombo,CB_GETCURSEL,0,0);
						len=SendMessage(hwndCombo,CB_GETLBTEXTLEN,dwId,0);
						if (len>0)
						{
							pwcEntry = new WCHAR[len+1];
							len=SendMessage(hwndCombo,CB_GETLBTEXT,dwId,(LPARAM)pwcEntry);
							man->SelectCurrent(pwcEntry);
							delete pwcEntry;
						}
					}
					return 0;
				case BN_CLICKED:
				{
					if (h==hwndProcess)
					{
						if(hProcDlg) SetForegroundWindow(hProcDlg);
						else hProcDlg=CreateDialog(hIns,(LPWSTR)IDD_DIALOG2,0,ProcessDlgProc);
					}
					else if (h==hwndThread)
					{
						if (hThreadDlg) SetForegroundWindow(hThreadDlg);
						else hThreadDlg=CreateDialog(hIns,(LPWSTR)IDD_DIALOG5,0,ThreadDlgProc);
					}
					else if (h==hwndHook)
					{
						if (hHookDlg) SetForegroundWindow(hHookDlg);
						else hHookDlg=CreateDialog(hIns,(LPWSTR)IDD_DIALOG1,0,HookDlgProc);
					}
					else if (h==hwndProfile)
					{
						if (hProfileDlg) SetForegroundWindow(hProfileDlg);
						else hProfileDlg=CreateDialog(hIns,(LPWSTR)IDD_DIALOG3,0,ProfileDlgProc);
					}
					else if (h==hwndOption)
					{
						if (hOptionDlg) SetForegroundWindow(hOptionDlg);
						else 
						{
							hOptionDlg=CreateDialog(hIns,(LPWSTR)IDD_DIALOG4,0,OptionDlgProc);
							ftwnd->ClearGlyphArea();
						}
					}
					else if (h==hwndClear)
					{
						WCHAR pwcEntry[0x80]={};
						dwId=SendMessage(hwndCombo,CB_GETCURSEL,0,0);
						int len=SendMessage(hwndCombo,CB_GETLBTEXT,dwId,(LPARAM)pwcEntry);
						swscanf(pwcEntry,L"%x",&dwId);
						if (dwId==0) man->ClearCurrent();
						else man->RemoveSingleThread(dwId);
					}
					else if (h==hwndTop)
					{
						if (SendMessage(h,BM_GETCHECK ,0,0)==BST_CHECKED)
						{
							SendMessage(h,BM_SETCHECK ,BST_UNCHECKED,0);
							SetWindowPos(hWnd,HWND_NOTOPMOST,0,0,0,0,SWP_NOSIZE|SWP_NOMOVE);
							if (hProcDlg) SetWindowPos(hProcDlg,HWND_NOTOPMOST,0,0,0,0,SWP_NOSIZE|SWP_NOMOVE);
							if (hThreadDlg) SetWindowPos(hThreadDlg,HWND_NOTOPMOST,0,0,0,0,SWP_NOSIZE|SWP_NOMOVE);
							if (hHookDlg) SetWindowPos(hHookDlg,HWND_NOTOPMOST,0,0,0,0,SWP_NOSIZE|SWP_NOMOVE);
							if (hProfileDlg) SetWindowPos(hProfileDlg,HWND_NOTOPMOST,0,0,0,0,SWP_NOSIZE|SWP_NOMOVE);
							if (hOptionDlg) SetWindowPos(hOptionDlg,HWND_NOTOPMOST,0,0,0,0,SWP_NOSIZE|SWP_NOMOVE);
						}
						else
						{
							SendMessage(h,BM_SETCHECK ,BST_CHECKED,0);
							SetWindowPos(hWnd,HWND_TOPMOST,0,0,0,0,SWP_NOSIZE|SWP_NOMOVE);
							if (hProcDlg) SetWindowPos(hProcDlg,HWND_TOPMOST,0,0,0,0,SWP_NOSIZE|SWP_NOMOVE);
							if (hThreadDlg) SetWindowPos(hThreadDlg,HWND_TOPMOST,0,0,0,0,SWP_NOSIZE|SWP_NOMOVE);
							if (hHookDlg) SetWindowPos(hHookDlg,HWND_TOPMOST,0,0,0,0,SWP_NOSIZE|SWP_NOMOVE);
							if (hProfileDlg) SetWindowPos(hProfileDlg,HWND_TOPMOST,0,0,0,0,SWP_NOSIZE|SWP_NOMOVE);
							if (hOptionDlg) SetWindowPos(hOptionDlg,HWND_TOPMOST,0,0,0,0,SWP_NOSIZE|SWP_NOMOVE);
						}
					}
					else if (h==hwndSave)
						SaveCurrentProfile();
				}
					break;
				default:
					break;
				}
			}
			break; 
		case WM_SETFOCUS: 
			SetFocus(hwndEdit); 
			return 0; 

		case WM_SIZE: 
			{
				DWORD l=LOWORD(lParam)>>3;
				WORD h=GetDialogBaseUnits()>>16;
				h=h+(h>>1);
				HDC hDC=GetDC(hWnd);
				RECT rc;
				GetClientRect(hWnd,&rc);
				FillRect(hDC,&rc,hWhiteBrush);
				ReleaseDC(hWnd,hDC);
				MoveWindow(hwndProcess, 0, 0, l, h, 1);
				MoveWindow(hwndThread, l, 0, l, h, 1);
				MoveWindow(hwndHook, l*2, 0, l, h, 1);
				MoveWindow(hwndProfile, l*3, 0, l, h, 1);
				MoveWindow(hwndOption, l*4, 0, l, h, 1);
				MoveWindow(hwndTop, l*5, 0, l, h, 1);
				MoveWindow(hwndClear, l*6, 0, l, h, 1);	
				MoveWindow(hwndSave, l*7, 0, LOWORD(lParam)-7*l, h, 1);	

				l<<=1;
				MoveWindow(hwndProc, 0, h, l, 200, 1);
				MoveWindow(hwndCmd, l, h, LOWORD(lParam)-l, h, 1);
				MoveWindow(hwndCombo, 0, h*2, LOWORD(lParam), 200, 1);
				h*=3;
				MoveWindow(hwndEdit, 0, h, LOWORD(lParam), HIWORD(lParam) - h, 0);
			}
			return 0; 
		case WM_ERASEBKGND:
			return 1;
		case WM_DESTROY:
			running=false;
			//DeleteCriticalSection(&update_cs);
			SaveSettings();
			PostQuitMessage(0);
			return 0;
		case WM_CTLCOLOREDIT:
			if (background)
			if ((HWND)lParam==hwndEdit)
			{
				SetTextColor((HDC)wParam,RGB(0xFF,0xFF,0xFF));
				SetBkMode((HDC)wParam, TRANSPARENT);
				return 0;
			}

		default:
			return DefWindowProc(hWnd, message, wParam, lParam); 
	}
	return NULL; 
}

int GetHookNameByIndex(LPWSTR str, DWORD pid, DWORD index);
HookWindow::HookWindow(HWND hDialog) : hDlg(hDialog)
{
	int i;
	HWND* t;
	t=&hcBigEndian;
	for (i=0;i<11;i++)
		t[i]=GetDlgItem(hDlg,IDC_CHECK1+i);
	t=&heAddr;
	for (i=0;i<8;i++)
		t[i]=GetDlgItem(hDlg,IDC_EDIT1+i);
	t=&hbModify;
	for (i=0;i<5;i++)
		t[i]=GetDlgItem(hDlg,IDC_BUTTON1+i);
	hText=GetDlgItem(hDlg,IDC_EDIT9);
	hCombo=GetDlgItem(hDlg,IDC_COMBO1);
}
bool HookWindow::IsBigEndian(){return IsDlgButtonChecked(hDlg,IDC_CHECK_BIGENDIAN)==BST_CHECKED;}
bool HookWindow::IsUnicode(){return IsDlgButtonChecked(hDlg,IDC_CHECK_UNICODE)==BST_CHECKED;}
bool HookWindow::IsString(){return IsDlgButtonChecked(hDlg,IDC_CHECK_STRING)==BST_CHECKED;}
bool HookWindow::IsDataInd(){return IsDlgButtonChecked(hDlg,IDC_CHECK_DATA_IND)==BST_CHECKED;}
bool HookWindow::IsSplit(){return IsDlgButtonChecked(hDlg,IDC_CHECK_SPLIT)==BST_CHECKED;}
bool HookWindow::IsSplitInd(){return IsDlgButtonChecked(hDlg,IDC_CHECK_SPLIT_IND)==BST_CHECKED;}
bool HookWindow::IsModule(){return IsDlgButtonChecked(hDlg,IDC_CHECK_MODULE)==BST_CHECKED;}
bool HookWindow::IsFunction(){return IsDlgButtonChecked(hDlg,IDC_CHECK_FUNCTION)==BST_CHECKED;}
bool HookWindow::IsHex(){return IsDlgButtonChecked(hDlg,IDC_CHECK_HEX)==BST_CHECKED;}
bool HookWindow::IsLastChar(){return IsDlgButtonChecked(hDlg,IDC_CHECK_LASTCHAR)==BST_CHECKED;}
bool HookWindow::IsNoContext(){return IsDlgButtonChecked(hDlg,IDC_CHECK_NOCONTEXT)==BST_CHECKED;}
void HookWindow::GenerateCode()
{
	WCHAR code[0x200];
	DWORD pid,i,addr;
	if (CB_ERR==SendMessage(hCombo,CB_GETCURSEL,0,0)) return;
	GetWindowText(hCombo,code,0x80);
	swscanf(code,L"%d:0x%x",&pid,&addr);
	HookParam hp;
	
	Hook* hks=(Hook*)man->RemoteHook(pid);
	for (i=0;i<MAX_HOOK;i++)
		if (hks[i].Address()==addr)
		{
			if (hks[i].Type()&EXTERN_HOOK)
				MessageBox(0,L"Special hook, no AGTH equivalent.",L"Warning",0);
			else
			{
				GetHookParam(hp);
				GetCode(hp,code,pid);
				SetDlgItemText(hDlg,IDC_EDIT9,code);
			}
			break;
		}
}
void HookWindow::GenerateHash(int ID)
{
	WCHAR str[0x20],text[0x80];
	GetDlgItemText(hDlg,IDC_EDIT8,text,0x80);
	if (ID==IDC_BUTTON3) _wcslwr(text);
	swprintf(str,L"%X",Hash(text));
	SetDlgItemText(hDlg,ID-6,str);
}
void HookWindow::GetHookParam(HookParam& hp)
{
	WCHAR str[0x80],code[0x80],*ptr;
	memset(&hp,0,sizeof(hp));
	ptr=code;
	if (IsNoContext()) hp.type|=NO_CONTEXT;
	if (IsHex()) {hp.type|=USING_UNICODE|PRINT_DWORD;hp.length_offset=0;}
	else if (IsUnicode())
	{
		hp.type|=USING_UNICODE;
		if (IsString()) hp.type|=USING_STRING;
		else 
		{
			hp.length_offset=1;
			if (IsLastChar()) hp.type|=STRING_LAST_CHAR;
		}
	}
	else
	{
		if (IsString()) hp.type|=USING_STRING;
		else
		{
			hp.length_offset=1;
			if (IsBigEndian()) hp.type|=BIG_ENDIAN;
			if (IsLastChar()) hp.type|=STRING_LAST_CHAR;
		}
	}
	GetWindowText(heAddr,str,0x80);
	swscanf(str,L"%x",&hp.addr);
	GetWindowText(heData,str,0x80);
	swscanf(str,L"%x",&hp.off);
	if (IsDataInd())
	{
		hp.type|=DATA_INDIRECT;
		GetWindowText(heDataInd,str,0x80);
		swscanf(str,L"%x",&hp.ind);
	}
	if (IsSplit())
	{
		hp.type|=USING_SPLIT;
		GetWindowText(heSplit,str,0x80);
		swscanf(str,L"%x",&hp.split);
	}
	if (IsSplitInd())
	{
		hp.type|=SPLIT_INDIRECT;
		GetWindowText(heSplitInd,str,0x80);
		swscanf(str,L"%x",&hp.split_ind);
	}
	if (IsModule())
		hp.type|=MODULE_OFFSET;
	GetWindowText(heModule,str,0x80);
	swscanf(str,L"%x",&hp.module);
	if (IsFunction())
		hp.type|=FUNCTION_OFFSET;
	GetWindowText(heFunction,str,0x80);
	swscanf(str,L"%x",&hp.function);
}
void HookWindow::ResetDialog(const HookParam &hp)
{
	WCHAR str[0x80];
	swprintf(str,L"%X",hp.addr);
	SetDlgItemText(hDlg,IDC_EDIT1,str);
	PrintSignDWORD(str,hp.off);
	SetDlgItemText(hDlg,IDC_EDIT2,str);
	PrintSignDWORD(str,hp.ind);
	SetDlgItemText(hDlg,IDC_EDIT3,str);
	PrintSignDWORD(str,hp.split);
	SetDlgItemText(hDlg,IDC_EDIT4,str);
	PrintSignDWORD(str,hp.split_ind);
	SetDlgItemText(hDlg,IDC_EDIT5,str);
	swprintf(str,L"%X",hp.module);
	SetDlgItemText(hDlg,IDC_EDIT6,str);
	swprintf(str,L"%X",hp.function);
	SetDlgItemText(hDlg,IDC_EDIT7,str);
	for (int i=0;i<11;i++)
		CheckDlgButton(hDlg,IDC_CHECK1+i,BST_UNCHECKED);
	for (int i=0;i<5;i++)
		EnableWindow(GetDlgItem(hDlg,IDC_EDIT3+i),TRUE);
	if (hp.type&NO_CONTEXT)
		CheckDlgButton(hDlg,IDC_CHECK11,BST_CHECKED);	
	if (hp.type&PRINT_DWORD)
		CheckDlgButton(hDlg,IDC_CHECK9,BST_CHECKED);
	if (hp.type&DATA_INDIRECT)
		CheckDlgButton(hDlg,IDC_CHECK4,BST_CHECKED);
	else
		EnableWindow(GetDlgItem(hDlg,IDC_EDIT3),FALSE);

	if (hp.type&USING_SPLIT)
		CheckDlgButton(hDlg,IDC_CHECK5,BST_CHECKED);
	else
		EnableWindow(GetDlgItem(hDlg,IDC_EDIT4),FALSE);

	if (hp.type&SPLIT_INDIRECT)
		CheckDlgButton(hDlg,IDC_CHECK6,BST_CHECKED);
	else
		EnableWindow(GetDlgItem(hDlg,IDC_EDIT5),FALSE);

	if (hp.type&MODULE_OFFSET)
		CheckDlgButton(hDlg,IDC_CHECK7,BST_CHECKED);
	else
		EnableWindow(GetDlgItem(hDlg,IDC_EDIT6),FALSE);

	if (hp.type&FUNCTION_OFFSET)
		CheckDlgButton(hDlg,IDC_CHECK8,BST_CHECKED);
	else
		EnableWindow(GetDlgItem(hDlg,IDC_EDIT7),FALSE);

	if (hp.type&BIG_ENDIAN) CheckDlgButton(hDlg,IDC_CHECK1,BST_CHECKED);
	if (hp.type&USING_UNICODE) CheckDlgButton(hDlg,IDC_CHECK2,BST_CHECKED);
	if (hp.type&USING_STRING) CheckDlgButton(hDlg,IDC_CHECK3,BST_CHECKED);
}
void HookWindow::ResetDialog(int index)
{
	if (index<0) return;
	DWORD pid,addr;
	WCHAR pwcEntry[0x100]={};
	int len=SendMessage(hCombo,CB_GETLBTEXT,index,(LPARAM)pwcEntry);
	swscanf(pwcEntry,L"%d:0x%x",&pid,&addr);
	man->LockProcessHookman(pid);
	Hook* hk=(Hook*)man->RemoteHook(pid);
	while (hk->Address()!=addr) hk++;
	HookParam hp;
	memcpy(&hp,hk,sizeof(hp));
	man->UnlockProcessHookman(pid);
	ResetDialog(hp);
}
void HookWindow::RemoveHook()
{
	WCHAR str[0x80]; DWORD pid; HANDLE hRemoved;
	int k=SendMessage(hCombo,CB_GETCURSEL,0,0);
	if (k==CB_ERR) return;
	hRemoved=IthCreateEvent(L"ITH_REMOVE_HOOK");
	SendParam sp={};
	sp.type=2;
	GetWindowText(hCombo,str,0x80);
	swscanf(str,L"%d:0x%x",&pid,&sp.hp.addr);
	cmdq->AddRequest(sp,pid);
	NtWaitForSingleObject(hRemoved,0,0);
	NtClose(hRemoved);
	man->RemoveSingleHook(pid,sp.hp.addr);
	SendMessage(hCombo,CB_DELETESTRING,k,0);
	SendMessage(hCombo,CB_SETCURSEL,0,0);
	ResetDialog(0);
}
void HookWindow::ModifyHook()
{
	DWORD pid; HANDLE hModify;
	WCHAR str[0x80];
	int k=SendMessage(hCombo,CB_GETCURSEL,0,0);
	if (k==CB_ERR) return;
	SendParam sp;
	hModify=IthCreateEvent(L"ITH_MODIFY_HOOK");
	GetWindowText(hCombo,str,0x80);
	swscanf(str,L"%d",&pid);
	GetHookParam(sp.hp);
	sp.type=3;
	cmdq->AddRequest(sp,pid);
	NtWaitForSingleObject(hModify,0,0);
	NtClose(hModify);
	man->RemoveSingleHook(pid,sp.hp.addr);
	SendMessage(hCombo,CB_DELETESTRING,k,0);
	SendMessage(hCombo,CB_SETCURSEL,0,0);
	ResetDlgHooks(pid, sp.hp);
	ResetDialog(sp.hp);
}
void HookWindow::ResetDlgHooks(DWORD pid, HookParam& hp)
	//hp.addr should be the target hook address.
{
	WCHAR str[0x200];
	LPWSTR ptr;
	DWORD len=0x1000;
	ProcessRecord* record=man->Records();
	SendMessage(hCombo,CB_RESETCONTENT,0,0);
	Hook *hks;
	int i,j,k;	
	for (j=0; record[j].pid_register; j++)
	{
		man->LockProcessHookman(record[j].pid_register);
		//index=(Hook*)man->RemoteHook(record[j].pid_register);
		hks=(Hook*)man->RemoteHook(record[j].pid_register);
		for (i=0;i<MAX_HOOK; i++)
		{
			if (hks[i].Address()==0) continue;
			ptr=str;
			ptr+=swprintf(ptr,L"%4d:0x%08X:",pid,hks[i].Address());
			GetHookNameByIndex(ptr,pid,i);
			//GetHookString(str,record[j].pid_register,index->Address(),index->Type());
			if (SendMessage(hCombo,CB_FINDSTRING,0,(LPARAM)str)==CB_ERR)
				k=SendMessage(hCombo,CB_ADDSTRING,0,(LPARAM)str);
			if (hp.addr==hks[i].Address()&&pid==record[j].pid_register)
			{
				memcpy(&hp,hks+i,sizeof(HookParam));
				SendMessage(hCombo,CB_SETCURSEL,k,0);
			}
		}
		man->UnlockProcessHookman(record[j].pid_register);
	}
}
void HookWindow::InitDlg()
{
	HookParam hp={};
	hp.addr=man->GetCurrentThread()->Addr();
	ResetDlgHooks(man->GetCurrentPID(), hp);
	ResetDialog(hp);
}
void HookWindow::PrintSignDWORD(LPWSTR str, DWORD d)
{
	if (d&0x80000000)
	{
		str[0]=L'-';
		swprintf(str+1,L"%X",-d);
	}
	else
		swprintf(str,L"%X",d);
}

ProcessWindow::ProcessWindow(HWND hDialog) : hDlg(hDialog)
{
	HWND* t;
	t=&hbRefresh;
	for (int i=0;i<5;i++)
		t[i]=GetDlgItem(hDlg,IDC_BUTTON1+i);
	EnableWindow(hbAddProfile,0);
	hlProcess=GetDlgItem(hDlg,IDC_LIST1);
	hlThread=GetDlgItem(hDlg,IDC_LIST2);
	heOutput=GetDlgItem(hDlg,IDC_EDIT1);
	heAddr=GetDlgItem(hDlg,IDC_EDIT2);
	t=&hrSuspend;
	for (int i=0;i<3;i++)
		t[i]=GetDlgItem(hDlg,IDC_RADIO1+i);
	ListView_SetExtendedListViewStyleEx(hlProcess,LVS_EX_FULLROWSELECT,LVS_EX_FULLROWSELECT);
	InitProcessDlg();
	RefreshProcess();
	
	ListView_SetExtendedListViewStyleEx(hlThread,LVS_EX_FULLROWSELECT,LVS_EX_FULLROWSELECT);
}
void ProcessWindow::InitProcessDlg()
{
	LVCOLUMN lvc={}; 
	lvc.mask = LVCF_FMT | LVCF_TEXT | LVCF_WIDTH; 
	lvc.fmt = LVCFMT_RIGHT;  // left-aligned column
	lvc.cx = 40;
	lvc.pszText = L"PID";	
	ListView_InsertColumn(hlProcess, 0, &lvc);
	lvc.cx = 60;
	lvc.pszText = L"Memory";	
	ListView_InsertColumn(hlProcess, 1, &lvc);
	lvc.cx = 100;
	lvc.fmt = LVCFMT_LEFT;  // left-aligned column
	lvc.pszText = L"Name";	
	ListView_InsertColumn(hlProcess, 2, &lvc);

	lvc.mask = LVCF_FMT | LVCF_TEXT | LVCF_WIDTH; 
	lvc.fmt = LVCFMT_LEFT;  // left-aligned column
	lvc.cx = 40;
	lvc.pszText = L"TID";	
	ListView_InsertColumn(hlThread, 0, &lvc);
	lvc.cx = 80;
	lvc.pszText = L"Start";	
	ListView_InsertColumn(hlThread, 1, &lvc);
	lvc.cx = 100;
	lvc.pszText = L"Module";	
	ListView_InsertColumn(hlThread, 2, &lvc);
	lvc.cx = 100;
	lvc.pszText = L"State";	
	ListView_InsertColumn(hlThread, 3, &lvc);
}
void ProcessWindow::RefreshProcess() 
{ 
	ListView_DeleteAllItems(hlProcess);
	ListView_DeleteAllItems(hlThread);
	LVITEM item={};
	item.mask = LVIF_TEXT | LVIF_PARAM | LVIF_STATE; 
	MyStack<HANDLE,0x100> stk;
	BYTE *pbBuffer=GetSystemInformation();
	if (pbBuffer==0) return;
	SYSTEM_PROCESS_INFORMATION *spiProcessInfo;
	HANDLE hProcess;
	DWORD ws,size,flag64,wow64;
	if (!NT_SUCCESS(NtQueryInformationProcess(NtCurrentProcess(),ProcessWow64Information,&flag64,4,0)))
		flag64=0;
	OBJECT_ATTRIBUTES attr={};
	CLIENT_ID id;
	WCHAR pwcBuffer[0x100];
	attr.uLength=sizeof(attr);
	id.UniqueThread=0;
	item.pszText=pwcBuffer;
	for (spiProcessInfo=(SYSTEM_PROCESS_INFORMATION*)pbBuffer; spiProcessInfo->dNext;)
	{
		spiProcessInfo=(SYSTEM_PROCESS_INFORMATION*)
			((DWORD)spiProcessInfo+spiProcessInfo->dNext);
		id.UniqueProcess=spiProcessInfo->dUniqueProcessId;
		if (NT_SUCCESS(NtOpenProcess(&hProcess,
			PROCESS_CREATE_THREAD|PROCESS_QUERY_INFORMATION|PROCESS_VM_READ|
			PROCESS_VM_WRITE|PROCESS_VM_OPERATION, &attr,&id)))
		{
			if (flag64)
				if (NT_SUCCESS(NtQueryInformationProcess(hProcess,ProcessWow64Information,&wow64,4,0)))
					if (wow64==0) 
					{
						NtClose(hProcess);
						continue;
					}
			stk.push_back(hProcess);
			swprintf(pwcBuffer,L"%d",spiProcessInfo->dUniqueProcessId);
			item.lParam=spiProcessInfo->dUniqueProcessId;
			ListView_InsertItem(hlProcess, &item);
			ListView_SetItemText(hlProcess,item.iItem,2,spiProcessInfo->usName.Buffer);
		}
	}
	while (stk.size())
	{
		GetProcessMemory(stk.back(),size,ws);
		swprintf(pwcBuffer,L"%dK", size);
		ListView_SetItemText(hlProcess,item.iItem++,1,pwcBuffer);
		NtClose(stk.back());
		stk.pop_back();
	}
	delete pbBuffer;
	EnableWindow(hbDetach,FALSE);
}
void ProcessWindow::AttachProcess()
{			
	LVITEM item={};
	item.mask=LVIF_PARAM;
	item.iItem=ListView_GetSelectionMark(hlProcess);
	ListView_GetItem(hlProcess,&item);
	if (InjectByPID(item.lParam)!=-1) 
	{
		SetWindowText(heOutput,L"Attach ITH to process successfully.");
		EnableWindow(hbDetach,TRUE);
		WCHAR path[MAX_PATH];
		EnableWindow(hbAddProfile,TRUE);
		if (GetProcessPath(item.lParam,path))
			if (pfman->IsPathProfile(path))
				EnableWindow(hbAddProfile,FALSE);
		EnableWindow(hbAttach,FALSE);
		RefreshThreadColumns(item.lParam);
	}
	else 
		SetWindowText(heOutput,L"Failed to attach ITH to process.");
}
void ProcessWindow::DetachProcess()
{
	DWORD pid=GetSelectPID();
	if (ActiveDetachProcess(pid)==0) 
	{
		SetWindowText(heOutput,L"ITH detach from process.");
		EnableWindow(hbDetach,FALSE);
		EnableWindow(hbAddProfile,FALSE);
		EnableWindow(hbAttach,TRUE);
		RefreshThreadColumns(pid);
	}
	else SetWindowText(heOutput,L"Detach failed.");
}
void ProcessWindow::OperateThread()
{
	int i,e;
	for (i=0; i<3&&IsDlgButtonChecked(hDlg,IDC_RADIO1+i)==BST_UNCHECKED; i++);
	if (i==3) return;
	ThreadOperation op=(ThreadOperation)i;
	LVITEM item={};
	item.mask=LVIF_PARAM;
	item.iItem=ListView_GetSelectionMark(hlProcess);
	ListView_GetItem(hlProcess,&item);
	DWORD pid=item.lParam;
	if (GetWindowTextLength(heAddr))
	{
		WCHAR text[0x10];
		DWORD addr;
		GetWindowText(heAddr,text,0xF);
		swscanf(text,L"%x",&addr);
		e=ListView_GetItemCount(hlThread);
		for (i=0;i<e;i++)
		{
			item.iItem=i;
			ListView_GetItem(hlThread,&item);
			PerformThread(0,item.lParam,op,addr);
		}
	}
	else
	{
		LVITEM item={};
		item.mask=LVIF_PARAM;
		item.iItem=ListView_GetSelectionMark(hlThread);
		if (item.iItem==-1) return;
		ListView_GetItem(hlThread,&item);
		PerformThread(0,item.lParam,op,0);
	}
	RefreshThreadColumns(pid);
}
void ProcessWindow::AddCurrentToProfile()
{
	LVITEM item={};
	item.mask=LVIF_PARAM;
	item.iItem=ListView_GetSelectionMark(hlProcess);
	ListView_GetItem(hlProcess,&item);
	WCHAR path[MAX_PATH];
	if (man->GetProcessPath(item.lParam,path))
	{
		if (pfman->IsPathProfile(path)) 
			SetWindowText(heOutput,L"Profile already exists.");
		else
		{
			Profile pf;
			pfman->AddProfile(path,pf);
			EnableWindow(hbAddProfile,0);
			SetWindowText(heOutput,L"Profile added");
			if (pfwnd) pfwnd->RefreshProfileList();
			SendParam sp={5};
			cmdq->AddRequest(sp,item.lParam);
		}
	}
	else SetWindowText(heOutput,L"Fail to add profile");
}
void ProcessWindow::RefreshThread(int index)
{
	WCHAR path[MAX_PATH];
	LVITEM item={};
	item.mask=LVIF_PARAM;
	item.iItem=index;
	ListView_GetItem(hlProcess,&item);
	RefreshThreadColumns(item.lParam);
	BOOL enable=man->GetHookManByPID(item.lParam)>0;
	EnableWindow(hbDetach,enable);
	EnableWindow(hbAttach,!enable);
	if (GetProcessPath(item.lParam,path))
		if (pfman->IsPathProfile(path)) enable=0;
	EnableWindow(hbAddProfile,enable);
	if (item.lParam==current_process_id) 
		EnableWindow(hbAttach,FALSE);
	SetWindowText(heOutput,L"");
}
void ProcessWindow::RefreshThreadColumns(DWORD pid)
{
	ListView_DeleteAllItems(hlThread);
	BYTE *pbBuffer=GetSystemInformation();
	if (pbBuffer==0) return;
	SYSTEM_PROCESS_INFORMATION *spiProcessInfo=GetBaseByPid(pbBuffer,pid);
	SYSTEM_THREAD* base;
	DWORD dwLimit;
	int i=0;
	if (spiProcessInfo)
	{
		base=(SYSTEM_THREAD*)((DWORD)spiProcessInfo+sizeof(SYSTEM_PROCESS_INFORMATION));
		dwLimit=(DWORD)spiProcessInfo->usName.Buffer;
		while ((DWORD)base<dwLimit)
		{
			PerformThread(base->Cid.UniqueProcess,base->Cid.UniqueThread);
			LPWSTR state= (base->dThreadState==StateWait)?				
				WaitReasonString[base->WaitReason] : StateString[base->dThreadState];
			ListView_SetItemText(hlThread, 0, 3, state);
			base++;
			i++;
		}
	}
	delete pbBuffer;
}
bool ProcessWindow::PerformThread(DWORD pid, DWORD tid, ThreadOperation op, DWORD addr)
{
	if (tid==0) return false;
	HANDLE hThread,hProc;
	CLIENT_ID id;
	NTSTATUS status;
	OBJECT_ATTRIBUTES att={};
	att.uLength=sizeof(att);
	id.UniqueProcess=pid;
	id.UniqueThread=tid;
	DWORD right=THREAD_QUERY_INFORMATION;
	switch(op)
	{
	case Suspend:
	case Resume:
		right|=THREAD_SUSPEND_RESUME;
		break;
	case	Terminate:
		right|=THREAD_TERMINATE;
		break;
	}
	if (!NT_SUCCESS(NtOpenThread(&hThread,right,&att,&id))) return false;
	THREAD_WIN32_START_ADDRESS_INFORMATION address;
	status=NtQueryInformationThread(hThread,ThreadQuerySetWin32StartAddress,&address,sizeof(address),0);
	if (!NT_SUCCESS(status)) return false;
	if (addr==0||addr==(DWORD)address.Win32StartAddress)
	{
		switch (op)
		{
		case OutputInformation:
		{
			LVITEM item={};
			item.mask = LVIF_TEXT | LVIF_PARAM | LVIF_STATE; 

			WCHAR name[0x100],str[0x100];
			item.pszText=str;
			id.UniqueProcess=pid;
			id.UniqueThread=0;
			if (!NT_SUCCESS(NtOpenProcess(&hProc,PROCESS_QUERY_INFORMATION,&att,&id)))
				return false;
			if (!NT_SUCCESS(NtQueryVirtualMemory(hProc,address.Win32StartAddress,
				MemorySectionName,name,0x200,0))) return false;

			swprintf(str,L"%d",tid);
			item.lParam=tid;
			ListView_InsertItem(hlThread, &item);
			swprintf(str,L"%X",address.Win32StartAddress);
			ListView_SetItemText(hlThread,item.iItem,1,str);
			ListView_SetItemText(hlThread,item.iItem,2,wcsrchr(name,L'\\')+1);
			status=0;
		}
		break;
		case Suspend:
			status=NtSuspendThread(hThread,0);
			break;
		case Resume:
			status=NtResumeThread(hThread,0);
			break;
		case Terminate:
			status=NtTerminateThread(hThread,0);
			break;
		}
		NtClose(hThread);
		NtClose(hProc);
	}
	return true;
}
DWORD ProcessWindow::GetSelectPID()
{
	LVITEM item={};
	item.mask=LVIF_PARAM;
	item.iItem=ListView_GetSelectionMark(hlProcess);
	ListView_GetItem(hlProcess,&item);
	return item.lParam;
}

ThreadWindow::ThreadWindow(HWND hDialog)
{
	hDlg=hDialog;
	hcCurrentThread=GetDlgItem(hDlg,IDC_COMBO1);
	hcLinkThread=GetDlgItem(hDlg,IDC_COMBO2);
	hlFromThread=GetDlgItem(hDlg,IDC_LIST1);
	heSentence=GetDlgItem(hDlg,IDC_EDIT1);
	heInfo=GetDlgItem(hDlg,IDC_EDIT2);
	heComment=GetDlgItem(hDlg,IDC_EDIT3);
	InitWindow();
}
void ThreadWindow::InitWindow()
{
	WCHAR entry_string[0x100];
	entry_string[0]=0;
	SetWindowText(heInfo,entry_string);
	SetWindowText(heSentence,entry_string);
	SendMessage(hcCurrentThread,CB_RESETCONTENT,0,0);
	SendMessage(hcLinkThread,CB_RESETCONTENT,0,0);
	SendMessage(hlFromThread,LB_RESETCONTENT,0,0);

	man->LockHookman();
	TextThread* it;
	ThreadTable* table=man->Table();
	for (int i=0;i<=table->Used();i++)
	{
		it=table->FindThread(i);
		if (it==0) continue;
		it->GetEntryString(entry_string);
		SendMessage(hcCurrentThread,CB_ADDSTRING,0,(LPARAM)entry_string);		
	}
	man->UnlockHookman();
	man->GetCurrentThread()->GetEntryString(entry_string);
	int i=SendMessage(hcCurrentThread,CB_FINDSTRING,0,(LPARAM)entry_string);
	SendMessage(hcCurrentThread,CB_SETCURSEL,i,0);
	InitThread(i);
}
void ThreadWindow::InitThread(int index)
{
	WCHAR entry_string[0x100]; WORD number,link_num;
	TextThread *it,*cur,*curl; DWORD num;
	SendMessage(hcCurrentThread,CB_GETLBTEXT,index,(LPARAM)entry_string);
	swscanf(entry_string,L"%X",&num);
	number=num&0xFFFF;
	man->LockHookman();
	cur=man->FindSingle(number);
	curl=cur->Link();
	cur->Link()=0;
	link_num=cur->LinkNumber();
	cur->LinkNumber()=-1;
	SendMessage(hlFromThread,LB_RESETCONTENT,0,0);
	SendMessage(hcLinkThread,CB_RESETCONTENT,0,0);
	SendMessage(hcLinkThread,CB_ADDSTRING,0,(LPARAM)L"_None");
	entry_string[0]=0;
	SetWindowText(heInfo,entry_string);
	SetWindowText(heSentence,entry_string);
	ThreadTable* table=man->Table();
	for (int i=0;i<=table->Used();i++)
	{
		it=table->FindThread(i);
		if (it==0) continue;
		swprintf(entry_string,L"%.4X",it->Number());
		if (it->LinkNumber()==number)
			SendMessage(hlFromThread,LB_ADDSTRING,0,(LPARAM)entry_string);
		if (!it->CheckCycle(cur)) 
			SendMessage(hcLinkThread,CB_ADDSTRING,0,(LPARAM)entry_string);
	}
	cur->Link()=curl;
	cur->LinkNumber()=link_num;
	if (curl)
	{
		swprintf(entry_string,L"%.4X",link_num);
		int i=SendMessage(hcLinkThread,CB_FINDSTRINGEXACT,0,(LPARAM)entry_string);
		if (i!=CB_ERR) 
		{
			SendMessage(hcLinkThread,CB_SETCURSEL,i,0);
			SetThreadInfo(i);
		}
	}
	else SendMessage(hcLinkThread,CB_SETCURSEL,0,0);
	SetLastSentence(number);
	man->UnlockHookman();
	SetWindowText(heComment,cur->GetComment());
}
void ThreadWindow::SetThreadInfo(int index)
{

	if (index==-1) return;
	WCHAR str[0x80]; 
	str[0]=0;
	if (index==0)
	{
		SetWindowText(heInfo,str);
		SetWindowText(heSentence,str);
		return;
	}
	int i,j=SendMessage(hcLinkThread,CB_GETLBTEXT,index,(LPARAM)str);
	swscanf(str,L"%X",&j);
	TextThread *it=man->FindSingle(j);
	if (it)
	{
		it->GetEntryString(str);
		SetWindowText(heInfo,str);
		str[0]=L'\r';
		str[1]=L'\n';
		while (it=it->Link())
		{
			i=GetWindowTextLength(heInfo);
			SendMessage(heInfo,EM_SETSEL,i,i);
			it->GetEntryString(str+2);
			SendMessage(heInfo,EM_REPLACESEL,0,(LPARAM)str+2);
		}
	}
	//SetWindowText(heInfo,str);
	SetLastSentence(j);
}
void ThreadWindow::RemoveLink(int index)
{
	WCHAR str[0x80];
	DWORD number;
	SendMessage(hlFromThread,LB_GETTEXT,index,(LPARAM)str);
	swscanf(str,L"%x",&number);
	TextThread* it=man->FindSingle(number);
	it->Link()=0;
	it->LinkNumber()=-1;
	SendMessage(hlFromThread,LB_DELETESTRING,index,0);
}
void ThreadWindow::SetThread()
{
	WCHAR str[0x280];
	DWORD from,to,index;
	index=SendMessage(hcCurrentThread,CB_GETCURSEL,0,0);
	SendMessage(hcCurrentThread,CB_GETLBTEXT,index,(LPARAM)str);
	swscanf(str,L"%x",&from);
	TextThread* it=man->FindSingle(from);
	index=SendMessage(hcLinkThread,CB_GETCURSEL,0,0);
	SendMessage(hcLinkThread,CB_GETLBTEXT,index,(LPARAM)str);
	if (str[0]==L'_')
	{
		it->Link()=0;
		it->LinkNumber()=-1;
	}
	else
	{
		swscanf(str,L"%x",&to);
		man->AddLink(from&0xFFFF,to&0xFFFF);
	}
	GetWindowText(heComment,str,0x200);
	it->RemoveFromCombo();
	if (wcslen(str))
		it->SetComment(str);
	it->AddToCombo();
	if (it->Status()&CURRENT_SELECT)
		it->ComboSelectCurrent();
}
void ThreadWindow::SetLastSentence(DWORD number)
{
	TextThread* it=man->FindSingle(number);
	WCHAR str[0x100];
	if (it)
	{
		it->CopyLastSentence(str);
		str[0xFF]=0;
		SetWindowText(heSentence,str);
	}
}
void ThreadWindow::ExportAllThreadText()
{
	WCHAR str_buffer[0x200];
	LPWSTR str,p,p1,p2;
	LARGE_INTEGER time;
	TIME_FIELDS tf;
	TextThread* it;
	str=str_buffer;
	if (GetWindowText(hwndProc,str,0x40))
	{
		str[0x3F]=L'.';
		for (;*str!=L'.';str++);
		*str=0;
		HANDLE h=IthCreateDirectory(str_buffer+5);
		if (INVALID_HANDLE_VALUE==h) return;
		NtClose(h);
	}
	ThreadTable* table=man->Table();
	NtQuerySystemTime(&time);
	IthSystemTimeToLocalTime(&time);
	RtlTimeToTimeFields(&time,&tf);
	*str++=L'\\';
	tf.wYear=tf.wYear%100;

	p=str+swprintf(str,L"%.2d%.2d%.2d-%.2d%.2d-",tf.wYear,tf.wMonth,tf.wDay,tf.wHour,tf.wMinute);
	man->LockHookman();
	for (int i=0;i<=table->Used();i++)
	{
		it=table->FindThread(i);
		if (it==0) continue;
		it->GetEntryString(p);
		p1=p+5;p2=p+0x2B;
		p[4]=L'-';
		while (*p2)
		{
			*p1=*p2;
			p1++;p2++;
		}
		p1[0]=L'.'; p1[1]=L't';
		p1[2]=L'x'; p1[3]=L't';
		p1[4]=0;
		it->ExportTextToFile(str_buffer+5);
	}
	man->UnlockHookman();
	MessageBox(0,L"Success. Text saved in ITH folder.",L"Success",0);
	p=str_buffer+5;
	p1=p;
	while (*p1&&*p1!=L'\\') p1++;
	if (*p1==0) return;
	*p1=0;
	ShellExecute(0,L"open",p,0,0,SW_SHOWNORMAL);
}
void ThreadWindow::ExportSingleThreadText()
{
	WCHAR entry_string[0x200]; 
	LPWSTR p1,p2;
	DWORD num,index;
	LARGE_INTEGER time;
	TIME_FIELDS tf;
	TextThread* it;
	ThreadTable* table=man->Table();
	NtQuerySystemTime(&time);
	IthSystemTimeToLocalTime(&time);
	RtlTimeToTimeFields(&time,&tf);
	index=SendMessage(hcCurrentThread,CB_GETCURSEL,0,0);
	SendMessage(hcCurrentThread,CB_GETLBTEXT,index,(LPARAM)entry_string);
	swscanf(entry_string,L"%X",&num);
	man->LockHookman();
	it=table->FindThread(num);
	tf.wYear=tf.wYear%100;
	if (it)
	{
		p1=entry_string+swprintf(entry_string,L"%.2d%.2d%.2d-%.2d%.2d-%.4X-",
			tf.wYear,tf.wMonth,tf.wDay,tf.wHour,tf.wMinute,num);
		p2=entry_string+0x2B;
		while (*p2)
		{
			*p1=*p2;
			p1++;p2++;
		}
		p1[0]=L'.';
		p1[1]=L't';
		p1[2]=L'x';
		p1[3]=L't';
		p1[4]=0;
		//wcscpy(p1,entry_string+0x2B);
		//it->GetEntryString(p);
		it->ExportTextToFile(entry_string);
	}
	man->UnlockHookman();
	MessageBox(0,L"Success. Text saved in ITH folder.",L"Success",0);
	ShellExecute(0,L"open",L"",0,0,SW_SHOWNORMAL);
}

ProfileWindow::ProfileWindow(HWND hDialog)
{
	hDlg=hDialog;
	hlProfileList=GetDlgItem(hDlg,IDC_LIST1);
	hlThread=GetDlgItem(hDlg,IDC_LIST2);
	hlLink=GetDlgItem(hDlg,IDC_LIST3);
	hlComment=GetDlgItem(hDlg,IDC_LIST4);
	hcbSelect=GetDlgItem(hDlg,IDC_COMBO1);
	hePath=GetDlgItem(hDlg,IDC_EDIT1);
	heHook1=GetDlgItem(hDlg,IDC_EDIT2);
	heHook2=GetDlgItem(hDlg,IDC_EDIT3);
	heHook3=GetDlgItem(hDlg,IDC_EDIT4);
	heHook4=GetDlgItem(hDlg,IDC_EDIT5);
	hcHook1=GetDlgItem(hDlg,IDC_CHECK1);
	hcHook2=GetDlgItem(hDlg,IDC_CHECK2);
	hcHook3=GetDlgItem(hDlg,IDC_CHECK3);
	hcHook4=GetDlgItem(hDlg,IDC_CHECK4);
	hbStart=GetDlgItem(hDlg,IDC_BUTTON1);
	hbDelete=GetDlgItem(hDlg,IDC_BUTTON2);
	hbSave=GetDlgItem(hDlg,IDC_BUTTON3);
	ListView_SetExtendedListViewStyleEx(hlProfileList,LVS_EX_FULLROWSELECT,LVS_EX_FULLROWSELECT);
	LVCOLUMN lvc={}; 
	lvc.mask = LVCF_FMT | LVCF_TEXT | LVCF_WIDTH; 
	lvc.fmt = LVCFMT_RIGHT;  // left-aligned column
	lvc.cx = 30;
	lvc.pszText = L"No.";	
	ListView_InsertColumn(hlProfileList, 0, &lvc);
	lvc.cx = 40;
	lvc.pszText = L"PID";	
	ListView_InsertColumn(hlProfileList, 1, &lvc);
	lvc.cx = 100;
	lvc.fmt = LVCFMT_LEFT;  // left-aligned column
	lvc.pszText = L"Name";	
	ListView_InsertColumn(hlProfileList, 2, &lvc);
	RefreshProfileList();
	ResetProfileWindow();
}
void ProfileWindow::RefreshProfileList()
{
	ListView_DeleteAllItems(hlProfileList);
	if (hEditProfileDlg) EndDialog(hEditProfileDlg,0);
	ProfileNode* it=pfman->BeginProfile();
	LPWSTR name; WCHAR buff[0x20];
	LVITEM item={};
	item.mask = LVIF_TEXT | LVIF_STATE | LVIF_PARAM; 
	for (int i=0;it;i++)
	{
		item.pszText=buff;
		swprintf(buff,L"%d",i);
		item.iItem=i;
		name=wcsrchr(it->key,L'\\');
		if (name==0) name=it->key;
		else name++;
		item.lParam=man->GetProcessIDByPath(it->key);
		ListView_InsertItem(hlProfileList, &item);
		if (item.lParam)
		{
			swprintf(buff,L"%d",item.lParam);
			ListView_SetItemText(hlProfileList,item.iItem,1,buff);
		}
		ListView_SetItemText(hlProfileList,item.iItem,2,name);
		it=it->Successor();
	}
}
void ProfileWindow::ResetProfile(int index)
{
	LVITEM item={};
	item.mask=LVIF_PARAM;
	item.iItem=index;
	ListView_GetItem(hlProfileList,&item);
	EnableWindow(hbStart,item.lParam==0);
	WCHAR code[0x300];
	SendMessage(hePath,EM_SETSEL,0,-1);
	ProfileNode* pfn=pfman->GetProfile(index);
	Profile temp;
	Profile *pf;
	
	if (pfn==0)
	{
		SetWindowText(hePath,L"");
		pf=&temp;
	}
	else
	{
		pf=&pfn->data;
		SendMessage(hePath,EM_SETSEL,0,-1);
		SendMessage(hePath,EM_REPLACESEL,FALSE,(LPARAM)pfn->key);
	}
	
	HWND *heHook=&heHook1;
	for (index=0;index<pf->hook_count;index++)
	{
		GetCode(pf->hps[index],code);
		EnableWindow(heHook[index],TRUE);
		SetWindowText(heHook[index],code);
		CheckDlgButton(hDlg,IDC_CHECK1+index,BST_CHECKED);
	}
	for (;index<4;index++)
	{
		EnableWindow(heHook[index],FALSE);
		SetWindowText(heHook[index],0);
		CheckDlgButton(hDlg,IDC_CHECK1+index,BST_UNCHECKED);
	}
	SendMessage(hlThread,LB_RESETCONTENT,0,0);
	SendMessage(hcbSelect,CB_RESETCONTENT,0,0);
	for (index=0;index<pf->thread_count;index++)
	{
		LPWSTR str=code;
		str+=swprintf(str,L"%.4X:",index);
		GetThreadString(pf->threads+index,str);
		SendMessage(hlThread,LB_ADDSTRING,0,(LPARAM)code);
		SendMessage(hcbSelect,CB_ADDSTRING,0,(LPARAM)code);
	}
	SendMessage(hcbSelect,CB_SETCURSEL,pf->select_index-1,0);
	SendMessage(hlThread,LB_ADDSTRING,0,(LPARAM)L"...");
	SendMessage(hlComment,LB_RESETCONTENT,0,0);
	for (index=0;index<pf->comment_count;index++)
	{
		CommentParam* cp=pf->comments+index;
		swprintf(code,L"%.4X:%.4X:%s",index,cp->thread_index-1,cp->comment);
		SendMessage(hlComment,LB_ADDSTRING,0,(LPARAM)code);
	}
	SendMessage(hlComment,LB_ADDSTRING,0,(LPARAM)L"...");
	SendMessage(hlLink,LB_RESETCONTENT,0,0);
	for (index=0;index<pf->link_count;index++)
	{
		LinkParam* lp=pf->links+index;
		swprintf(code,L"%.4X:%.4X->%.4X",index,lp->from_index-1,lp->to_index-1);
		SendMessage(hlLink,LB_ADDSTRING,0,(LPARAM)code);
	}
	SendMessage(hlLink,LB_ADDSTRING,0,(LPARAM)L"...");
}
void ProfileWindow::ResetProfileWindow(int index)
{
	WCHAR str[]=L"";
	ListView_SetSelectionMark(hlProfileList,index);
	if (index>=0) 
	{
		ResetProfile(index);
		return;
	}
	HWND *heHook,*hcHook;
	heHook=&heHook1;hcHook=&hcHook1;
	SetWindowText(hePath,str);
	for (index=0;index<4;index++)
	{
		SetWindowText(heHook[index],str);
		EnableWindow(heHook[index],0);
		CheckDlgButton(hDlg,IDC_CHECK1+index,BST_UNCHECKED);
	}
}
void ProfileWindow::StartProfileProcess()
{
	int index=ListView_GetSelectionMark(hlProfileList);
	if (index==-1) return;
	LVITEM item={};
	item.mask=LVIF_PARAM;
	item.iItem=index;
	ListView_GetItem(hlProfileList,&item);
	if (item.lParam) return;
	ProfileNode* pfn=pfman->GetProfile(index);
	if (pfn) 
	{
		WCHAR path[MAX_PATH]=L"\\??\\"; 
		wcscpy(path+4,pfn->key);
		if (IthCheckFileFullPath(path)==0)
		{
			man->AddConsoleOutput(L"Can't find file");
			return;
		}
		LPWSTR p;
		STARTUPINFO sin={sizeof(sin)};
		PROCESS_INFORMATION pin;
		p=wcsrchr(path,L'\\');
		p[1]=0;
		if (CreateProcess(pfn->key,0,0,0,0,0,0,path+4,&sin,&pin))
		{
			EnableWindow(hbStart,0);
			NtClose(pin.hProcess);
			NtClose(pin.hThread);
		}
	}
}
void ProfileWindow::SetCurrentProfile(Profile* pf)
{
	WCHAR path[MAX_PATH];
	LPWSTR ts;

	pf->ClearHooks();
	HWND *heHook=&heHook1;
	HookParam hp;
	for (int i=0;i<4;i++)
	{
		if (IsHook(i)==false) continue;
		GetWindowText(heHook[i],path,MAX_PATH);
		 ts=wcsrchr(path,L':');
		if (ts) *ts=0;
		_wcslwr(path);
		if (ts) *ts=L':';
		if (Parse(path+2,hp)) pf->AddHook(hp);
	}
}
void ProfileWindow::SaveCurrentProfile()
{
	int index=ListView_GetSelectionMark(hlProfileList);
	if (index==-1) return;
	Profile* pf=&pfman->GetProfile(index)->data;
	SetCurrentProfile(pf);
	pf->select_index=(SendMessage(hcbSelect,CB_GETCURSEL,0,0)&0xFFFF)+1;
	pfman->SaveProfile();
	ResetProfileWindow(index);
}
void ProfileWindow::DeleteCurrentProfile()
{
	int count,index;
	index=ListView_GetSelectionMark(hlProfileList);
	if (index==-1) return;
	count=ListView_GetItemCount(hlProfileList)-1;
	pfman->DeleteProfile(index);
	WCHAR digit[0x10];
	ListView_DeleteItem(hlProfileList,index);
	count=index<count?index:count;
	for (;index<count;index++)
	{
		swprintf(digit,L"%d",index);
		ListView_SetItemText(hlProfileList, index, 0, digit);
	}
	ResetProfileWindow(count);
}
void ProfileWindow::ExportCurrentProfile()
{
	int index=ListView_GetSelectionMark(hlProfileList);
	if (index==-1) return;
	HANDLE hFile=IthPromptCreateFile(GENERIC_WRITE,FILE_SHARE_READ,FILE_OVERWRITE_IF);
	MyVector<WCHAR,0x1000,WCMP> export_text;
	ProfileNode* pfn=pfman->GetProfile(index);
	WCHAR bom=0xFEFF;
	export_text.AddToStore(&bom,1);
	if (hFile!=INVALID_HANDLE_VALUE&&pfn!=0)
	{
		ExportSingleProfile(pfn,export_text);
		export_text.AddToStore(L"#",1);
		IO_STATUS_BLOCK ios;
		NtWriteFile(hFile,0,0,0,&ios,export_text.Storage(),export_text.Used()<<1,0,0);
		NtClose(hFile);
	}
}
void ProfileWindow::ExportAllProfile()
{
	int index,count=ListView_GetItemCount(hlProfileList);
	HANDLE hFile=IthPromptCreateFile(GENERIC_WRITE,FILE_SHARE_READ,FILE_OVERWRITE_IF);
	if (hFile==INVALID_HANDLE_VALUE) return;
	MyVector<WCHAR,0x1000,WCMP> export_text;
	WCHAR bom=0xFEFF;
	export_text.AddToStore(&bom,1);
	for (index=0;index<count;index++)
	{
		ProfileNode* pfn=pfman->GetProfile(index);
		ExportSingleProfile(pfn,export_text);
	}
	export_text.AddToStore(L"#",1);
	IO_STATUS_BLOCK ios;
	NtWriteFile(hFile,0,0,0,&ios,export_text.Storage(),export_text.Used()<<1,0,0);
	NtClose(hFile);
}
void ProfileWindow::ImportCurrentProfile()
{
	int index=ListView_GetSelectionMark(hlProfileList);
	if (index==-1) return;
	if (DialogBoxParam(hIns,(LPCWSTR)IDD_DIALOG9,0,ImportProfileDlgProc,0))
	{
		if (import_buffer==0) return;
		ProfileNode* pfn=pfman->GetProfile(index);
		Profile pf;
		if (pfn==0) return;
		LPWSTR str=import_buffer,str1,str2;
		WCHAR left=L'[';
		DWORD flag=0;
		while (*str!=left) str++;

		if (memcmp(str,L"[ITH 2.2]",18)!=0) return;
		str+=9;
		while (*str!=left) str++;
		str2=str;
		while (*str2!=L'\\') str2--;
		if (wcsstr(str2,wcsrchr(pfn->key,L'\\'))==0)
			if (MessageBox(0,L"Process name dismatch, continue?",L"Warning",1)==IDCANCEL) return;
		*str=left;

		if (memcmp(str,L"[UserHook]",20)!=0) return;
		HookParam hp;
		str+=10;
		str1=str;
		flag=0;
		while (*str1!=left) str1++;
		for (;;)
		{
			while (str<str1&&*str!=L'/') str++;
			if (str>=str1||flag>3) break;
			str2=str;
			while (*str2!=L'\n') str2++;
			*str2=0;
			Parse(_wcslwr(str)+2,hp);
			pf.AddHook(hp);
			flag++;
			str=str2;
		}		

		str=str1;						
		flag=0;
		if (memcmp(str,L"[Thread]",16)!=0) return;
		str+=8;
		str1=str;
		while (*str1!=left) str1++;
		for (;;)
		{
			while (*str<=0x20) str++;
			if (str>=str1) break;
			str2=str;
			while (*str2!=L'\n') str2++;
			*str2=0;
			ThreadParam tp;
			if (swscanf(str,L"%x:%x",&flag,&tp.hook_index)!=2) return;
			str+=10;
			if (*str==L'X') {str+=4;tp.status|=THREAD_MASK_RETN;}
			if (swscanf(str,L"%x",&tp.retn)==0) return;
			while (*str!=L':') str++;
			str++;
			if (*str==L'X') {str+=4;tp.status|=THREAD_MASK_SPLIT;}
			if (swscanf(str,L"%x",&tp.split)==0) return;
			pf.AddThread(&tp);
			str=str2;
		}

		str=str1;						
		flag=0;
		if (memcmp(str,L"[Link]",12)!=0) return;
		str+=6;
		str1=str;
		while (*str1!=left) str1++;
		for (;;)
		{
			while (*str<=0x20) str++;
			if (str>=str1) break;
			str2=str;
			while (*str2!=L'\n') str2++;
			*str2=0;
			LinkParam lp;
			DWORD from,to;
			if (swscanf(str,L"%x:%x->%x",&flag,&from,&to)!=3) return;
			lp.from_index=(from+1)&0xFFFF;
			lp.to_index=(to+1)&0xFFFF;
			pf.AddLink(&lp);
			str=str2;
		}

		str=str1;						
		flag=0;
		if (memcmp(str,L"[Comment]",18)!=0) return;
		str+=9;
		str1=str;
		while (*str1!=left) str1++;
		for (;;)
		{
			while (*str<=0x20) str++;
			if (str>=str1) break;
			str2=str;
			while (*str2!=L'\n') str2++;
			*str2=0;
			int thread_index;
			if (swscanf(str,L"%X:%X",&flag,&thread_index)!=2) return;
			thread_index++;
			str+=10;
			pf.AddComment(str,thread_index);
			str=str2+1;
		}

		str=str1;
		if (memcmp(str,L"[Select]",16)!=0) return;
		str+=8;
		while (*str<20&&*str) str++;
		if (swscanf(str,L"%x",&flag)!=1) return;
		pf.select_index=(flag+1)&0xFFFF;
		MessageBox(0,L"Success",L"Success",0);
		pfn->data=pf;
		
		flag=man->GetProcessIDByPath(pfn->key);
		if (flag)
			pfman->RefreshProfileAddr(flag,pfn->key);
		ResetProfile(index);
	}
}
void ProfileWindow::DeleteItem(int last_select)
{
	HWND h=GetFocus();
	if (h==hlProfileList)
	{
		DeleteCurrentProfile();
		return;
	}
	Profile* pf=GetCurrentProfile();
	if (pf==0) return;
	int i,j;
	i=last_select;
	if (h==hlThread)
	{		
		j=SendMessage(hlThread,LB_GETCOUNT,0,0);
		if (i>=0&&i!=j-1)
			pf->RemoveThread(i);
	}
	else if (h==hlLink)
	{
		j=SendMessage(hlLink,LB_GETCOUNT,0,0);
		if (i>=0&&i!=j-1)
			pf->RemoveLink(i);
	}
	else if (h==hlComment)
	{
		j=SendMessage(hlComment,LB_GETCOUNT,0,0);
		if (i>=0&&i!=j-1)
			pf->RemoveComment(i);
	}
	j=ListView_GetSelectionMark(hlProfileList);
	ResetProfile(j);
}
void ProfileWindow::CheckHook(int index, bool check)
{
	CheckDlgButton(hDlg,IDC_CHECK1+index,check);
	HWND *heHook=&heHook1;
	EnableWindow(heHook[index],check);
}
bool ProfileWindow::IsHook(int index)
{
	return IsDlgButtonChecked(hDlg,IDC_CHECK1+index)==BST_CHECKED;
}
Profile* ProfileWindow::GetCurrentProfile()
{
	int index=ListView_GetSelectionMark(hlProfileList);
	if (index==-1) return 0;
	ProfileNode* pfn=pfman->GetProfile(index);
	if (pfn==0) return 0;
	return &pfn->data;
}
DWORD ProfileWindow::GetCurrentSelect()
{
	int index=ListView_GetSelectionMark(hlProfileList);
	LVITEM item={};
	item.mask=LVIF_PARAM;
	item.iItem=index;
	ListView_GetItem(hlProfileList,&item);
	return (DWORD)item.lParam;
}
DWORD WINAPI UpdateWindows(LPVOID lpThreadParameter)
{
	EnterCriticalSection(&update_cs);
	if (hkwnd) hkwnd->InitDlg();
	if (pfwnd) pfwnd->RefreshProfileList();
	LeaveCriticalSection(&update_cs);
	return 0;
}

class IthGlyph
{
public:
	IthGlyph(HDC hdc):hDC(hdc), glyph_buffer(0), hBmp(0)
	{
		hMemDC=CreateCompatibleDC(hdc);
	}
	~IthGlyph()
	{
		if (hBmp) DeleteObject(hBmp);
		if (hMemDC) DeleteDC(hMemDC);
		if (glyph_buffer) delete glyph_buffer;
		glyph_buffer=0;
		glyph_char=0;
		hMemDC=0;
		hBmp=0;
		hDC=0;
	}
	int InitGlyph(wchar_t ch)
	{
		DWORD len,i,ii,j,k,t;
		BYTE *buffer,*bptr;
		LPVOID ptr;
		MAT2 mt={};
		glyph_char=ch;
		mt.eM11.value=1;
		mt.eM22.value=-1;

		len=GetGlyphOutline(hDC,ch,GGO_GRAY8_BITMAP,&gm,0,0,&mt);
		if (len<=0) return -1;
		glyph_buffer=new BYTE[len];
		len=GetGlyphOutline(hDC,ch,GGO_GRAY8_BITMAP,&gm,len,glyph_buffer,&mt);
		if (len==-1) return -1;	
		BITMAPINFOHEADER info={sizeof(info),gm.gmBlackBoxX,gm.gmBlackBoxY,1,32,BI_RGB,0,0,0,0,0};
		hBmp=CreateDIBSection(hMemDC,(BITMAPINFO*)&info,DIB_RGB_COLORS,&ptr,0,0);
		buffer=(BYTE*)ptr;
		bptr=glyph_buffer;
		k=(gm.gmBlackBoxX+3)&~3;t=0;ii=0;
		for (i=0;i<gm.gmBlackBoxY;i++)
		{
			for (j=0;j<gm.gmBlackBoxX;j++)
			{
				bptr[j]=64-bptr[j];
				if (bptr[j]) 
					buffer[0]=buffer[1]=buffer[2]=(bptr[j]<<2)-1;
				buffer+=4;
			}
			bptr+=k;
		}
		SelectObject(hMemDC,hBmp);
		return 0;
	}
	int DrawGlyph(HDC hdc, int x, int y, int height)
	{
		if (glyph_buffer==0) return -1;
		return BitBlt(hdc, x+gm.gmptGlyphOrigin.x, y+height-gm.gmBlackBoxY+gm.gmptGlyphOrigin.y, 
			gm.gmBlackBoxX, gm.gmBlackBoxY, hMemDC, 0, 0, SRCCOPY);
	}
private:
	HDC hDC, hMemDC;
	HBITMAP hBmp;
	UINT glyph_char;
	GLYPHMETRICS gm;
	BYTE* glyph_buffer;
};

LRESULT CALLBACK EditCharProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	switch (message)
	{
	case WM_PASTE:
		{
			HGLOBAL   hglb; 
			LPWSTR    lpwstr; 

			if (!IsClipboardFormatAvailable(CF_UNICODETEXT)) break;
			if (!OpenClipboard(0)) break;
			hglb = GetClipboardData(CF_UNICODETEXT); 
			if (hglb != NULL) 
			{ 
				lpwstr = (LPWSTR)GlobalLock(hglb); 
				if (lpwstr != NULL) 
				{ 
					// Call the application-defined ReplaceSelection 
					// function to insert the text and repaint the 
					// window. 
					ftwnd->InitWithChar(lpwstr[0]);
					GlobalUnlock(hglb); 
				} 
			} 
			CloseClipboard(); 
			return 0;
		}
	case WM_CHAR:
		if (wParam>=0x20)
		{
			ftwnd->InitWithChar(wParam);
			return 0;
		}
	default:
		break;
	}
	return CallWindowProc(procChar,hWnd,message,wParam,lParam);
}
void InsertUniChar(WORD uni_char)
{
	ftwnd->SetUniChar(uni_char);
}
void InsertMBChar(WORD mb_char)
{
	ftwnd->SetMBChar(mb_char);
}
FilterWindow::FilterWindow(HWND hDialog)
{
	modify=remove=commit=0;
	hDlg=hDialog;
	hList=GetDlgItem(hDlg,IDC_LIST1);
	hGlyph=GetDlgItem(hDlg,IDC_STATIC1);
	hSJIS=GetDlgItem(hDlg,IDC_EDIT6);
	hUnicode=GetDlgItem(hDlg,IDC_EDIT7);
	hChar=GetDlgItem(hDlg,IDC_EDIT8);
	procChar=(WNDPROC)SetWindowLongPtr(hChar,GWL_WNDPROC,(LONG_PTR)EditCharProc);
	ListView_SetExtendedListViewStyleEx(hList,LVS_EX_FULLROWSELECT,LVS_EX_FULLROWSELECT);
	ListView_DeleteAllItems(hList);
	LVCOLUMN lvc={}; 
	lvc.mask = LVCF_FMT | LVCF_TEXT | LVCF_WIDTH; 
	lvc.fmt = LVCFMT_LEFT;  // left-aligned column
	lvc.cx = 35;
	lvc.pszText = L"Char";	
	ListView_InsertColumn(hList, 0, &lvc);
	lvc.cx = 50;
	lvc.pszText = L"SJIS";	
	ListView_InsertColumn(hList, 1, &lvc);
	lvc.cx = 100;
	lvc.fmt = LVCFMT_LEFT;  // left-aligned column
	lvc.pszText = L"Unicode";	
	ListView_InsertColumn(hList, 2, &lvc);

	hGlyphFont=CreateFont( 64, 0, 0, 0, FW_THIN, FALSE, FALSE, FALSE, SHIFTJIS_CHARSET, OUT_DEFAULT_PRECIS, 
		CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"MS Mincho" );
	hGlyphDC=GetDC(hGlyph);
	SelectObject(hGlyphDC,hGlyphFont);
	white=CreateSolidBrush(RGB(0xFF,0xFF,0xFF));
	GetTextMetrics(hGlyphDC,&tm);
	GetClientRect(hGlyph,&rc);
	init_x=(rc.right-tm.tmMaxCharWidth)/2;
	init_y=0;
}
FilterWindow::~FilterWindow()
{
	WCHAR buffer[8];
	WCHAR filter_unichar[2];
	char filter_mbchar[4];
	ReleaseDC(hGlyph,hGlyphDC);
	DeleteObject(white);
	DeleteObject(hGlyphFont);
	if (uni_filter&&mb_filter&&commit)
	{
		if (modify)
		{
			LVITEM item={};
			LVITEM sub={};
			int i,count=ListView_GetItemCount(hList);
			item.mask=LVIF_TEXT;
			item.cchTextMax=2;
			item.pszText=filter_unichar;
			sub.mask=LVIF_TEXT;
			sub.cchTextMax=8;
			sub.pszText=buffer;
			if (remove)
			{
				uni_filter->Reset();
				mb_filter->Reset();
				for (i=0;i<count;i++)
				{
					item.iItem=i;
					ListView_GetItem(hList,&item);
					filter_unichar[1]=0;
					WC_MB(filter_unichar,filter_mbchar);
					sub.iSubItem=1;
					SendMessage(hList, LVM_GETITEMTEXT, (WPARAM)(i), (LPARAM)(LV_ITEM *)&sub);
					if (buffer[4]==L'+') uni_filter->Set(filter_unichar[0]);
					sub.iSubItem=2;
					SendMessage(hList, LVM_GETITEMTEXT, (WPARAM)(i), (LPARAM)(LV_ITEM *)&sub);
					if (buffer[4]==L'+') mb_filter->Set(*(WORD*)filter_mbchar);
				}
			}
			else
			{
				for (i=0;i<count;i++)
				{
					item.iItem=i;
					ListView_GetItem(hList,&item);
					filter_unichar[1]=0;
					WC_MB(filter_unichar,filter_mbchar);
					sub.iSubItem=1;
					SendMessage(hList, LVM_GETITEMTEXT, (WPARAM)(i), (LPARAM)(LV_ITEM *)&sub);
					if (buffer[4]==L'+') uni_filter->Set(filter_unichar[0]);
					else uni_filter->Clear(filter_unichar[0]);
					sub.iSubItem=2;
					SendMessage(hList, LVM_GETITEMTEXT, (WPARAM)(i), (LPARAM)(LV_ITEM *)&sub);
					if (buffer[4]==L'+') mb_filter->Set(*(WORD*)filter_mbchar);
					else mb_filter->Clear(*(WORD*)filter_mbchar);
				}
			}
		}
	}
}
void FilterWindow::Init()
{
	WCHAR uni_char[8],buffer[8];
	union {DWORD mbd;WORD mbw[2];char mbc[4];BYTE mbb[4];};
	uni_filter->Traverse(InsertUniChar);
	mb_filter->Traverse(InsertMBChar);
	DWORD count,index;
	LVITEM item={};
	item.mask=LVIF_TEXT;
	item.cchTextMax=8;
	item.pszText=buffer;
	mbd=0;
	count=ListView_GetItemCount(hList);
	for (index=0;index<count;index++)
	{
		ListView_GetItemText(hList,index,0,uni_char,8);
		item.iSubItem=1;
		if (SendMessage(hList,LVM_GETITEMTEXT,index,(LPARAM)&item)==0)
		{
			WC_MB(uni_char,mbc);
			mbw[0]=_rotl16(mbw[0],(LeadByteTable[mbb[0]]-1)<<3);
			swprintf(buffer,L"%.4X-",mbd);
			SendMessage(hList,LVM_SETITEMTEXT,index,(LPARAM)&item);
		}
		else
		{
			item.iSubItem=2;
			if (SendMessage(hList,LVM_GETITEMTEXT,index,(LPARAM)&item)==0)
			{
				swprintf(buffer,L"%.4X-",uni_char[0]);
				SendMessage(hList,LVM_SETITEMTEXT,index,(LPARAM)&item);
			}
		}

	}
}
void FilterWindow::DeleteCurrentChar()
{
	WCHAR buffer[4];
	DWORD index=ListView_GetSelectionMark(hList);
	if (-1==index) 
	{
		MessageBox(0,L"Select one item first.",0,0);
		return;
	}
	ListView_DeleteItem(hList,index);
	buffer[0]=0;
	SetWindowText(hSJIS,buffer);
	SetWindowText(hUnicode,buffer);
	SetWindowText(hChar,buffer);
	FillRect(hGlyphDC,&rc,white);
	remove=1;modify=1;
}
void FilterWindow::AddNewChar()
{
	WCHAR buffer[8];
	DWORD uni,index;
	if (GetWindowText(hChar,buffer,8)==0)
	{
		MessageBox(0,L"No character.",0,0);
		return;
	}
	uni=buffer[0];
	LVFINDINFO find={LVFI_STRING,buffer};
	index=ListView_FindItem(hList,0,&find);
	if (index!=-1)
	{
		ListView_SetSelectionMark(hList,index);
		SetCurrentChar();
		return;
	}
	LVITEM item={};
	item.mask=LVIF_TEXT;
	item.cchTextMax=2;
	item.pszText=buffer;
	index=ListView_InsertItem(hList,&item);
	if (-1==index) return;
	item.iItem=index;
	GetWindowText(hSJIS,buffer,8);
	if (IsSJISCheck()) buffer[4]=L'+';
	else buffer[4]=L'-';
	buffer[5]=0;
	ListView_SetItemText(hList,index,1,buffer);
	GetWindowText(hUnicode,buffer,8);
	if (IsUnicodeCheck()) buffer[4]=L'+';
	else buffer[4]=L'-';
	buffer[5]=0;
	ListView_SetItemText(hList,index,2,buffer);
	modify=1;
}
void FilterWindow::SetCurrentChar()
{
	WCHAR buffer[8];
	DWORD unichar,index,index_duplicate,flag_uni,flag_mb;
	GetWindowText(hChar,buffer,8);
	unichar=buffer[0];	
	index=ListView_GetSelectionMark(hList);
	if (-1==index) 
	{
		MessageBox(0,L"Select one item first.",0,0);
		return;
	}
	LVFINDINFO find={LVFI_STRING,buffer};
	index_duplicate=ListView_FindItem(hList,0,&find);
	LV_ITEM item={};
	if (index_duplicate!=-1)
	{
		if (index!=index_duplicate)
		{
			DeleteCurrentChar();
			if (index<index_duplicate) index_duplicate--;
			index=index_duplicate;
		}

	}
	modify=1;
	item.pszText=buffer+4;
	item.cchTextMax=8;
	SendMessage(hList,LVM_GETITEMTEXT,index,(LPARAM)&item);
	if (buffer[0]!=buffer[4]) remove=1;

	item.pszText=buffer;
	SendMessage(hList,LVM_SETITEMTEXT,index,(LPARAM)&item);

	GetWindowText(hUnicode,buffer,8);
	flag_uni=IsUnicodeCheck();
	if (flag_uni) buffer[4]=L'+';
	else buffer[4]=L'-';
	buffer[5]=0;
	item.iSubItem=2;
	SendMessage(hList,LVM_SETITEMTEXT,index,(LPARAM)&item);
	//ListView_SetItemText(hList,index,2,buffer);

	GetWindowText(hSJIS,buffer,8);
	flag_mb=IsSJISCheck();
	if (flag_mb) buffer[4]=L'+';
	else buffer[4]=L'-';
	buffer[5]=0;
	item.iSubItem=1;
	SendMessage(hList,LVM_SETITEMTEXT,index,(LPARAM)&item);
	//ListView_SetItemText(hList,index,1,buffer);
	if ((flag_mb|flag_uni)==0)
	{
		ListView_SetSelectionMark(hList,index);
		DeleteCurrentChar();
	}
}
void FilterWindow::SelectCurrentChar(DWORD index)
{
	WCHAR buffer[8],uni_char;
	LVITEM item={};
	item.mask=LVIF_TEXT;
	item.cchTextMax=8;
	item.pszText=buffer;
	if (SendMessage(hList,LVM_GETITEMTEXT,index,(LPARAM)&item)==1)
	{
		uni_char=buffer[0];
		DrawGlyph(uni_char);
		item.iSubItem=1;
		SetWindowText(hChar,buffer);
		if (SendMessage(hList,LVM_GETITEMTEXT,index,(LPARAM)&item)==5)
		{
			if (buffer[4]==L'+') CheckDlgButton(hDlg,IDC_CHECK6,BST_CHECKED);
			else CheckDlgButton(hDlg,IDC_CHECK6,BST_UNCHECKED);
			buffer[4]=0;
			SetWindowText(hSJIS,buffer);
		}
		item.iSubItem=2;
		if (SendMessage(hList,LVM_GETITEMTEXT,index,(LPARAM)&item)==5)
		{
			if (buffer[4]==L'+') CheckDlgButton(hDlg,IDC_CHECK7,BST_CHECKED);
			else CheckDlgButton(hDlg,IDC_CHECK7,BST_UNCHECKED);
			buffer[4]=0;
			SetWindowText(hUnicode,buffer);
		}
	}

}
void FilterWindow::InitWithChar(WCHAR uni_char)
{
	WCHAR buffer[8];
	union {DWORD mbd;WORD mbw[2];char mbc[4];BYTE mbb[4];};
	mbd=0;
	DrawGlyph(uni_char);
	buffer[0]=uni_char;
	buffer[1]=0;
	SetWindowText(hChar,buffer);
	WC_MB(buffer,mbc);

	if (LeadByteTable[mbb[0]]==2) mbw[0]=_byteswap_ushort(mbw[0]);
	swprintf(buffer,L"%.4X",mbw[0]);
	SetWindowText(hSJIS,buffer);
	CheckDlgButton(hDlg,IDC_CHECK6,BST_CHECKED);

	swprintf(buffer,L"%.4X",uni_char);
	SetWindowText(hUnicode,buffer);
	CheckDlgButton(hDlg,IDC_CHECK7,BST_CHECKED);
}
void FilterWindow::DrawGlyph(WCHAR glyph)
{
	RECT rc;
	GetClientRect(hGlyph,&rc);
	FillRect(hGlyphDC,&rc,white);
	IthGlyph g(hGlyphDC);
	g.InitGlyph(glyph);
	g.DrawGlyph(hGlyphDC,init_x,init_y,tm.tmHeight);
}
void FilterWindow::SetUniChar(WCHAR uni_char)
{
	WCHAR buffer[8];
	DWORD index;
	buffer[0]=uni_char;
	buffer[1]=0;
	LVFINDINFO find={LVFI_STRING,buffer};
	index=ListView_FindItem(hList,0,&find);
	if (index==-1) 
	{
		LVITEM item={};
		item.mask=LVIF_TEXT;
		item.cchTextMax=2;
		item.pszText=buffer;
		index=ListView_InsertItem(hList,&item);
		if (-1==index) return;
	}
	swprintf(buffer,L"%.4X+",uni_char);
	ListView_SetItemText(hList,index,2,buffer);
}
void FilterWindow::SetMBChar(WORD mb_char)
{
	WCHAR buffer[8];
	char mb[4]={};
	DWORD index;
	*(WORD*)mb=mb_char;
	MB_WC(mb,buffer);
	buffer[1]=0;
	LVFINDINFO find={LVFI_STRING,buffer};
	index=ListView_FindItem(hList,-1,&find);
	if (index==-1) 
	{
		LVITEM item={};
		item.mask=LVIF_TEXT;
		item.cchTextMax=2;
		item.pszText=buffer;
		index=ListView_InsertItem(hList,&item);
		if (-1==index) return;
	}
	if (LeadByteTable[(BYTE)mb[0]]==2) 
		mb_char=_byteswap_ushort(mb_char);
	swprintf(buffer,L"%.4X+",mb_char);
	ListView_SetItemText(hList,index,1,buffer);
}
void FilterWindow::SetCommitFlag() {commit=1;}
void FilterWindow::ClearGlyphArea()
{
	FillRect(hGlyphDC,&rc,white);
}
UINT FilterWindow::IsSJISCheck(){ return IsDlgButtonChecked(hDlg,IDC_CHECK6);}
UINT FilterWindow::IsUnicodeCheck(){ return IsDlgButtonChecked(hDlg,IDC_CHECK7);}