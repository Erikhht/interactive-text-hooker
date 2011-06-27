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

#include "profile.h"
#include "cmdq.h"
#include "hookman.h"
bool MonitorFlag;
extern HWND hMainWnd;
DWORD auto_inject, auto_insert;
static WCHAR process_path[MAX_PATH];
LPWSTR EngineHookName[]=
{
	L"Unknown",L"KiriKiri1",L"BGI",L"Reallive",
	L"MAJIRO",L"CMVS",L"rUGP",L"Lucifen",
	L"System40",L"AtelierKaguya",L"CIRCUS",L"ShinaRio",
	L"MBL",L"TinkerBell",L"YU-RIS",L"Cotopha",L"Malie",
	L"SofthouseChara",L"CatSystem2",L"IronGameSystem",
	L"Waffle",L"NitroPlus",L"DotNet1",L"RetouchSystem",
	L"SiglusEngine",L"AbelSoftware",L"Live",L"FrontWing",
	L"Bruns"
};
DWORD WINAPI InjectThread(LPVOID lpThreadParameter)
{
	WCHAR path[MAX_PATH];
	DWORD pid=(DWORD)lpThreadParameter;
	IthSleep(inject_delay);
	DWORD s=InjectByPID(pid);
	if (!auto_insert) return s;
	if (s==-1) return s;
	IthSleep(insert_delay);
	if (GetProcessPath(pid,path))
	{
		SendParam sp;
		sp.type=0;
		ProfileNode* pf=pfman->GetProfile(path);
		for (int i=0;i<pf->data.hook_count;i++)
		{
			memcpy(&sp.hp,pf->data.hps+i,sizeof(HookParam));
			cmdq->AddRequest(sp,pid);
		}
	}
	return s;
}
DWORD WINAPI MonitorThread(LPVOID lpThreadParameter)
{
	SetEnvironmentVariable(L"__COMPAT_LAYER", L"#ApplicationLocale");
	SetEnvironmentVariable(L"AppLocaleID", L"0411");
	DWORD size=0x20000,rs;
	LPVOID addr=0; NTSTATUS status;
	SYSTEM_PROCESS_INFORMATION *spiProcessInfo;
	NtAllocateVirtualMemory(NtCurrentProcess(),&addr,0,&size,MEM_COMMIT,PAGE_READWRITE);
	while (MonitorFlag)
	{
		status=NtQuerySystemInformation(SystemProcessInformation,addr,size,&rs);
		if (status==STATUS_INFO_LENGTH_MISMATCH)
		{
			NtFreeVirtualMemory(NtCurrentProcess(),&addr,&size,MEM_DECOMMIT);
			addr=0;size=(rs&0xFFFFF000)+0x4000;
			NtAllocateVirtualMemory(NtCurrentProcess(),&addr,0,&size,MEM_COMMIT,PAGE_READWRITE);
			status=NtQuerySystemInformation(SystemProcessInformation,addr,size,&rs);
		}
		if (!NT_SUCCESS(status)) {man->AddConsoleOutput(ErrorMonitor);break;}
		for (spiProcessInfo=(SYSTEM_PROCESS_INFORMATION*)addr; MonitorFlag&&spiProcessInfo->dNext;)
		{
			IthSleep(process_time);
			spiProcessInfo=(SYSTEM_PROCESS_INFORMATION*)	
				((DWORD)spiProcessInfo+spiProcessInfo->dNext);
			if (!auto_inject||	pid_map->Check(spiProcessInfo->dUniqueProcessId>>2)) continue;
			if (GetProcessPath(spiProcessInfo->dUniqueProcessId,process_path))
				if (pfman->IsPathProfile(process_path))
				{
					pid_map->Set(spiProcessInfo->dUniqueProcessId>>2);
					NtClose(IthCreateThread(InjectThread,spiProcessInfo->dUniqueProcessId));
				}
		}
	}
	NtFreeVirtualMemory(NtCurrentProcess(),&addr,&size,MEM_DECOMMIT);
	return 0;
}
Profile::Profile()
{
	memset(this,0,sizeof(Profile));
}
Profile::Profile(const Profile& pf) 
{
	if(&pf!=this)
		memcpy(this,&pf,sizeof(Profile));
}

Profile::~Profile() {}
void Profile::Release()
{
	if (thread_allocate) {delete threads;}
	if (link_allocate) {delete links;}
	if (comment_allocate) 
	{
		for (int i=0;i<comment_count;i++)
			delete comments[i].comment;
		delete comments;
	}
	memset(this,0,sizeof(Profile));
}
void Profile::AddHook(const HookParam& hp)
{
	if (hook_count==4) return;
	hps[hook_count++]=hp;
}
void Profile::ClearHooks() {hook_count=0;}
int Profile::AddThread(ThreadParam *tp)
{
	tp->hook_addr=0;
	tp->hm_index=0;
	for (int i=0;i<thread_count;i++) if (memcmp(tp,threads+i,sizeof(ThreadParam))==0) return i;
	if (thread_count>=thread_allocate)
	{
		thread_allocate+=4;
		ThreadParam* temp=new ThreadParam[thread_allocate];
		if (threads)
		{
			memcpy(temp,threads,thread_count*sizeof(ThreadParam));
			delete threads;
		}
		threads=temp;
	}
	memcpy(threads+thread_count,tp,sizeof(ThreadParam));
	return thread_count++;
}
int Profile::AddLink(LinkParam* lp)
{
	for (int i=0;i<link_count;i++) if (memcmp(lp,links+i,sizeof(LinkParam))==0) return i;
	if (link_count>=link_allocate)
	{
		link_allocate=link_count+4;
		LinkParam* temp=new LinkParam[link_allocate];
		if (links)
		{
			memcpy(temp,links,link_count*sizeof(LinkParam));
			delete links;
		}
		links=temp;
	}
	memcpy(links+link_count,lp,sizeof(LinkParam));
	return link_count++;
}
int Profile::AddComment(LPWSTR comment, WORD index)
{
	if (comment==0) return -1;
	if (comment[0]==0) return -1;
	for (int i=0;i<comment_count;i++) 
	{
		if (comments[i].thread_index==index)
		{
			if (comments[i].comment) delete comments[i].comment;
			comments[i].comment=new WCHAR[wcslen(comment)+1];
			wcscpy(comments[i].comment,comment);
			return i;
		}
	}
	if (comment_count>=comment_allocate)
	{
		comment_allocate=comment_count+4;
		CommentParam* temp=new CommentParam[comment_allocate];
		if (comments)
		{
			memcpy(temp,comments,comment_count*sizeof(CommentParam));
			delete comments;
		}
		comments=temp;
	}
	comments[comment_count].thread_index=index;
	comments[comment_count].comment=new WCHAR[wcslen(comment)+1];
	wcscpy(comments[comment_count].comment,comment);
	return comment_count++;
}
void Profile::RemoveThread(int index)
{
	if (index>=0&&index<thread_count)
	{
		int i;
		for (i=link_count-1;i>=0;i--)
			if (links[i].from_index==index+1||
				links[i].to_index==index+1)
				RemoveLink(i);
		for (i=comment_count-1;i>=0;i--)
			if (comments[i].thread_index==index+1)
				RemoveComment(i);
		if (select_index==index+1) select_index=0;
		for (i=index;i<thread_count-1;i++)
			threads[i]=threads[i+1];
		thread_count--;
		memset(threads+thread_count,0,sizeof(ThreadParam));		
		if (index<select_index) select_index--;
		else if (index==select_index) select_index=0;
	}
}
void Profile::RemoveLink(int index)
{
	if (index>=0&&index<link_count)
	{
		for (int i=index;i<link_count-1;i++)
			links[i]=links[i+1];
		link_count--;
		memset(links+link_count,0,sizeof(LinkParam));
		
	}
}
void Profile::RemoveComment(int index)
{
	if (index>=0&&index<comment_count)
	{
		delete comments[index].comment;
		for (int i=index;i<comment_count-1;i++)
			comments[i]=comments[i+1];
		comment_count--;
		memset(comments+comment_count,0,sizeof(CommentParam));
		
	}
}
Profile& Profile::operator = (Profile& pf)
{
	Release();
	if(&pf!=this)
		memcpy(this,&pf,sizeof(Profile));
	return *this;
}
class NodeSize
{
public:
	NodeSize() : size(0x4),name_off(0x4) {}
	void operator() (TreeNode<LPWSTR,Profile>* p)
	{
		Profile* pf=&p->data;
		int t=pf->hook_count*sizeof(HookParam)+0x10;
		t+=pf->thread_count*(sizeof(ThreadParam)-4);
		t+=pf->link_count*sizeof(LinkParam);
		t+=pf->comment_count*sizeof(CommentParam);
		name_off+=t;
		size+=t+(wcslen(p->key)<<1)+2;
		for (t=0;t<pf->comment_count;t++)
			size+=(wcslen(pf->comments[t].comment)<<1)+2;
	}
	int size,name_off;
};
class NodeWrite
{
public:
	NodeWrite(BYTE* buff, LPWSTR off): ptr(buff+4),buffer(buff),name(off) {}
	void operator() (TreeNode<LPWSTR,Profile>* p)
	{
		Profile* pf=&p->data;
		*(DWORD*)ptr=pf->hook_count|(pf->thread_count<<16);
		*(DWORD*)(ptr+4)=pf->link_count|(pf->comment_count<<16);
		*(DWORD*)(ptr+8)=pf->select_index|(pf->engine_type<<16);	
		*(DWORD*)(ptr+0xC)=(DWORD)name-(DWORD)buffer;
		int i,len;
		len=wcslen(p->key);
		wcscpy(name,p->key);
		name+=len+1;		
		for (ptr+=0x10,i=0;i<pf->hook_count;i++,ptr+=sizeof(HookParam))
			memcpy(ptr,pf->hps+i,sizeof(HookParam));
		for (i=0;i<pf->thread_count;i++,ptr+=sizeof(ThreadParam)-4)
			memcpy(ptr,pf->threads+i,sizeof(ThreadParam)-4);
		for (i=0;i<pf->link_count;i++,ptr+=sizeof(LinkParam))
			memcpy(ptr,pf->links+i,sizeof(LinkParam));
		for (i=0;i<pf->comment_count;i++,ptr+=sizeof(CommentParam))
		{
			*(DWORD*)ptr=pf->comments[i].thread_index;
			*(DWORD*)(ptr+4)=(DWORD)name-(DWORD)buffer;
			len=wcslen(pf->comments[i].comment);
			wcscpy(name,pf->comments[i].comment);
			name+=len+1;
		}
	}
	LPWSTR name;
	BYTE* ptr,*buffer;
};

ProfileManager::ProfileManager()
{
	LoadProfile();
	MonitorFlag=true;
	hMonitorThread=IthCreateThread(MonitorThread,0);
}
ProfileManager::~ProfileManager()
{
	MonitorFlag=false;
	SaveProfile();
	ClearProfile();
	NtWaitForSingleObject(hMonitorThread,0,0);
	NtClose(hMonitorThread);
}
void ProfileManager::AddProfile(LPWSTR path, const Profile& p)
{
	pftree.Insert(path,p);
}
void ProfileManager::ClearProfile()
{
	pftree.~AVLTree();
}
void ProfileManager::LoadProfile()
{
	HANDLE hFile=IthCreateFile(L"ITH.pro",FILE_READ_DATA,FILE_SHARE_READ,FILE_OPEN);
	if (hFile==INVALID_HANDLE_VALUE) return;
	DWORD i,j,profile_count;
	IO_STATUS_BLOCK ios;
	FILE_STANDARD_INFORMATION info;
	NtQueryInformationFile(hFile,&ios,&info,sizeof(info),FileStandardInformation);
	BYTE *path,*ptr,*buffer=new BYTE[info.AllocationSize.LowPart];
	NtReadFile(hFile,0,0,0,&ios,buffer,info.AllocationSize.LowPart,0,0);
	NtClose(hFile);
	profile_count=*(DWORD*)buffer;
	ptr=buffer+4;
	Profile *p;
	ClearProfile();
	WORD thread_count,link_count,comment_count,hook_count;
	for (i=0;i<profile_count;i++)
	{
		hook_count=*(WORD*)ptr;
		thread_count=*(WORD*)(ptr+2);
		link_count=*(WORD*)(ptr+4);
		comment_count=*(WORD*)(ptr+6);

		path=buffer+*(DWORD*)(ptr+0xC);
		p=&pftree.Insert((LPWSTR)path,Profile())->data;

		p->select_index=*(WORD*)(ptr+8);
		p->engine_type=*(WORD*)(ptr+0xA);
		ptr+=0x10;
		for (j=0;j<hook_count;j++,ptr+=sizeof(HookParam))
			p->AddHook(*(HookParam*)ptr);
		ThreadParam tp={0};
		for (j=0;j<thread_count;j++,ptr+=sizeof(ThreadParam)-4)
		{
			memcpy(&tp,ptr,sizeof(ThreadParam)-4);
			p->AddThread(&tp);
		}
		for (j=0;j<link_count;j++,ptr+=sizeof(LinkParam))
			p->AddLink((LinkParam*)ptr);
		for (j=0;j<comment_count;j++,ptr+=sizeof(CommentParam))
			p->AddComment((LPWSTR)(buffer+*(DWORD*)(ptr+4)),*(WORD*)ptr);
	}
	delete buffer;	
}
void ProfileManager::SaveProfile()
{
	NodeSize ns; BYTE *buffer;
	pftree.TraverseTree<NodeSize>(ns);
	buffer=new BYTE[ns.size];
	*(DWORD*)(buffer)=pftree.Count();
	NodeWrite nw(buffer,(LPWSTR)(buffer+ns.name_off));
	pftree.TraverseTree<NodeWrite>(nw);
	HANDLE hFile=IthCreateFile(L"ITH.pro",FILE_WRITE_DATA,FILE_SHARE_READ,FILE_OVERWRITE_IF);
	IO_STATUS_BLOCK ios;
	if (hFile!=INVALID_HANDLE_VALUE)
	{
		NtWriteFile(hFile,0,0,0,&ios,buffer,ns.size,0,0);
		NtClose(hFile);
	}
	delete buffer;
}
void ProfileManager::DeleteProfile(int index)
{
	ProfileNode* pf=GetProfile(index);
	if (pf==0) return;
	pftree.Delete(pf->key);
}
void ProfileManager::DeleteProfile(LPWSTR path)
{
	pftree.Delete(path);
}
void ProfileManager::RefreshProfileAddr(DWORD pid, LPWSTR path)
{
	ProfileNode* pfn=pftree.Search(path);
	if (pfn)
	{
		Profile* pf=&pfn->data;
		Hook* hks=(Hook*)man->RemoteHook(pid);
		int i,j;
		for (i=0;i<pf->thread_count;i++)
		{
			j=pf->threads[i].hook_index;
			pf->threads[i].hook_addr=hks[j-1].Address();
		}
	}
}
void ProfileManager::SetProfileEngine(LPWSTR path, DWORD type)
{
	ProfileNode* pfn=pftree.Search(path);
	if (pfn)
		pfn->data.engine_type=type&0xFFFF;
}
bool ProfileManager::IsPathProfile(LPWSTR path)
{
	if (GetProfile(path)!=0) return true;
	else return false;
}
ProfileNode* ProfileManager::GetProfile(int index)
{
	return pftree.SearchIndex(index);
}
ProfileNode* ProfileManager::GetProfile(LPWSTR path)
{
	return pftree.Search(path);
}
ProfileNode* ProfileManager::BeginProfile()
{
	return pftree.Begin();
}
ProfileNode* ProfileManager::EndProfile()
{
	return pftree.End();
}
void GetThreadString(ThreadParam* tp, LPWSTR str)
{
	str+=swprintf(str,L"%.4X:",tp->hook_index);
	if (tp->status&THREAD_MASK_RETN)
	{
		tp->retn&=0xFFFF;
		str+=swprintf(str,L"XXXX%.4X:",tp->retn);
	}
	else
		str+=swprintf(str,L"%.8X:",tp->retn);
	if (tp->status&THREAD_MASK_SPLIT)
	{
		tp->split&=0xFFFF;
		str+=swprintf(str,L"XXXX%.4X",tp->split);
	}
	else
		str+=swprintf(str,L"%.8X",tp->split);
}
void ExportSingleProfile(ProfileNode* pfn, MyVector<WCHAR,0x1000,WCMP> &export_text)
{
	int index,len;
	WCHAR buffer[0x200]; LPWSTR str;
	if (pfn!=0)
	{
		Profile* pf=&pfn->data;
		export_text.AddToStore(L"[ITH 2.2]\r\n",11);
		export_text.AddToStore(pfn->key,wcslen(pfn->key));
		export_text.AddToStore(L"\r\n[UserHook]\r\n",14);
		for (index=0;index<pf->hook_count;index++)
		{
			GetCode(pf->hps[index],buffer);
			len=wcslen(buffer);
			buffer[len]=L'\r';
			buffer[len+1]=L'\n';
			export_text.AddToStore(buffer,len+2);
		}
		export_text.AddToStore(L"[Thread]\r\n",10);
		for (index=0;index<pf->thread_count;index++)
		{
			str=buffer;
			str+=swprintf(str,L"%.4X:",index);
			GetThreadString(pf->threads+index,str);
			export_text.AddToStore(buffer,wcslen(buffer));
			export_text.AddToStore(L"\r\n",2);
		}
		export_text.AddToStore(L"[Link]\r\n",8);
		for (index=0;index<pf->link_count;index++)
		{
			LinkParam* lp=pf->links+index;
			swprintf(buffer,L"%.4X:%.4X->%.4X",index,lp->from_index-1,lp->to_index-1);
			export_text.AddToStore(buffer,wcslen(buffer));
			export_text.AddToStore(L"\r\n",2);

		}
		export_text.AddToStore(L"[Comment]\r\n",11);
		for (index=0;index<pf->comment_count;index++)
		{
			CommentParam* cp=pf->comments+index;
			swprintf(buffer,L"%.4X:%.4X:",index,cp->thread_index-1);
			export_text.AddToStore(buffer,wcslen(buffer));
			export_text.AddToStore(cp->comment,wcslen(cp->comment));
			export_text.AddToStore(L"\r\n",2);
		}
		export_text.AddToStore(L"[Select]\r\n",10);
		swprintf(buffer,L"%.4X",pf->select_index-1);
		export_text.AddToStore(buffer,(wcslen(buffer)));
		export_text.AddToStore(L"\r\n",2);
	}
}
