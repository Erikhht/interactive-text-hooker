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
#include "..\AVL.h"
#define THREAD_MASK_RETN 1
#define THREAD_MASK_SPLIT 2
struct ThreadParam
{
	UINT_PTR hook_index,status;
	UINT_PTR hook_addr;
	UINT_PTR retn;
	UINT_PTR split;
	UINT_PTR hm_index,reserve;
};
struct LinkParam
{
	UINT_PTR from_index,to_index;
};
struct CommentParam
{
	UINT_PTR thread_index,status;
	LPWSTR comment;
};
class Profile
{
public:
	Profile();
	Profile(const Profile& p);
	~Profile();
	void Release();
	void AddHook(const HookParam& hp);
	void RemoveThread(UINT_PTR index);
	void RemoveLink(UINT_PTR index);
	void RemoveComment(UINT_PTR index);
	void ClearHooks();
	UINT_PTR AddThread(ThreadParam *tp);
	UINT_PTR AddLink(LinkParam* lp);
	UINT_PTR AddComment(LPWSTR comment, UINT_PTR index);
	Profile& operator = (Profile& pf);
	HookParam hps[4];
	UINT_PTR hook_count,thread_count,link_count,comment_count,select_index;		
	UINT_PTR engine_type,thread_allocate,link_allocate,comment_allocate,flag;
	ThreadParam* threads;
	LinkParam* links;
	CommentParam *comments;
};
typedef TreeNode<LPWSTR,Profile> ProfileNode;
class ProfileManager
{
public:
	ProfileManager();
	~ProfileManager();
	void AddProfile(LPWSTR path, const Profile& p);
	void ClearProfile();
	void LoadProfile();
	void SaveProfile();
	void DeleteProfile(int index);
	void DeleteProfile(LPWSTR path);
	void RefreshProfileAddr(UINT_PTR pid,LPWSTR path);
	void SetProfileEngine(LPWSTR path, UINT_PTR type);
	bool IsPathProfile(LPWSTR path);
	ProfileNode* GetProfile(LPWSTR path);
	ProfileNode* GetProfile(int index);
	ProfileNode* BeginProfile();
	ProfileNode* EndProfile();
private:
	AVLTree<WCHAR,Profile,WCMP,WCPY,WLEN> pftree;
	HANDLE hMonitorThread;
};
void GetCode(const HookParam& hp, LPWSTR buffer, UINT_PTR pid=0);
void GetThreadString(ThreadParam* tp, LPWSTR str);