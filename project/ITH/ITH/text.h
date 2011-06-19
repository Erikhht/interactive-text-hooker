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
#include "main_template.h"
class TextBuffer : public MyVector<BYTE, 0x800>
{
public:
	TextBuffer();
	virtual ~TextBuffer();
	void AddText(BYTE* text,int len,bool);
	void AddNewLIne();
	void ReplaceSentence(BYTE* text, int len);
	void Flush();
	void ClearBuffer();
	void SetUnicode(bool mode);
	void SetLine();
	void SetFlushTimer(UINT t);
private:
	UINT timer;
	bool line;
	bool unicode;
};
struct RepeatCountNode
{
	short repeat;
	short count;
	RepeatCountNode* next;
};
struct ThreadParameter
{
	DWORD pid;
	DWORD hook;
	DWORD retn;
	DWORD spl;
	/*DWORD spl;
	DWORD retn;
	DWORD hook;
	DWORD pid;*/
};
#define COUNT_PER_FOWARD 0x200
#define REPEAT_DETECT 0x10000
#define REPEAT_SUPPRESS 0x20000
#define REPEAT_NEWLINE 0x40000
class TextThread : public MyVector<BYTE, 0x200>
{
public:
	TextThread(DWORD pid, DWORD hook, DWORD retn, DWORD spl, WORD num);
	virtual ~TextThread();
	void Reset();
	void AddToStore(BYTE* con,int len, bool new_line=false, bool console=false);
	void RemoveSingleRepeatAuto(BYTE* con, int &len);
	void RemoveSingleRepeatForce(BYTE* con, int &len);
	void RemoveCyclicRepeat(BYTE* &con, int &len);
	void ResetRepeatStatus();
	void AddLineBreak();
	void ResetEditText();
	void ComboSelectCurrent();
	void GetEntryString(LPWSTR str);
	void CopyLastSentence(LPWSTR str);
	void CopyLastToClipboard();
	void ExportTextToFile(LPWSTR filename);
	void AdjustPrevRepeat(DWORD len);
	void PrevRepeatLength(DWORD &len);
	void SetComment(LPWSTR);
	bool AddToCombo();
	bool RemoveFromCombo();
	bool CheckCycle(TextThread* start);
	void SetNewLineFlag();
	void SetNewLineTimer();
	inline DWORD PID() const {return tp.pid;}
	inline DWORD Addr() const {return tp.hook;}
	inline DWORD& Status() {return status;}
	inline WORD Number() const {return number;}
	inline WORD& Last() {return last;}
	inline WORD& LinkNumber() {return link_number;}
	inline UINT_PTR& Timer() {return timer;}
	inline ThreadParameter* GetThreadParameter() {return &tp;}
	inline TextThread*& Link() {return link;}
	
	inline void SetRepeatFlag();
	inline void ClearNewLineFlag();
	inline void ClearRepeatFlag();
	inline LPWSTR GetComment() {return comment;}
private:
	ThreadParameter tp;
	
	WORD number,link_number;
	WORD last,align_space;
	WORD repeat_single;
	WORD repeat_single_current;
	WORD repeat_single_count;
	WORD repeat_detect_count;
	RepeatCountNode* head;

	TextThread *link;
	LPWSTR comment,thread_string;
	UINT_PTR timer;
	DWORD status,repeat_detect_limit;
	DWORD last_sentence,prev_sentence,sentence_length,repeat_index,last_time;
};
