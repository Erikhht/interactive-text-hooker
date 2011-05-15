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
	void AddText(BYTE* text,size_t len,bool);
	void ReplaceSentence(BYTE* text, size_t len);
	void Flush();
	void ClearBuffer();
	void SetUnicode(bool mode);
	void SetLine();
	void SetFlushTimer(UINT_PTR t);
private:
	UINT_PTR timer;
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
	UINT_PTR pid;
	UINT_PTR hook;
	UINT_PTR retn;
	UINT_PTR spl;
};
#define COUNT_PER_FOWARD 0x200
#define REPEAT_DETECT 0x10000
#define REPEAT_SUPPRESS 0x20000
#define REPEAT_NEWLINE 0x40000
class TextThread : public MyVector<BYTE, 0x200>
{
public:
	TextThread(UINT_PTR pid, UINT_PTR hook, UINT_PTR retn, UINT_PTR spl, UINT_PTR num);
	virtual ~TextThread();
	void Reset();
	void AddToStore(BYTE* con,size_t len, bool new_line=false, bool console=false);
	void RemoveSingleRepeat(BYTE* con, size_t &len);
	void RemoveCyclicRepeat(BYTE* &con, size_t &len);
	void AddLineBreak();
	void ResetEditText();
	void ComboSelectCurrent();
	void GetEntryString(LPWSTR str);
	void CopyLastSentence(LPWSTR str);
	void CopyLastToClipboard();
	void AdjustPrevRepeat(UINT_PTR len);
	void PrevRepeatLength(UINT_PTR &len);
	void SetComment(LPWSTR);
	void SetNewLineTimer();
	bool AddToCombo();
	bool RemoveFromCombo();
	bool CheckCycle(TextThread* start);
	inline UINT_PTR PID() const {return tp.pid;}
	inline UINT_PTR Addr() const {return tp.hook;}
	inline UINT_PTR& Status() {return status;}
	inline UINT_PTR Number() const {return number;}
	inline WORD& Last() {return last;}
	inline UINT_PTR& LinkNumber() {return link_number;}
	inline UINT_PTR& Timer() {return timer;}
	inline ThreadParameter* GetThreadParameter() {return &tp;}
	inline TextThread*& Link() {return link;}
	inline void SetNewLineFlag();
	inline void SetRepeatFlag();
	inline void ClearNewLineFlag();
	inline void ClearRepeatFlag();
	inline LPWSTR GetComment() {return comment;}
private:
	ThreadParameter tp;
	
	UINT_PTR number,link_number;
	WORD last,reserved;
	WORD repeat_single;
	WORD repeat_single_current;
	WORD repeat_single_count;
	WORD repeat_detect_count;
	RepeatCountNode* head;

	TextThread *link;
	LPWSTR comment,thread_string;
	UINT_PTR timer;
	UINT_PTR status,last_time,repeat_detect_limit;
	UINT_PTR last_sentence,prev_sentence,sentence_length,repeat_index;
};
