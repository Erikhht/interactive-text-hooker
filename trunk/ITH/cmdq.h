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
enum ThreadOperation
{
	Suspend,
	Resume,
	Terminate,
	OutputInformation
};
struct PipeRecord
{
	HANDLE hTextPipe, hCmdPipe, hThread;
};
void CreateNewPipe();
#define QUEUE_MAX 16 //QUEUE_MAX need to be a exponent of 2;
#define QUEUE_BUFF_SIZE 0x40
#define CMD_SIZE 0x200

class CommandQueue
{
public:
	CommandQueue();
	~CommandQueue();
	void AddRequest(const SendParam& sp,DWORD pid=0);
	void SendCommand();
	bool Empty();
	void Register(DWORD pid, DWORD hookman, DWORD module, DWORD engine);
	DWORD ProcessCommand(LPWSTR cmd);
private:
	CRITICAL_SECTION rw;
	DWORD current;
	DWORD used;
	SendParam queue[QUEUE_MAX];
	HANDLE hSemaphore,hThread;
	DWORD pid_associate[QUEUE_MAX];
};
