//Prevent ITH overide operator new.
#define DEFAULT_MM

#include <ITH\IHF.h>
#include <stdio.h>
static HookManager* man;
DWORD ProcessAttach(DWORD pid)
{
	printf("Process %d attached.\n",pid);
	return 0;
}
DWORD ProcessDetach(DWORD pid)
{
	printf("Process %d detached.\n",pid);
	return 0;
}
DWORD ProcessNewHook(DWORD pid)
{
	printf("Process %d has new hook inserted.\n",pid);
	return 0;
}
DWORD ThreadOutput(TextThread* t, BYTE* data,DWORD len, DWORD new_line, PVOID user_data)
{
	printf("Thread %.4X output. len = %d, new_line = %d, user_data = %.8X\n",
		t->Number(),len,new_line,user_data);
	if (len <= 2)
	{
		//Single character.
		printf("Data: %.2X",data[0]);
		if (len == 2) printf(" %.2X",data[1]);
		printf("\n");
	}
	else
	{
		printf("Data:\n");
		for (DWORD i = 0; i < len; i++)
		{
			printf("%.2X ",data[i]);
			if ((i & 0xF) == 0xF) printf("\n");
		}
	}
	return len;
}
DWORD ThreadCreate(TextThread* t)
{
	printf("New thread created.\n");
	ThreadParameter* tp = t->GetThreadParameter();
	printf("%.4x:%.4x:%.8X:%.8X:%.8X\n",t->Number(),tp->pid,tp->hook,tp->retn,tp->spl);
	//Set output callback. This function is called when some text is dispatched to thread 't'.
	//It's possible to set different callback for different thread.
	t->RegisterOutputCallBack(ThreadOutput,0);
	return 0;
}
int main(int argc, char** argv)
{
	//__debugbreak();
	HANDLE running = OpenMutex(MUTEX_ALL_ACCESS, FALSE, L"ITH_MAIN_RUNNING");
	if (running != 0 || GetLastError() != ERROR_FILE_NOT_FOUND)
	{
		//There's another instance of ITH running in the system.
		CloseHandle(running);
		return 1;
	}
	if (IHF_Init())
	{
		IHF_GetHookManager(&man);
		if (man)
		{
			man->RegisterProcessAttachCallback(ProcessAttach);
			man->RegisterProcessDetachCallback(ProcessDetach);
			man->RegisterProcessNewHookCallback(ProcessNewHook);
			man->RegisterThreadCreateCallback(ThreadCreate);
			IHF_Start();//IHF started functioning.
			DWORD inject_pid;
			printf("Enter pid to inject:\n");
			scanf("%d",&inject_pid);
			getchar(); //Get the last linebreak.
			IHF_InjectByPID(inject_pid, 0); //Use default engine.
			getchar(); //Wait till any key.
			IHF_ActiveDetachProcess(inject_pid);
		}
		IHF_Cleanup();
	}
	else
	{
		//There's another program using IHF running in the system.
		return 1;
	}
	//Sometimes the system create extra threads. Simply return from here doesn't shutdown the process.
	//Even ExitProcess may fail. TerminateProcess is considered to be safer.
	return 0;
}