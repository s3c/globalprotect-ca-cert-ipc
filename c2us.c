//#include "stdafx.h"
#include <windows.h>
#include <Winbase.h>
#include <Wtsapi32.h>
#include <Userenv.h>
#include <malloc.h>
#include <stdbool.h>
#include <tchar.h>

//https://gist.github.com/masthoon/6f81e466d458ff8056d76266b90d2b5e
//gcc .\c2us.c -o .\c2us.dll -DISDLL -shared -lWtsapi32 -luserenv
//gcc .\c2us.c -o .\c2us.exe -lWtsapi32 -luserenv

#define DLL_EXPORT __declspec(dllexport)

// Specify the command to run
LPCTSTR fixCmdLine = TEXT("C:\\Windows\\System32\\cmd.exe");

bool StartInteractiveProcess(LPTSTR cmd) {
	LPCTSTR cmdDir;
	STARTUPINFO si;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	si.lpDesktop = TEXT("winsta0\\default");  // Use the default desktop for GUIs
	cmdDir = TEXT("C:\\Windows\\"); // Default directory
	PROCESS_INFORMATION pi;
	ZeroMemory(&pi, sizeof(pi));
	HANDLE token;
	DWORD sessionId = WTSGetActiveConsoleSessionId();
	if (sessionId == 0xffffffff)  // Noone is logged-in
		return false;
	// This only works if the current user is the system-account (we are probably a Windows-Service)
	HANDLE dummy;
	TOKEN_PRIVILEGES tp;
	LUID luid;
	HANDLE hPToken = NULL;
	HANDLE hProcess = NULL;
	DWORD dwCreationFlags = NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE;
	if (WTSQueryUserToken(sessionId, &dummy)) {
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY
			| TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_SESSIONID
			| TOKEN_READ | TOKEN_WRITE, &hPToken))
		{
			return false;
		}
		if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
		{
			return false;
		}
		tp.PrivilegeCount = 1;
		tp.Privileges[0].Luid = luid;
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		if (!DuplicateTokenEx(hPToken, MAXIMUM_ALLOWED, NULL, SecurityIdentification, TokenPrimary, &token)) {
			return false;
		}

		if (!SetTokenInformation(token, TokenSessionId, (void*)&sessionId, sizeof(DWORD)))
		{
			return false;
		}
		if (!AdjustTokenPrivileges(token, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, NULL))
		{
			return false;
		}
		LPVOID pEnv = NULL;
		if (CreateEnvironmentBlock(&pEnv, token, TRUE))
		{
			dwCreationFlags |= CREATE_UNICODE_ENVIRONMENT;
		}
		else pEnv = NULL;
		// Create process for user with desktop
		if (!CreateProcessAsUser(token, NULL, cmd, NULL, NULL, FALSE, dwCreationFlags, pEnv, NULL, &si, &pi)) {  // The "new console" is necessary. Otherwise the process can hang our main process
			CloseHandle(token);
			return false;
		}
		CloseHandle(dummy);
		CloseHandle(token);
	}
	// Create process for current user
	else if (!CreateProcess(NULL, cmd, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, cmdDir, &si, &pi))  // The "new console" is necessary. Otherwise the process can hang our main process
		return false;

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	return true;
}


bool StartProcess() {
	BOOL b;
	SIZE_T rawSize = (_tcslen(fixCmdLine) + 1) * sizeof(TCHAR);
	LPTSTR commandLine = (LPTSTR)_malloca(rawSize); // Allocate on the stack
	memcpy(commandLine, fixCmdLine, rawSize);
	b = StartInteractiveProcess(commandLine);
	_freea(commandLine);
	return b;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved){
	
	switch(ul_reason_for_call){
		case DLL_PROCESS_ATTACH:
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
		case DLL_PROCESS_DETACH:
			break;
	}
	return TRUE;
}

#ifdef ISDLL

DLL_EXPORT void Launch(void){
	StartProcess();
	return;
}

#else
	
int main(void){
	StartProcess();
	
	return 0;
}

#endif
