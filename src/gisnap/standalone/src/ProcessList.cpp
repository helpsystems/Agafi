#include "stdafx.h"
#include "psapi.h"
#include "processlist.h"
#include <stdio.h>
#include <TlHelp32.h>

//extern Debugger *gDebugger;
//extern LogWindow *gLog;

extern LPWSTR *szArglist;
extern int nArgs;


#define WM_SETUPWINDOW (WM_USER + 1)

//------------------------------------------------------------------------------------------------------
ProcessList::ProcessList(HWND hwndDlg, HINSTANCE hInstance)
//------------------------------------------------------------------------------------------------------
{
	_parent = hwndDlg;
	_hinstance = hInstance;
	_currentline = 0;
	_hwnd = GetDlgItem(hwndDlg, IDC_PROCLIST); 
}

//------------------------------------------------------------------------------------------------------
void ProcessList::SetSelectionFromPid(DWORD pid)
//------------------------------------------------------------------------------------------------------
{
	unsigned int line=0;

	while(line < sizeof(aListNames)) {
		SendMessage(_hwnd, LB_SETCURSEL, (WPARAM)line, (LPARAM)0);
		LRESULT res = SendMessage(_hwnd, LB_GETCURSEL, (WPARAM)0, (LPARAM)0);
		if(aListNames[res].pid == pid) {
			break;
		}
		line++;
	}
}

//------------------------------------------------------------------------------------------------------
ProcessList::~ProcessList()
//------------------------------------------------------------------------------------------------------
{
}

void ProcessList::EnableDisable(BOOL val)
{
	HWND btn1 = GetDlgItem(_parent, IDC_DUMP);
	HWND btn2 = GetDlgItem(_parent, IDC_REFRESH);
	EnableWindow(_hwnd, val);
	EnableWindow(btn1, val);
	EnableWindow(btn2, val);
	SendDlgItemMessage(_parent, IDC_PROCLIST, WM_PAINT, 0, 0);
}

//------------------------------------------------------------------------------------------------------
DWORD ProcessList::GetSelectedPid()
//------------------------------------------------------------------------------------------------------
{
	LRESULT res = SendMessage(_hwnd, LB_GETCURSEL, (WPARAM)0, (LPARAM)0);
	if(res == -1)
		return (DWORD)res;
	return aListNames[res].pid;
}

//------------------------------------------------------------------------------------------------------
void ProcessList::ListEmpty()
//------------------------------------------------------------------------------------------------------
{
	SendMessage(_hwnd, LB_RESETCONTENT, (WPARAM)0, (LPARAM)0);
	SendMessage(_hwnd, WM_PAINT, 0, 0);
	_currentline=0;
}

void ProcessList::FillList()
{
	ListEmpty();

	HANDLE h_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if(h_snapshot == INVALID_HANDLE_VALUE)
		return;

	DWORD index=0;
	PROCESSENTRY32 _tmpProcEntry32;
	_tmpProcEntry32.dwSize = sizeof(PROCESSENTRY32);

	HANDLE _tmphProcess = INVALID_HANDLE_VALUE;
	BOOL is64b = FALSE;

	if(Process32First(h_snapshot, &_tmpProcEntry32)) {
		do {
			_tmphProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE,  _tmpProcEntry32.th32ProcessID);
			if(_tmphProcess == INVALID_HANDLE_VALUE)
				continue;
#ifndef _WIN64
		// only list 32bit processes
		SYSTEM_INFO sysinfo;
		GetNativeSystemInfo(&sysinfo);
		if(sysinfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) {
			IsWow64Process(_tmphProcess, &is64b);
				if(!is64b) {
					continue;
				}
		}
#else
		// only list 64bit processes
		SYSTEM_INFO sysinfo;
		GetNativeSystemInfo(&sysinfo);
		if(sysinfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) {
			IsWow64Process(_tmphProcess, &is64b);
				if(is64b) {
					continue;
				}
		}
#endif

			aListNames[index].pid = _tmpProcEntry32.th32ProcessID;
			strncpy(aListNames[index].name, _tmpProcEntry32.szExeFile, 1024);
			ListPrint("[%05d] - %s", aListNames[index].pid, aListNames[index].name);
			index++;
			CloseHandle(_tmphProcess);
		} while(Process32Next(h_snapshot, &_tmpProcEntry32));
	}
	CloseHandle(h_snapshot);
}
/*

//------------------------------------------------------------------------------------------------------
void ProcessList::FillList()
//------------------------------------------------------------------------------------------------------
{
	ListEmpty();

	DWORD tmp=0;
	DWORD a_pids[1024];
	memset(a_pids, 0xff, sizeof(a_pids));
	BOOL res = EnumProcesses(a_pids, sizeof(a_pids), &tmp);
	unsigned int maxidx=tmp/sizeof(DWORD);
	WORD index=0;
	BOOL is64b=FALSE;

	for(unsigned int i=0;i<=maxidx;i++) {
		if(a_pids[i] == 0xffffffff)
			continue;
		HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE,  a_pids[i]);
		if(!hProcess) {
			continue;
		}
		

#ifndef _WIN64
		// only list 32bit processes
		SYSTEM_INFO sysinfo;
		GetNativeSystemInfo(&sysinfo);
		if(sysinfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) {
			IsWow64Process(hProcess, &is64b);
				if(!is64b) {
					continue;
				}
		}
#else
		// only list 64bit processes
		SYSTEM_INFO sysinfo;
		GetNativeSystemInfo(&sysinfo);
		if(sysinfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) {
			IsWow64Process(hProcess, &is64b);
				if(is64b) {
					continue;
				}
		}
#endif
		char szProcessName[1024];
		memset(szProcessName, 0, sizeof(szProcessName));
		GetProcessImageFileName(hProcess, szProcessName, sizeof(szProcessName));
		CloseHandle(hProcess);
		char *filename = strrchr(szProcessName, '\\');
		if(!filename) {
			filename = "System";
		} else
			filename++;
		aListNames[index].pid = a_pids[i];

		lstrcpyn(aListNames[index].name, filename, 1023);
		ListPrint("[%05d] - %s", aListNames[index].pid, aListNames[index].name);
		index++;
	}
}
*/

//------------------------------------------------------------------------------------------------------
void ProcessList::ListPrint(char *formatstring, ...)
//------------------------------------------------------------------------------------------------------
{
	va_list args;
	va_start(args, formatstring);

	char msg[1024];

	memset(msg, 0, sizeof(msg));

	_vsnprintf(msg, sizeof(msg), formatstring, args);
	SendMessage(_hwnd, LB_INSERTSTRING, _currentline, (LPARAM)msg);

	_currentline++;
}

