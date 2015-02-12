// ropstandalone.cpp : Defines the entry point for the application.
//

#include "stdafx.h"

#include "gisnap.h"
#include <Commctrl.h>
#include <Commdlg.h>
#include <Shellapi.h>

#include <stdio.h>

#define MAX_LOADSTRING 100

ProcessList *gProcList;
MemorySnapshot *gMemSnap;

// Global Variables:
HINSTANCE hInst;								// current instance
TCHAR szTitle[MAX_LOADSTRING];					// The title bar text
TCHAR szWindowClass[MAX_LOADSTRING];			// the main window class name

HWND gHWND;
BOOL _done = FALSE;

LPWSTR *szArglist=0;
int nArgs=0;

BOOL InitInstance(HINSTANCE hInstance, int nCmdShow);
BOOL SetProcessPrivilege();

INT_PTR CALLBACK MainDlgProc(HWND hwndDlg, UINT message, WPARAM wParam, LPARAM lParam);

int APIENTRY _tWinMain(HINSTANCE hInstance,
                     HINSTANCE hPrevInstance,
                     LPTSTR    lpCmdLine,
                     int       nCmdShow)
{
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(lpCmdLine);

 	// TODO: Place code here.
	MSG msg;
	HACCEL hAccelTable;

	// Initialize global strings
	LoadString(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
	LoadString(hInstance, IDC_GISNAP, szWindowClass, MAX_LOADSTRING);

	// Perform application initialization:
	if (!InitInstance (hInstance, nCmdShow))
	{
		return FALSE;
	}

	hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDC_GISNAP));

	BOOL bRet;

	while( (bRet = GetMessage( &msg, gHWND, 0, 0 )) != 0)
	{ 
		if(_done) {
			break;
		}
		if (bRet == -1) {
			break;
		} else {
			TranslateMessage(&msg); 
			DispatchMessage(&msg); 
		}
	}
	return (int) msg.wParam;
}


BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
{
	TOKEN_PRIVILEGES pTokenPrivileges = {0};
	TOKEN_PRIVILEGES oldTokenPrivileges = {0};
	DWORD cbSize=0;
	LUID luid;

	if( !LookupPrivilegeValue( NULL, lpszPrivilege, &luid ) ) { 
		return FALSE; 
	}
	pTokenPrivileges.PrivilegeCount = 1;
	pTokenPrivileges.Privileges[ 0 ].Luid = luid;
	if(bEnablePrivilege) { 
		pTokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED; 
	} else { 
		pTokenPrivileges.Privileges[0].Attributes = 0; 
	}
	if(!AdjustTokenPrivileges(hToken, FALSE, &pTokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) { 
		return FALSE; 
	}
	if(GetLastError()== ERROR_NOT_ALL_ASSIGNED) { 
		return FALSE; 
	}
	return TRUE;
}

BOOL SetProcessPrivilege()
{
	HANDLE pToken = NULL;
	OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &pToken);
	return SetPrivilege(pToken, SE_DEBUG_NAME, TRUE);
}


BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{

	SetProcessPrivilege();

	hInst = hInstance; // Store instance handle in our global variable
	INITCOMMONCONTROLSEX InitCtrlEx;

	InitCtrlEx.dwSize = sizeof(INITCOMMONCONTROLSEX);
	InitCtrlEx.dwICC  = ICC_PROGRESS_CLASS;
	InitCommonControlsEx(&InitCtrlEx);

	gHWND = CreateDialogParam(hInstance, MAKEINTRESOURCE(IDD_MAIN), NULL, MainDlgProc, LPARAM(0)); 
	return TRUE;
}

int SetProgressBar(unsigned int progress)
{
	HWND progressbar = GetDlgItem(gHWND, IDC_PROGRESS);
	if(!progressbar) 
		return 0;
	SendDlgItemMessage(gHWND, IDC_PROGRESS, PBM_SETRANGE32, 0, 100);
	SendDlgItemMessage(gHWND, IDC_PROGRESS, PBM_GETPOS, 0, 0);
	UINT old = (UINT)SendDlgItemMessage(gHWND, IDC_PROGRESS, PBM_GETPOS, 0, 0);
	if(progress < old) {
		SendDlgItemMessage(gHWND, IDC_PROGRESS, PBM_SETPOS, progress, 0);
		SendMessage(progressbar, WM_PAINT, 0, 0);
		Sleep(5);
	} else {
		while(progress > old) {
			SendDlgItemMessage(gHWND, IDC_PROGRESS, PBM_SETPOS, old+1, 0);
			SendDlgItemMessage(gHWND, IDC_PROGRESS, WM_PAINT, 0, 0);
			old = (UINT)SendDlgItemMessage(gHWND, IDC_PROGRESS, PBM_GETPOS, 0, 0);
			Sleep(3);
		}
	}
		
	return progress;
}

bool DumpProcess(DWORD pid)
{
	gMemSnap = new MemorySnapshot;
	char filename[1024];
	OPENFILENAME ofln;

	memset(&filename, 0, sizeof(filename));
	memset(&ofln, 0, sizeof(OPENFILENAME));
	ofln.lStructSize = sizeof(OPENFILENAME);
	ofln.hwndOwner = gHWND;
	ofln.lpstrFile = filename;
	ofln.nMaxFile = sizeof(filename);
	ofln.lpstrFilter = "snap\0*.snap\0All\0*.*\0";
	ofln.nFilterIndex = 1;
	ofln.lpstrFileTitle = NULL;
	ofln.nMaxFileTitle = 0;
	ofln.lpstrInitialDir = NULL;
	ofln.lpstrDefExt = ".snap";
	ofln.Flags = OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT;
	GetSaveFileName(&ofln);
	CommDlgExtendedError();
	return gMemSnap->Dump(pid, filename);
}

INT_PTR CALLBACK MainDlgProc(HWND hwndDlg, UINT message, WPARAM wParam, LPARAM lParam) 
{
	int lbItem=0;
	HWND hwndList=0;
	DWORD pid=0xFFFFFFFF;

	HDC dc = 0;
	PAINTSTRUCT ps;
	gHWND = hwndDlg;

	char szpid[1024] = {0};

	switch (message)
	{
		case WM_INITDIALOG:
			// reset progress bar
			SetProgressBar(0);
			gProcList = new ProcessList(hwndDlg, hInst);
			gProcList->FillList();
			szArglist = CommandLineToArgvW(GetCommandLineW(), &nArgs);	
			if(nArgs > 1) {
				wsprintf(szpid, "%S", szArglist[1]);
				gProcList->SetSelectionFromPid(atoi(szpid));
				if(nArgs >2 ) {
					MemorySnapshot *gMemSnap = new MemorySnapshot;
					char filename[MAX_PATH];
					wsprintf(filename, "%S", szArglist[2]);
					bool res = gMemSnap->Dump(atoi(szpid), filename);
					SendMessage(hwndDlg, WM_CLOSE, IDC_DUMP, (LPARAM)res);
				} else {
					DumpProcess(atoi(szpid));
				}
			}
			return TRUE;

		case WM_PAINT:
			{
				BeginPaint(gHWND, &ps);
				RECT rc;
				GetClientRect(gHWND, &rc); 
				EndPaint(gHWND, &ps);
			}
			break;

		case WM_CLOSE:
			delete gProcList;
			gProcList = 0;
			EndDialog(gHWND, 0);
			ExitProcess((UINT)lParam);
			break;

		case WM_COMMAND:
			switch(LOWORD(wParam))
			{
				case IDC_DUMP:
					pid = gProcList->GetSelectedPid();
					gProcList->EnableDisable(FALSE);
					DumpProcess(pid);
					gProcList->EnableDisable(TRUE);
					break;
					
				case IDC_REFRESH:
					gProcList->FillList();
					break;

				case IDC_EXIT:
					SendMessage(gHWND, WM_CLOSE, 0, 0);
					break;


				case IDC_PROCLIST:
					if(pid == 0xFFFFFFFF) {
						if(gProcList) {
							pid = gProcList->GetSelectedPid();
						}
						if(pid == 0xFFFFFFFF)
							EnableWindow(GetDlgItem(gHWND, IDC_DUMP), TRUE);
					}
					switch (HIWORD(wParam)) 
					{ 
						case LBN_DBLCLK:
								SendMessage(gHWND, WM_COMMAND, IDC_DUMP, 0);
								break;
						default:
							break;
					}

				default:
					break;
			}
		default:
			break;

	}
//	UpdateWindow(gHWND);
	return (INT_PTR)FALSE;
}