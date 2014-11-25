#include "stdafx.h"
#include "logwindow.h"
#include <stdio.h>

LogWindow::LogWindow(HWND hwndDlg, HINSTANCE hInstance)
{
	_parent = hwndDlg;
	_hinstance = hInstance;
	_currentline = 0;
	_hwnd = GetDlgItem(hwndDlg, IDC_LOGLIST); 
}

LogWindow::~LogWindow()
{
	CloseWindow(_hwnd);
}

void LogWindow::Clear()
{
	SendDlgItemMessage(_parent, IDC_LOGLIST, LB_RESETCONTENT, (WPARAM)0, (LPARAM)0);
}

void LogWindow::LogPrint(char *formatstring, ...)
{
	va_list args;
	va_start(args, formatstring);

	char msg[1024];

	memset(msg, 0, sizeof(msg));

	_vsnprintf(msg, sizeof(msg)-2, formatstring, args);
	SendMessage(_hwnd, LB_INSERTSTRING, _currentline, (LPARAM)msg);
	SendMessage(_hwnd, LB_SETTOPINDEX, _currentline, (LPARAM)0);
	_currentline++;
	lstrcat(msg, "\n");
	FILE *logfile = fopen("roptool.log", "a+");
	fputs(msg, logfile);
	fclose(logfile);
	SendMessage(_hwnd, WM_PAINT, 0, 0);
}
