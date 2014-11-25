#define _CRT_SECURE_NO_DEPRECATE

#include <windows.h>
#include "MemorySnapshot.h"
#include <stdio.h>
#include <string.h>
//#include <winnt.h>                     // Only if you call ODBG2_Pluginmainloop
                                       
#include "plugin.h"

#define PLUGINNAME     L"gisnap"    // Unique plugin name
#define VERSION        L"2.00.01"      // Plugin version

HINSTANCE        hdllinst;             // Instance of plugin DLL


void DumpProcess(HANDLE hprocess)
{
	MemorySnapshot *gMemSnap = new MemorySnapshot;

	WCHAR filename[1024];
	char filenameA[1024];
	OPENFILENAME ofln;
	memset(&filename, 0, sizeof(filename));
	memset(&ofln, 0, sizeof(OPENFILENAME));
	ofln.lStructSize = sizeof(OPENFILENAME);
	ofln.hwndOwner = hwollymain;
	ofln.lpstrFile = filename;
	ofln.nMaxFile = sizeof(filename);
	ofln.lpstrFilter = L"Snapshot\0*.snap\0All\0*.*\0";
	ofln.nFilterIndex = 1;
	ofln.lpstrFileTitle = NULL;
	ofln.nMaxFileTitle = 0;
	ofln.lpstrInitialDir = NULL;
	ofln.lpstrDefExt = L".snap";
	ofln.Flags = OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT;

	GetSaveFileName(&ofln);
	CommDlgExtendedError();
	wcstombs(filenameA, filename, 1024);
	gMemSnap->Dump(hprocess, filenameA);
	delete gMemSnap;

	MessageBox(hwollymain, L"Snapshot dump finished.", L"Done!", MB_OK);
}

// main menu click
static int MtakeSnapshot(t_table *pt,wchar_t *name,ulong index,int mode) {
	int ret;

	switch(mode) {
		case MENU_VERIFY:
			ret=MENU_NORMAL;
			break;
		case MENU_EXECUTE:
			ret=MENU_NOREDRAW;
			if(run.status == STAT_IDLE) {
				MessageBox(hwollymain, L"NO TARGET ATTACHED", L"ERROR", MB_OK);
			} else {
				DumpProcess(process);
			}
			break;
		default:
			ret=MENU_ABSENT;
			break;
	}
	return ret;
};

// Plugin menu that will appear in the main OllyDbg menu.
static t_menu mainmenu[] = {
  { L"|gisnap", L"take memory snapshot", K_NONE, MtakeSnapshot, NULL, 0 },
  { NULL, NULL, K_NONE, NULL, NULL, 0 }
};

// Adds items either to main OllyDbg menu (type=PWM_MAIN) or to popup menu in
extc t_menu * __cdecl ODBG2_Pluginmenu(wchar_t *type) {
  if (wcscmp(type,PWM_MAIN)==0)
    // Main menu.
    return mainmenu;
  return NULL;                         // No menu
};

BOOL WINAPI DllEntryPoint(HINSTANCE hi,DWORD reason,LPVOID reserved) {
  if (reason==DLL_PROCESS_ATTACH)
    hdllinst=hi;                       // Mark plugin instance
  return 1;                            // Report success
};

// ODBG2_Pluginquery() is a "must" for valid OllyDbg plugin.
extc int __cdecl ODBG2_Pluginquery(int ollydbgversion,ulong *features, wchar_t pluginname[SHORTNAME],wchar_t pluginversion[SHORTNAME]) {
  if (ollydbgversion<201)
    return 0;
  // Report name and version to OllyDbg.
  wcscpy(pluginname,PLUGINNAME);       // Name of plugin
  wcscpy(pluginversion,VERSION);       // Version of plugin
  return PLUGIN_VERSION;               // Expected API version
};

extc int __cdecl ODBG2_Plugininit(void) {
  return 0;
};

// Function is called when user opens new or restarts current application.
// Plugin should reset internal variables and data structures to the initial
// state.
extc void __cdecl ODBG2_Pluginreset(void) {

};

extc int __cdecl ODBG2_Pluginclose(void) {
  return 0;
};

extc void __cdecl ODBG2_Plugindestroy(void) {

};


