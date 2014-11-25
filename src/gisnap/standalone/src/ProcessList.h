#ifndef PROCLIST_H
	#define PROCLIST_H


typedef struct _processListEntry {
	DWORD pid;
	char name[1024];
} processListEntry;

class ProcessList
{
	public:	
		ProcessList(HWND hwndDlg, HINSTANCE hInstance);
		~ProcessList();
		DWORD ProcessList::GetSelectedPid();
		void ProcessList::SetSelectionFromPid(DWORD pid);
		void ListPrint(char *formatstring, ...);
		void ListEmpty();
		void EnableDisable(BOOL val);
		static INT_PTR CALLBACK StaticDialogProcedure(HWND pDialog, UINT msg, WPARAM wParam, LPARAM lParam);
		INT_PTR CALLBACK DlgProc(HWND hwndDlg, UINT message, WPARAM wParam, LPARAM lParam);
		void FillList();
	private:
		HWND _hwnd;
		HWND _parent;
		DWORD _currentline;
		DWORD _done;
		HINSTANCE _hinstance;
		processListEntry aListNames[1024];
};


#endif