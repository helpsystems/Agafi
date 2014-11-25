#ifndef LOGWINDOW_H
	#define LOGWINDOW_H

class LogWindow
{
	public:	
		LogWindow(HWND parent, HINSTANCE hInstance);
		~LogWindow();
		void LogPrint(char *formatstring, ...);
		void Clear(void);
		HWND _hwnd;
	private:
		HINSTANCE _hinstance;

		HWND _parent;
		DWORD _currentline;
};


#endif