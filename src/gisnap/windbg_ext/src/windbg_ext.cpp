// SnapshotDumper windbg/ntsd extension.

#include <windows.h>
#include <imagehlp.h>

#ifdef __WIN64
	#define KDEXT_64BIT 
#endif
#include <wdbgexts.h>

#include "gisnap.h"

// Global Variable Needed For Functions
WINDBG_EXTENSION_APIS ExtensionApis = {0};
                      
// Global Variable Needed For Versioning
EXT_API_VERSION g_ExtApiVersion = {1 , 1 , EXT_API_VERSION_NUMBER , 0};

// dllmain
BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
		case DLL_PROCESS_ATTACH:
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
		case DLL_PROCESS_DETACH:
			break;
	}
	return TRUE;
}

// ExtensionApiVersion
LPEXT_API_VERSION WDBGAPI ExtensionApiVersion (void)
{
    return &g_ExtApiVersion;
}

// WinDbgExtensionDllInit
VOID WDBGAPI WinDbgExtensionDllInit (PWINDBG_EXTENSION_APIS lpExtensionApis, USHORT usMajorVersion, USHORT usMinorVersion)
{
     ExtensionApis = *lpExtensionApis;
}

// !help
DECLARE_API (help)
{
    dprintf("Gadget Inspector - SnapshotDumper\n\n");
    dprintf("!gisnap <output.dmp>\n");
}

// !gisnap
DECLARE_API (gisnap)
{

	if (!args || !*args) {
		dprintf("Usage: \n\t!gisnap <output.dmp>\n");
		return;
	}

	GiSnapDump *gsnp = new GiSnapDump;
	gsnp->TakeSnapshot((char *)args);
	delete gsnp;
}
