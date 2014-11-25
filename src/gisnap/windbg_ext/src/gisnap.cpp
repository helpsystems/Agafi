#include "gisnap.h"

GiSnapDump::GiSnapDump()
{
	g_Client = NULL;
	HRESULT res = DebugCreate(__uuidof(IDebugClient), (void**)&g_Client);
	if(S_OK != res) {
		dprintf("ERROR: Cannot talk to dbgeng.dll\n");
		return;
	}

	g_Client->QueryInterface(__uuidof(IDebugControl), (void**)&g_Control);
    g_Client->QueryInterface(__uuidof(IDebugSymbols), (void**)&g_Symbols);
    g_Client->QueryInterface(__uuidof(IDebugSymbols2), (void**)&g_Symbols2);

	g_Client->QueryInterface(__uuidof(IDebugDataSpaces2), (void**)&g_DataSpaces2);
	g_Client->QueryInterface(__uuidof(IDebugDataSpaces3), (void**)&g_DataSpaces3);
	g_Client->QueryInterface(__uuidof(IDebugDataSpaces4), (void**)&g_DataSpaces4);

	g_Client->QueryInterface(__uuidof(IDebugSystemObjects), (void**)&g_SystemObjects);

	// connect dbgeng.dll to the running debugger session
	g_Client->ConnectSession(DEBUG_CONNECT_SESSION_NO_VERSION | DEBUG_CONNECT_SESSION_NO_ANNOUNCE, NULL);
	if(S_OK != res) {
		dprintf("ERROR: Cannot conntect dbgeng to current debugger session\n");
		return;
	}

	ULONG myclass = 0;
	ULONG qual = 0;

	g_Control->GetDebuggeeType(&myclass, &qual);

	if(myclass == DEBUG_CLASS_UNINITIALIZED) {
		dprintf("ERROR: attach to your target first!\n\n");
	}
}


void GiSnapDump::__getStrForNativeProt(uint32_t prot, char *dest)
{
	switch(prot & 0xFF)
	{
		case PAGE_EXECUTE:
			strcpy(dest, "EXECUTE");
			break;
		case PAGE_EXECUTE_READ:
			strcpy(dest, "EXECUTE_READ");
			break;
		case PAGE_EXECUTE_READWRITE:
			strcpy(dest, "EXECUTE_READWRITE");
			break;
		case PAGE_EXECUTE_WRITECOPY:
			strcpy(dest, "EXECUTE_WRITECOPY");
			break;
		case PAGE_NOACCESS:
			strcpy(dest, "NOACCESS");
			break;
		case PAGE_READONLY:
			strcpy(dest, "READONLY");
			break;
		case PAGE_READWRITE:
			strcpy(dest, "READWRITE");
			break;
		case PAGE_WRITECOPY:
			strcpy(dest, "WRITECOPY");
			break;
		default:
			strcpy(dest, "UNKNOWN");
			break;
	}

	if(prot & PAGE_GUARD)
		strcat(dest, "|GUARD");
	if(prot & PAGE_NOCACHE)
		strcat(dest, "|NOCACHE");
	if(prot & PAGE_GUARD)
		strcat(dest, "|WRITECOMBINE");
}

void GiSnapDump::__getStrForProt(uint32_t prot, char *dest)
{
	if(prot & M_READ) {
		strcat(dest, "R");
	} else {
		strcat(dest, "-");
	}

	if(prot & M_WRITE) {
		strcat(dest, "W");
	} else {
		strcat(dest, "-");
	}

	if(prot & M_EXEC) {
		strcat(dest, "X");
	} else {
		strcat(dest, "-");
	}

	if(prot & M_ASLR) {
		strcat(dest, " ASLR");
	}

	if(prot & M_DEP) {
		strcat(dest, " DEP");
	}
}

uint32_t GiSnapDump::__translateProtFlags(uint32_t prot)
{
	uint32_t flags=0;
	switch(prot & 0xFF)
	{
		case PAGE_EXECUTE:
			flags = M_EXEC;
			break;
		case PAGE_EXECUTE_READ:
			flags = M_EXEC | M_READ;
			break;
		case PAGE_EXECUTE_READWRITE:
			flags = M_EXEC | M_READ | M_WRITE;
			break;
		case PAGE_EXECUTE_WRITECOPY:
			flags = M_EXEC | M_READ | M_WRITE;
			break;
		case PAGE_READONLY:
			flags = M_READ;
			break;
		case PAGE_READWRITE:
			flags = M_READ | M_WRITE;
			break;
		case PAGE_WRITECOPY:
			flags = M_WRITE;
			break;
	}
	return flags;
}

void GiSnapDump::__getStrForStat(uint32_t stat, char *dest)
{
	switch(stat)
	{
		case MEM_COMMIT:
			strcpy(dest, "COMMIT");
			break;
		case MEM_RESERVE:
			strcpy(dest, "RESERVE");
			break;
		case MEM_FREE:
			strcpy(dest, "FREE");
			break;
		case MEM_PRIVATE:
			strcpy(dest, "PRIVATE");
			break;
		case MEM_MAPPED:
			strcpy(dest, "MAPPED");
			break;
		case MEM_IMAGE:
			strcpy(dest, "IMAGE");
			break;
	}
}

uint32_t GiSnapDump::__getArch()
{
	ULONG processor_type=0;
	g_Control->GetExecutingProcessorType(&processor_type);

	uint32_t res = 0;
	switch(processor_type) {
		case IMAGE_FILE_MACHINE_I386:
			res = ARCH_X86;
			break;
		case IMAGE_FILE_MACHINE_ARM:
			res = ARCH_ARM;
			break;
		case IMAGE_FILE_MACHINE_AMD64:
			res = ARCH_X64;
			break;
		default:
			res = 0;
			break;
	}
	return res;
}

// gets symbol name for a memory address
void GiSnapDump::__getMemRegionName(uint64_t base, char *name)
{
	char symname[1024] = {0};
	uint8_t namesize=255;

	HRESULT status = g_Symbols->GetNameByOffset(base, symname, sizeof(symname), NULL, NULL);
	if(status == E_FAIL) {
		memset(&symname, 0, 1);
	}

	char *bang = strstr(symname, "!");
	if(bang) {
		if(bang-symname < namesize)
			namesize = (uint8_t)(bang-symname);
	}

	strncpy(name, symname, namesize);
}

// print information about a memory block to the debugger console
void GiSnapDump::__printBlockInfo(MEM_BLOCK *tmpblock)
{
	char name[1024] = {0};
//	__getMemRegionName(tmpblock->BaseAddress, name);
//	strcpy((char *)&tmpblock->name, name);

	char prot[1024] = {0};
	__getStrForProt(tmpblock->Protect, prot);

	dprintf("% 10s base:%08I64x size:%08I64x, prot:%s\n", tmpblock->name, tmpblock->BaseAddress, tmpblock->RegionSize, prot);
}
/*
// sets memory region flags corresponding to ASLR and/or DEP dllCharacteristics
void GiSnapDump::__setASLRDEP(MEM_BLOCK *tmpblock)
{
	ULONG modidx = 0;
	ULONG64 modbase = 0;

	HRESULT res = g_Symbols->GetModuleByOffset(tmpblock->BaseAddress, 0, &modidx, &modbase);

	IMAGE_DOS_HEADER hdr_mz;
	ReadMemory((ULONG_PTR)modbase, &hdr_mz, sizeof(IMAGE_DOS_HEADER), NULL);
	if(hdr_mz.e_magic == IMAGE_DOS_SIGNATURE) {
		IMAGE_NT_HEADERS hdr_nt;
		ReadMemory((ULONG_PTR)(modbase+hdr_mz.e_lfanew), &hdr_nt, sizeof(IMAGE_NT_HEADERS), NULL);
		if(hdr_nt.Signature == IMAGE_NT_SIGNATURE) {
			IMAGE_FILE_HEADER hdr_file;
			memcpy(&hdr_file, &hdr_nt.FileHeader, sizeof(IMAGE_FILE_HEADER));

			IMAGE_OPTIONAL_HEADER hdr_optional;
			memcpy(&hdr_optional, &hdr_nt.OptionalHeader, sizeof(IMAGE_OPTIONAL_HEADER));
			if((hdr_optional.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) || (hdr_optional.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)) {
				if(hdr_optional.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) {
					tmpblock->Protect |= M_ASLR;
				}

				if(hdr_optional.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) {
					tmpblock->Protect |= M_DEP;
				}
			}
		}
	}
}
*/

void GiSnapDump::__getBlockInfo(MEM_BLOCK *tmpblock, char * name)
{
	*name = 0;
	ULONG64 hprocess = 0;
	g_SystemObjects->GetCurrentProcessHandle(&hprocess);

	HANDLE h_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetProcessId((HANDLE)hprocess));
	
	if(h_snapshot == INVALID_HANDLE_VALUE)
		return;
	MODULEENTRY32 __modentry;
	__modentry.dwSize = sizeof(MODULEENTRY32);

	SetLastError(0);	
	if(Module32First(h_snapshot, &__modentry) == FALSE)
		return;
	do {
		if((tmpblock->BaseAddress >= (uint64_t)__modentry.modBaseAddr) && (tmpblock->BaseAddress < (uint64_t)(__modentry.modBaseAddr+__modentry.modBaseSize))) {
//			lstrcpyn(name, __modentry.szModule, 1024);
			wsprintfA(name, "%S", __modentry.szModule);
			__setASLRDEP(tmpblock, (uint64_t)__modentry.modBaseAddr);
			break;
		}

		if(GetLastError() == ERROR_NO_MORE_FILES)
			break;
		__modulelist.push_back(__modentry);
	} while(Module32Next(h_snapshot, &__modentry));
	CloseHandle(h_snapshot);
}


void  GiSnapDump::TakeSnapshot(char *filename)
{
	ULONG64 hprocess = 0;
	g_SystemObjects->GetCurrentProcessHandle(&hprocess);

	BOOL bIs64 = (__getArch() == ARCH_X64) ;

	// fill a vector with valid memory blocks
	MEM_BLOCK tmpblock = {0};
	memset(&tmpblock.name, 0, 256);
	MEMORY_BASIC_INFORMATION info = {0};
	uint64_t addr=0;
	while(VirtualQueryEx((HANDLE)hprocess, (LPVOID)addr, &info, sizeof(info))) {
		if((info.State == MEM_COMMIT) || (info.Type == MEM_MAPPED) || (info.Type == MEM_IMAGE)) {
			if(bIs64) {
				tmpblock.BaseAddress = (uint64_t)info.BaseAddress;
				tmpblock.RegionSize = info.RegionSize;
			} else {
				tmpblock.BaseAddress = (DWORD)info.BaseAddress;	//cast takes care of idiotic sign extension on pointers
				tmpblock.RegionSize = (DWORD)info.RegionSize;
			}
			if(info.Protect) {
				tmpblock.Protect = __translateProtFlags(info.Protect);
			} else {
				tmpblock.Protect = __translateProtFlags(info.AllocationProtect);
			}
			__getBlockInfo(&tmpblock, (char *)&tmpblock.name);
			__printBlockInfo(&tmpblock);
			memblocks.push_back(tmpblock);
		}
		addr += info.RegionSize+1;
	} 

	// write
	// create dumpfile
	FILE *dumpfile = fopen(filename, "wb" );
	if(!dumpfile) {
		return;
	}

	SNAPSHOTFILE snphdr = {0};
	snphdr.sig = 0x70616E73;
	snphdr.version = 0x00000002;
	snphdr.flags = __getArch() | OS_WINDOWS;

	snphdr.blockcount = (uint32_t)memblocks.size();

	// write header SNAPSHOTFILE
	fwrite ( &snphdr, sizeof(SNAPSHOTFILE) , 1 , dumpfile);

	unsigned int blkcnt=0;

//	SetProgressBar(0);

	for (std::vector<MEM_BLOCK>::iterator block = memblocks.begin(); block != memblocks.end(); ++block, ++blkcnt)
	{

		MEM_BLOCK tmpblock = {0};

		tmpblock.RegionSize = block->RegionSize;
		tmpblock.BaseAddress = block->BaseAddress;
		tmpblock.Protect = block->Protect;
		strncpy((char *)&tmpblock.name, (char *)&block->name, 255);

		// write MEM_BLOCK
		fwrite ( &tmpblock, sizeof(MEM_BLOCK) , 1 , dumpfile);
		// write data
		uint8_t *buffer = new uint8_t [(unsigned int)block->RegionSize];
		ReadProcessMemory((HANDLE)hprocess, (LPCVOID)block->BaseAddress, buffer, (ULONG)block->RegionSize, NULL);
		fwrite ( buffer , (size_t)block->RegionSize, 1 , dumpfile);
		delete buffer;
//		SetProgressBar(blkcnt*100/snphdr.blockcount);
	}
	fclose(dumpfile);
	dprintf("done!\n");
//	CloseHandle(hprocess);
//	SetProgressBar(100);
}

// sets memory region flags corresponding to ASLR and/or DEP dllCharacteristics
void GiSnapDump::__setASLRDEP(MEM_BLOCK *tmpblock, uint64_t dllbase)
{
	ULONG modidx = 0;
	ULONG64 modbase = dllbase;

	ULONG64 hprocess = 0;
	g_SystemObjects->GetCurrentProcessHandle(&hprocess);

	IMAGE_DOS_HEADER hdr_mz;
	ReadProcessMemory((HANDLE)hprocess, (LPCVOID)modbase, &hdr_mz, sizeof(IMAGE_DOS_HEADER), NULL);
	if(hdr_mz.e_magic == IMAGE_DOS_SIGNATURE) {
		IMAGE_NT_HEADERS hdr_nt;
		ReadProcessMemory((HANDLE)hprocess, (LPCVOID)(modbase+hdr_mz.e_lfanew), &hdr_nt, sizeof(IMAGE_NT_HEADERS), NULL);
		if(hdr_nt.Signature == IMAGE_NT_SIGNATURE) {
			IMAGE_FILE_HEADER hdr_file;
			memcpy(&hdr_file, &hdr_nt.FileHeader, sizeof(IMAGE_FILE_HEADER));

			IMAGE_OPTIONAL_HEADER hdr_optional;
			memcpy(&hdr_optional, &hdr_nt.OptionalHeader, sizeof(IMAGE_OPTIONAL_HEADER));
			if((hdr_optional.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) || (hdr_optional.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)) {
				if(hdr_optional.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) {
					tmpblock->Protect |= M_ASLR;
				}

				if(hdr_optional.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) {
					tmpblock->Protect |= M_DEP;
				}
			}
		}
	}
}

/*

void GiSnapDump::TakeSnapshot(char *filename)
{
	ULONG64 hprocess = 0;
	g_SystemObjects->GetCurrentProcessHandle(&hprocess);

	//check x64
	BOOL bIs64 = (__getArch() == ARCH_X64);

	MEMORY_BASIC_INFORMATION info = {0};

	// fill a vector with valid memory blocks
	MEM_BLOCK tmpblock = {0};

	uint64_t addr=0;
	while(VirtualQueryEx((HANDLE)hprocess, (LPVOID)addr, &info, sizeof(info))) {
		if((info.State == MEM_COMMIT) && ((info.Type == MEM_MAPPED) || (info.Type == MEM_IMAGE))) {
			if(bIs64) {
				tmpblock.BaseAddress = (uint64_t)info.BaseAddress;
				tmpblock.RegionSize = info.RegionSize;
			} else {
				tmpblock.BaseAddress = (DWORD)info.BaseAddress;	//cast takes care of idiotic sign extension on pointers
				tmpblock.RegionSize = (DWORD)info.RegionSize;
			}
			tmpblock.Protect = __translateProtFlags(info.Protect);

			char name[1024] = {0};
			__getMemRegionName(tmpblock.BaseAddress, name);
			strncpy((char *)tmpblock.name, name, sizeof(tmpblock.name));

			// if region is part of an executable image we set ASLR and DEP flags accordingly
			if(info.Type == MEM_IMAGE) {
				__setASLRDEP(&tmpblock);
			}

			// print block info on the console
			__printBlockInfo(&tmpblock);
			// save for later
			memblocks.push_back(tmpblock);
		}
		addr += info.RegionSize;
	} 

	// create dumpfile
	FILE *dumpfile = fopen(filename, "wb" );
	if(!dumpfile) {
		dprintf("ERROR: cannot write %s\r\n", filename);
		return;
	}

	dprintf("Writting %s...", filename);
	SNAPSHOTFILE snphdr = {0};
	snphdr.sig = 0x70616E73;
	snphdr.version = 0x00000002;

	snphdr.flags = __getArch() | OS_WINDOWS;
	snphdr.blockcount = (uint32_t)memblocks.size();

	// write header SNAPSHOTFILE
	fwrite ( &snphdr, sizeof(SNAPSHOTFILE) , 1 , dumpfile);

	for (std::vector<MEM_BLOCK>::iterator block = memblocks.begin(); block != memblocks.end(); ++block)
	{

		MEM_BLOCK tmpblock = {0};

		tmpblock.RegionSize = block->RegionSize;
		tmpblock.BaseAddress = block->BaseAddress;
		strncpy((char *)&tmpblock.name, (char *)block->name, sizeof(tmpblock.name));
		tmpblock.Protect = block->Protect;
		
		// write MEM_BLOCK
		fwrite ( &tmpblock, sizeof(MEM_BLOCK) , 1 , dumpfile);
		// write data
		uint8_t *buffer = new uint8_t [(unsigned int)block->RegionSize];
		ReadMemory((ULONG)block->BaseAddress, buffer, (ULONG)block->RegionSize, NULL);
		fwrite ( buffer , (size_t)block->RegionSize, 1 , dumpfile);
		delete buffer;
	}
	fclose(dumpfile);
	dprintf("done!\n");
}
*/
GiSnapDump::~GiSnapDump()
{
	if (g_Client != NULL)
	{
		g_Client->EndSession(DEBUG_END_PASSIVE);
		g_Client->Release();
		g_Client = NULL;

		g_Control->Release();
		g_Symbols->Release();
		g_Symbols2->Release();
		g_DataSpaces2->Release();
		g_DataSpaces3->Release();
		g_DataSpaces4->Release();
		g_SystemObjects->Release();

	}

	g_Control = NULL;
	g_Symbols = NULL;
	g_Symbols2 = NULL;
	g_DataSpaces2 = NULL;
	g_DataSpaces3 = NULL;
	g_SystemObjects = NULL;
}
