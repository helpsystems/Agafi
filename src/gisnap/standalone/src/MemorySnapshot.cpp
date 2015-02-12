#include "stdafx.h"
#include <windows.h>
#include <DbgHelp.h>
#include "memorysnapshot.h"

#include <Psapi.h>

extern int SetProgressBar(unsigned int progress);

MemorySnapshot::MemorySnapshot()
{
	hprocess = 0;
}

MemorySnapshot::~MemorySnapshot()
{
	hprocess = 0;
}

uint32_t MemorySnapshot::__getArch()
{
	SYSTEM_INFO sysinfo = {0};
	uint32_t res = 0;

	GetSystemInfo(&sysinfo);

	switch(sysinfo.wProcessorArchitecture) {
		case PROCESSOR_ARCHITECTURE_AMD64:
			res = ARCH_X64;
			break;

		case PROCESSOR_ARCHITECTURE_INTEL:
			res = ARCH_X86;
			break;

		case PROCESSOR_ARCHITECTURE_ARM:
			res = ARCH_ARM;
			break;

	}
	return res;
}


void MemorySnapshot::__getBlockInfo(MEM_BLOCK *tmpblock, char *name)
{
	*name = 0;
	HANDLE h_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, hpid);
	if(h_snapshot == INVALID_HANDLE_VALUE)
		return;
	MODULEENTRY32 __modentry;
	__modentry.dwSize = sizeof(MODULEENTRY32);

	SetLastError(0);	
	if(Module32First(h_snapshot, &__modentry) == FALSE)
		return;
	do {
		if((tmpblock->BaseAddress >= (uint64_t)__modentry.modBaseAddr) && (tmpblock->BaseAddress < (uint64_t)(__modentry.modBaseAddr+__modentry.modBaseSize))) {
			lstrcpyn(name, __modentry.szModule, 1024);
			__setASLRDEP(tmpblock, (uint64_t)__modentry.modBaseAddr);
			break;
		}

		if(GetLastError() == ERROR_NO_MORE_FILES)
			break;
		__modulelist.push_back(__modentry);
	} while(Module32Next(h_snapshot, &__modentry));
	CloseHandle(h_snapshot);
}

// sets memory region flags corresponding to ASLR and/or DEP dllCharacteristics
void MemorySnapshot::__setASLRDEP(MEM_BLOCK *tmpblock, uint64_t dllbase)
{
	ULONG modidx = 0;
	ULONG64 modbase = dllbase;

	IMAGE_DOS_HEADER hdr_mz;
	ReadProcessMemory(hprocess, (LPCVOID)modbase, &hdr_mz, sizeof(IMAGE_DOS_HEADER), NULL);
	if(hdr_mz.e_magic == IMAGE_DOS_SIGNATURE) {
		IMAGE_NT_HEADERS hdr_nt;
		ReadProcessMemory(hprocess, (LPCVOID)(modbase+hdr_mz.e_lfanew), &hdr_nt, sizeof(IMAGE_NT_HEADERS), NULL);
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

// try to guess process arch
bool MemorySnapshot::__isProcessSameArch()
{
	BOOL res = FALSE;
#ifndef _WIN64		// 32bit process fails to create snapshot of 64bit process
	HANDLE h_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, hpid);
	if(h_snapshot != INVALID_HANDLE_VALUE) {
		res = TRUE;
	}
	CloseHandle(h_snapshot);
#else
	IsWow64Process(hprocess, &res);
	res = !res;
#endif
	return (bool)res;
}


uint32_t MemorySnapshot::__translateProtFlags(uint32_t prot)
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

bool MemorySnapshot::Dump(DWORD pid, char *filename)
{
	bool res = false;		// return value

	hpid = pid;

	// open process
	hprocess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ , FALSE, hpid);
	if(hprocess == 0)
		return res;

	BOOL bIs64 = (__getArch() == ARCH_X64);

	if(!__isProcessSameArch())
		return res;		// we got passed an x64 pid on a 32bit gisnap or vice versa

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
			memblocks.push_back(tmpblock);
		}
		addr += info.RegionSize+1;
	} 

	// write
	// create dumpfile
	FILE *dumpfile = fopen(filename, "wb" );
	if(!dumpfile) {
		return res;
	}

	SNAPSHOTFILE snphdr = {0};
	snphdr.sig = 0x70616E73;
	snphdr.version = 0x00000002;
	snphdr.flags = __getArch() | OS_WINDOWS;

	snphdr.blockcount = (uint32_t)memblocks.size();
	if(snphdr.blockcount > 0)
		res = true;

	// write header SNAPSHOTFILE
	fwrite ( &snphdr, sizeof(SNAPSHOTFILE) , 1 , dumpfile);

	unsigned int blkcnt=0;

	SetProgressBar(0);

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
		ReadProcessMemory(hprocess, (LPCVOID)block->BaseAddress, buffer, (ULONG)block->RegionSize, NULL);
		fwrite ( buffer , (size_t)block->RegionSize, 1 , dumpfile);
		delete buffer;
		SetProgressBar(blkcnt*100/snphdr.blockcount);
	}
	fclose(dumpfile);
	CloseHandle(hprocess);
	SetProgressBar(100);

	return res;
}