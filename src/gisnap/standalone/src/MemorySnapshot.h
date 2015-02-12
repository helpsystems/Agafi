#ifndef MEMSNAP_H
#define MEMSNAP_H

#include <DbgEng.h>

#include <TlHelp32.h>
#include "snapshotformat.h"
#include <iostream>
#include <vector>


#define MEM_BLOCK DUMPBLOCKV20

class MemorySnapshot
{
	public:	
		MemorySnapshot();
		~MemorySnapshot();
		bool MemorySnapshot::Dump(DWORD pid, char *filename);
	
	private:
		void MemorySnapshot::__getBlockInfo(MEM_BLOCK *tmpblock, char *name);
		void MemorySnapshot::__setASLRDEP(MEM_BLOCK *tmpblock, uint64_t dllbase);

		uint32_t MemorySnapshot::__getArch();
		bool MemorySnapshot::__isProcessSameArch();
		uint32_t MemorySnapshot::__translateProtFlags(uint32_t prot);

		HANDLE hprocess;
		DWORD hpid;

		std::vector<MEM_BLOCK> memblocks;
		std::vector<MODULEENTRY32> __modulelist;
	
};
#endif