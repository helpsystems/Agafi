#ifndef MEMSNAP_H
#define MEMSNAP_H


#include "snapshotformat.h"
#include <iostream>
#include <vector>


#define MEM_BLOCK DUMPBLOCKV20

class MemorySnapshot
{
	public:	
		MemorySnapshot();
		~MemorySnapshot();
		bool MemorySnapshot::Dump(HANDLE hprocess, char *filename);
		void MemorySnapshot::__setASLRDEP(MEM_BLOCK *tmpblock);
	
	private:
		uint32_t MemorySnapshot::__getArch();
		uint32_t MemorySnapshot::__translateProtFlags(uint32_t prot);
		void MemorySnapshot::__getName(MEM_BLOCK *tmpblock, char *name);

		HANDLE hprocess;
		std::vector<MEM_BLOCK> memblocks;
	
};
#endif