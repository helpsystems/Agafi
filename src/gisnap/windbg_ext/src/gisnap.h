#include <windows.h>

#ifdef __WIN64
	#define KDEXT_64BIT 
#endif
#include <wdbgexts.h>

#include <DbgEng.h>
#include <Psapi.h>
#include <TlHelp32.h>

#include <stdint.h> 

#include <iostream>
#include <vector>

#include "snapshotformat.h"

#ifndef __GISNAP__
	#define __GISNAP__

//#define MEM_BLOCK DUMPBLOCKV10
#define MEM_BLOCK DUMPBLOCKV20

class GiSnapDump
{
	private:
		IDebugClient* g_Client;

		IDebugControl* g_Control;
		IDebugSymbols* g_Symbols;
		IDebugSymbols2* g_Symbols2;

		IDebugDataSpaces2* g_DataSpaces2;
		IDebugDataSpaces3* g_DataSpaces3;
		IDebugDataSpaces4* g_DataSpaces4;

		IDebugSystemObjects *g_SystemObjects;

		std::vector<MEM_BLOCK> memblocks;
		std::vector<MODULEENTRY32> __modulelist;

		void GiSnapDump::__getStrForProt(uint32_t prot, char* dest);
		void GiSnapDump::__getStrForNativeProt(uint32_t prot, char *dest);

		void GiSnapDump::__getStrForStat(uint32_t stat, char* dest);

		uint32_t GiSnapDump::__translateProtFlags(uint32_t prot);
		void GiSnapDump::__setASLRDEP(MEM_BLOCK *tmpblock, uint64_t dllbase);

		void GiSnapDump::__getBlockInfo(MEM_BLOCK *tmpblock, char * name);

		uint32_t GiSnapDump::__getArch();
		uint32_t GiSnapDump::__getOS();

		void GiSnapDump::__getMemRegionName(uint64_t, char *symname);
		void GiSnapDump::__printBlockInfo(MEM_BLOCK *);

	public:
		GiSnapDump::GiSnapDump();
		GiSnapDump::~GiSnapDump();
		void GiSnapDump::TakeSnapshot(char *filename);
};


#endif
