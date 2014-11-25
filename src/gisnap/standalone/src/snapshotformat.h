// standard structures for writting/reading Gadget Inspector snapshots

#ifndef __SNAPSHOTFORMAT
	#define __SNAPSHOTFORMAT

#include <stdint.h> 

// Memory protection flags
#define M_READ		0x01
#define M_WRITE		0x02
#define M_EXEC		0x04

#define M_ASLR		0x08	// ASLR is enabled
#define M_DEP		0x10	// DEP is enabled

// OS flags
#define OS_WINDOWS	0x0100
#define OS_LINUX	0x0200
#define OS_MACOS	0x0400
#define OS_ANDROID	0x0800
#define OS_IOS		0x1000

// Arch. flags
#define ARCH_X86	0x10000
#define ARCH_X64	0x20000
#define ARCH_ARM	0x40000
#define ARCH_PPC	0x80000

#pragma pack(push)
#pragma pack(1)
typedef struct _SNAPSHOTFILE
{
	uint32_t sig;			// signature: "snap" or 0x70616E73 in little endian
	uint32_t version;		// if version == 1: use DUMPBLOCKV10 / version == 2 uses DUMPBLOCKV20 and so on.
	uint32_t flags;			//
	uint32_t blockcount;
} SNAPSHOTFILE, *PSNAPSHOTFILE;

typedef struct _dumpblockV10
{
	uint64_t BaseAddress;
	uint64_t RegionSize;
	uint32_t Protect;		// see memory protection constants
} DUMPBLOCKV10, *PDUMPBLOCKV10;

typedef struct _dumpblockV20
{
	uint64_t BaseAddress;
	uint64_t RegionSize;
	uint32_t Protect;		// see memory protection constants
	uint8_t  name[256];
} DUMPBLOCKV20, *PDUMPBLOCKV20;

#pragma pack(pop)
#endif // __SNAPSHOTFORMAT