import os
import sys
import struct

M_READ		= 0x01
M_WRITE		= 0x02
M_EXEC		= 0x04

M_ASLR		= 0x08
M_DEP		= 0x10


#OS flags
OS_WINDOWS	= 0x0100
OS_LINUX	= 0x0200
OS_MACOS	= 0x0400
OS_ANDROID	= 0x0800
OS_IOS		= 0x1000

# Arch. flags
ARCH_X86	= 0x10000
ARCH_X64	= 0x20000
ARCH_ARM	= 0x40000
ARCH_PPC	= 0x80000

class Reader:
	def ReadH(self):
		val = struct.unpack("<H", self.data[self.fp:self.fp+2])[0]
		self.fp += 2
		return val

	def ReadL(self):
		value = struct.unpack("<L", self.data[self.fp:self.fp+4])[0]
		self.fp += 4
		return value

	def ReadB(self, length=1):
		fmt = "B" * length
		value = struct.unpack(fmt, self.data[self.fp:self.fp+length])
		data = ''
		for val in value:
			data += chr(val)
		self.fp += length
		return data

	def ReadQ(self):
		value = struct.unpack("<Q", self.data[self.fp:self.fp+8])[0]
		self.fp += 8
		return value

	def PeekB(self, length=1):
		data = self.ReadB(length)
		self.fp -= length
		return data

class BlockV10(Reader):
	def __init__(self, data):
		self.data = data
		self.fp = 0
		
		self.BaseAddress = self.ReadQ()
		self.RegionSize = self.ReadQ()
		self.Protect = self.ReadL()

	def getProtString(self):
		mystr = ''
		if(self.Protect & M_READ):
			mystr = "R"
		else:
			mystr = "-"
			
		if(self.Protect & M_WRITE):
			mystr += "W"
		else:
			mystr += "-"
			
		if(self.Protect & M_EXEC):
			mystr += "X"
		else:
			mystr += "-"
	
		if(self.Protect & M_ASLR):
			mystr += " ASLR"
		
		if(self.Protect & M_DEP):
			mystr += " DEP"	
		return mystr
		
	def dump(self):
		print "BaseAddress: %08lx - RegionSize: %08lx - Protect: %s" % (self.BaseAddress, self.RegionSize, self.getProtString())


class BlockV20(Reader):
	def __init__(self, data):
		self.data = data
		self.fp = 0
		
		self.BaseAddress = self.ReadQ()
		self.RegionSize = self.ReadQ()
		self.Protect = self.ReadL()
		self.name = self.ReadB(256)

	def getProtString(self):
		mystr = ''
		if(self.Protect & M_READ):
			mystr = "R"
		else:
			mystr = "-"
			
		if(self.Protect & M_WRITE):
			mystr += "W"
		else:
			mystr += "-"
			
		if(self.Protect & M_EXEC):
			mystr += "X"
		else:
			mystr += "-"
	
		if(self.Protect & M_ASLR):
			mystr += " ASLR"
		
		if(self.Protect & M_DEP):
			mystr += " DEP"	
		return mystr
		
	def dump(self):
		cleanname = self.name.strip("\x00\x20")
		print "% 10s BaseAddress:%08lx - RegionSize:%08lx - Protect:%s" % (cleanname, self.BaseAddress, self.RegionSize, self.getProtString())
			
class DumpReader(Reader):
	def __init__(self, filename):
		self.fp = 0

		fd = open(filename, 'rb')
		self.data = fd.read()
		fd.close()
		
		# read file hreader
		self.sig = self.ReadB(4)
		self.ver = self.ReadL()
		self.flags = self.ReadL()
		self.numblocks = self.ReadL()
	
		self.blocks = []
		
		# read blocks
		for i in range(0, self.numblocks):
			if(self.ver == 1):
				blockdata = self.ReadB(0x14)
				blk = BlockV10(blockdata)
				
			elif(self.ver == 2):
				blockdata = self.ReadB(0x114)
				blk = BlockV20(blockdata)

			self.blocks.append(blk)
			self.fp += blk.RegionSize
		
	def getFlagsString(self):
		str = ''
		# get OS name
		if(self.flags & OS_WINDOWS):
			str = 'OS_WINDOWS'
		elif(self.flags & OS_LINUX):
			str = 'OS_LINUX'
		elif(self.flags & OS_MACOS):
			str = 'OS_MACOS'
		elif(self.flags & OS_ANDROID):
			str = 'OS_ANDROID'
		elif(self.flags & OS_IOS):
			str = 'OS_IOS'
		# get Arch
		if(self.flags & ARCH_X86):
			str += '|ARCH_X86'
		elif(self.flags & ARCH_X64):
			str += '|ARCH_X64'
		elif(self.flags & ARCH_ARM):
			str += '|ARCH_ARM'
		elif(self.flags & ARCH_PPC):
			str += '|ARCH_PPC'
		return str

	def dump(self):
		print "sig: %s" % self.sig
		print "ver: %08lx" % self.ver
		print "flags: %s" % self.getFlagsString()
		print "numblocks: %08lx" % self.numblocks
		
		for blk in self.blocks:
			blk.dump()
			

def main(argv):
	if(len(argv) == 0):
		print "Usage: dumpinfo dumpfile.dmp\n"
	else:
		dr = DumpReader(argv[0])
		dr.dump()

if __name__ == "__main__":
   main(sys.argv[1:])
