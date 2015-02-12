##What is Agafi/ROP?

Agafi/ROP is a Win32 command line tool chain useful to find gadgets and build ROP-Chains used by x86 binary exploits.

##What is Agafi?

Agafi (Advanced Gadget Finder) is a x86 gadget-finder tool useful to find gadgets in programs, modules and running processes.

The ROP search engine is based on 4 points:
 1. Search by objective
 2. An "executable/module/process/misc" snapshot
 3. x86 code emulation (QEMU support)
 4. Black box gadget analysis

Implementing the ideas mentioned above, Agafi is able to find very complex gadgets in short time.

Agafi in action ...

![Agafi in action ...](https://github.com/CoreSecurity/Agafi/blob/master/agafi.png)

##What is Agafi-rop?

Agafi-ROP is a x86 ROP-Chainer tool oriented to build ROP chains for win32 programs, modules and running processes.

Using Agafi as gadget-finder + Agafi-ROP as good and fast ROP-Chainer engine, this tool is able to build ROP-Chains to bypass DEP in binary exploits.

Agafi-ROP re-building a ROP-Chain with "invalid chars" to "hxds.dll" v2.5.50727.198 ...

![Agafi in action ...](https://github.com/CoreSecurity/Agafi/blob/master/agafi-rop.png)

##Where can Agafi find gadgets?

Mainly Win32 binary files although other x86 architectures are also supported as RAW snapshots.


##What APi uses Agafi-ROP to build ROP-Chains to bypass DEP?

For now, only "kernel32.VirtualProtect" function is used.


##In which Windows versions does Agafi/ROP work?

Starting from Windows XP SP2 up to the latest Windows version.


##Is it necessary to install Agafi/ROP to use?

No instalation needed.


##Dependencies

The only external dependency is the x86 disassembly lib (Distorm v3).
Please, download this from (https://code.google.com/p/distorm/downloads/detail?name=distorm3-3-dlls.zip) and copy the 32 bit "distorm3.dll" library at the same Agafi path.


##Licensing

Agafi/ROP is released under version 3 of the GNU General Public License.


##Contact

If you have some suggestion or some bug to report, please contact to the authors.

Agafi/Agafi-ROP (neconomou@coresecurity.com)
Gisnap modules (djuarez@coresecurity.com)
