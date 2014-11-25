
@rem Console makefile for Microsoft Visual Studio C++
@rem Note:
@rem If you don't have the "Microsoft Visual Studio" path,
@rem  Please, execute the "vcvarsall.bat" command in "C:\Program Files\Microsoft Visual Studio XX.X\VC"

@rem To compile Gisnap use "Microsoft Visual Studio 2012"
cl.exe fsnap.c /link -SUBSYSTEM:CONSOLE -DYNAMICBASE:NO -BASE:0x08000000 -FIXED
cl.exe agafi.cpp /link -SUBSYSTEM:CONSOLE
cl agafi-rop.cpp /link -SUBSYSTEM:CONSOLE
