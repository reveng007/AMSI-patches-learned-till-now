@ECHO OFF

cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tp patchAMSI.cpp /link /OUT:Inject.exe /SUBSYSTEM:CONSOLE /MACHINE:x64
del patchAMSI.obj
