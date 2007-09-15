# Microsoft Developer Studio Project File - Name="libssh2_lib" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Static Library" 0x0104

CFG=libssh2_lib - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE
!MESSAGE NMAKE /f "libssh2_lib.mak".
!MESSAGE
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE
!MESSAGE NMAKE /f "libssh2_lib.mak" CFG="libssh2_lib - Win32 Debug"
!MESSAGE
!MESSAGE Possible choices for configuration are:
!MESSAGE
!MESSAGE "libssh2_lib - Win32 Release" (based on "Win32 (x86) Static Library")
!MESSAGE "libssh2_lib - Win32 Debug" (based on "Win32 (x86) Static Library")
!MESSAGE

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "libssh2_lib - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release_lib"
# PROP BASE Intermediate_Dir "Release_lib"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release_lib"
# PROP Intermediate_Dir "Release_lib"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "LIBSSH2_WIN32" /D "_MBCS" /D "_LIB" /YX /FD /c
# ADD CPP /nologo /MD /W3 /GX /O2 /I "..\include" /I "..\win32" /D "WIN32" /D "NDEBUG" /D "LIBSSH2_WIN32" /D "_MBCS" /D "_LIB" /YX /FD /c
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo
# ADD LIB32 /nologo /out:"Release_lib\libssh.lib"

!ELSEIF  "$(CFG)" == "libssh2_lib - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug_lib"
# PROP BASE Intermediate_Dir "Debug_lib"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug_lib"
# PROP Intermediate_Dir "Debug_lib"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "LIBSSH2_WIN32" /D "_MBCS" /D "_LIB" /YX /FD /GZ /c
# ADD CPP /nologo /MDd /W3 /Gm /GX /ZI /Od /I "..\include" /I "..\win32" /D "WIN32" /D "_DEBUG" /D "LIBSSH2_WIN32" /D "_MBCS" /D "_LIB" /YX /FD /GZ /c
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo /out:"Debug_lib\libssh2d.lib"

!ENDIF

# Begin Target

# Name "libssh2_lib - Win32 Release"
# Name "libssh2_lib - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Source File

SOURCE=..\src\channel.c
# End Source File
# Begin Source File

SOURCE=..\src\comp.c
# End Source File
# Begin Source File

SOURCE=..\src\crypt.c
# End Source File
# Begin Source File

SOURCE=..\src\hostkey.c
# End Source File
# Begin Source File

SOURCE=..\src\kex.c
# End Source File
# Begin Source File

SOURCE=..\src\mac.c
# End Source File
# Begin Source File

SOURCE=..\src\misc.c
# End Source File
# Begin Source File

SOURCE=..\src\openssl.c
# End Source File
# Begin Source File

SOURCE=..\src\packet.c
# End Source File
# Begin Source File

SOURCE=..\src\pem.c
# End Source File
# Begin Source File

SOURCE=..\src\publickey.c
# End Source File
# Begin Source File

SOURCE=..\src\scp.c
# End Source File
# Begin Source File

SOURCE=..\src\session.c
# End Source File
# Begin Source File

SOURCE=..\src\sftp.c
# End Source File
# Begin Source File

SOURCE=..\src\transport.c
# End Source File
# Begin Source File

SOURCE=..\src\userauth.c
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# Begin Source File

SOURCE=..\include\libssh2.h
# End Source File
# Begin Source File

SOURCE=.\libssh2_config.h
# End Source File
# Begin Source File

SOURCE=..\include\libssh2_priv.h
# End Source File
# Begin Source File

SOURCE=..\include\libssh2_sftp.h
# End Source File
# End Group
# End Target
# End Project


