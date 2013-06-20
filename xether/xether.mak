# Microsoft Developer Studio Generated NMAKE File, Based on xether.dsp
!IF "$(CFG)" == ""
CFG=xether - Win32 Debug
!MESSAGE No configuration specified. Defaulting to xether - Win32 Debug.
!ENDIF 

!IF "$(CFG)" != "xether - Win32 Release" && "$(CFG)" != "xether - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "xether.mak" CFG="xether - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "xether - Win32 Release" (based on "Win32 (x86) Static Library")
!MESSAGE "xether - Win32 Debug" (based on "Win32 (x86) Static Library")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "xether - Win32 Release"

OUTDIR=.\Release
INTDIR=.\Release

ALL : ".\lib\xether.lib"


CLEAN :
	-@erase ".\lib\xether.lib"
	-@erase ".\objects\datalink.obj"
	-@erase ".\objects\ipaddr.obj"
	-@erase ".\objects\macaddr.obj"
	-@erase ".\objects\print-ascii.obj"
	-@erase ".\objects\vc60.idb"
	-@erase ".\objects\xapp.obj"
	-@erase ".\objects\xarp.obj"
	-@erase ".\objects\xdhcp.obj"
	-@erase ".\objects\xether.obj"
	-@erase ".\objects\xicmp.obj"
	-@erase ".\objects\xip.obj"
	-@erase ".\objects\xlayer.obj"
	-@erase ".\objects\xtcp.obj"
	-@erase ".\objects\xudp.obj"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP_PROJ=/nologo /ML /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_MBCS" /D "_LIB" /Fp"objects/xether.pch" /YX /Fo"objects/" /Fd"objects/" /FD /c 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"objects/xether.bsc" 
BSC32_SBRS= \
	
LIB32=link.exe -lib
LIB32_FLAGS=/nologo /out:"lib\xether.lib" 
LIB32_OBJS= \
	".\objects\datalink.obj" \
	".\objects\ipaddr.obj" \
	".\objects\macaddr.obj" \
	".\objects\print-ascii.obj" \
	".\objects\xapp.obj" \
	".\objects\xarp.obj" \
	".\objects\xether.obj" \
	".\objects\xicmp.obj" \
	".\objects\xip.obj" \
	".\objects\xlayer.obj" \
	".\objects\xtcp.obj" \
	".\objects\xudp.obj" \
	".\objects\xdhcp.obj"

".\lib\xether.lib" : "$(OUTDIR)" $(DEF_FILE) $(LIB32_OBJS)
    $(LIB32) @<<
  $(LIB32_FLAGS) $(DEF_FLAGS) $(LIB32_OBJS)
<<

!ELSEIF  "$(CFG)" == "xether - Win32 Debug"

OUTDIR=.\Debug
INTDIR=.\Debug
# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

ALL : "$(OUTDIR)\xether.lib"


CLEAN :
	-@erase "$(INTDIR)\datalink.obj"
	-@erase "$(INTDIR)\ipaddr.obj"
	-@erase "$(INTDIR)\macaddr.obj"
	-@erase "$(INTDIR)\print-ascii.obj"
	-@erase "$(INTDIR)\vc60.idb"
	-@erase "$(INTDIR)\vc60.pdb"
	-@erase "$(INTDIR)\xapp.obj"
	-@erase "$(INTDIR)\xarp.obj"
	-@erase "$(INTDIR)\xdhcp.obj"
	-@erase "$(INTDIR)\xether.obj"
	-@erase "$(INTDIR)\xicmp.obj"
	-@erase "$(INTDIR)\xip.obj"
	-@erase "$(INTDIR)\xlayer.obj"
	-@erase "$(INTDIR)\xtcp.obj"
	-@erase "$(INTDIR)\xudp.obj"
	-@erase "$(OUTDIR)\xether.lib"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP_PROJ=/nologo /MLd /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_MBCS" /D "_LIB" /Fp"$(INTDIR)\xether.pch" /YX /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /GZ /c 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\xether.bsc" 
BSC32_SBRS= \
	
LIB32=link.exe -lib
LIB32_FLAGS=/nologo /out:"$(OUTDIR)\xether.lib" 
LIB32_OBJS= \
	"$(INTDIR)\datalink.obj" \
	"$(INTDIR)\ipaddr.obj" \
	"$(INTDIR)\macaddr.obj" \
	"$(INTDIR)\print-ascii.obj" \
	"$(INTDIR)\xapp.obj" \
	"$(INTDIR)\xarp.obj" \
	"$(INTDIR)\xether.obj" \
	"$(INTDIR)\xicmp.obj" \
	"$(INTDIR)\xip.obj" \
	"$(INTDIR)\xlayer.obj" \
	"$(INTDIR)\xtcp.obj" \
	"$(INTDIR)\xudp.obj" \
	"$(INTDIR)\xdhcp.obj"

"$(OUTDIR)\xether.lib" : "$(OUTDIR)" $(DEF_FILE) $(LIB32_OBJS)
    $(LIB32) @<<
  $(LIB32_FLAGS) $(DEF_FLAGS) $(LIB32_OBJS)
<<

!ENDIF 

.c{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.c{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<


!IF "$(NO_EXTERNAL_DEPS)" != "1"
!IF EXISTS("xether.dep")
!INCLUDE "xether.dep"
!ELSE 
!MESSAGE Warning: cannot find "xether.dep"
!ENDIF 
!ENDIF 


!IF "$(CFG)" == "xether - Win32 Release" || "$(CFG)" == "xether - Win32 Debug"
SOURCE=.\src\datalink.c

!IF  "$(CFG)" == "xether - Win32 Release"


".\objects\datalink.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "xether - Win32 Debug"


"$(INTDIR)\datalink.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=.\src\ipaddr.c

!IF  "$(CFG)" == "xether - Win32 Release"


".\objects\ipaddr.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "xether - Win32 Debug"


"$(INTDIR)\ipaddr.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=.\src\macaddr.c

!IF  "$(CFG)" == "xether - Win32 Release"


".\objects\macaddr.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "xether - Win32 Debug"


"$(INTDIR)\macaddr.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=".\src\print-ascii.c"

!IF  "$(CFG)" == "xether - Win32 Release"


".\objects\print-ascii.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "xether - Win32 Debug"


"$(INTDIR)\print-ascii.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=.\src\xapp.c

!IF  "$(CFG)" == "xether - Win32 Release"


".\objects\xapp.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "xether - Win32 Debug"


"$(INTDIR)\xapp.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=.\src\xarp.c

!IF  "$(CFG)" == "xether - Win32 Release"


".\objects\xarp.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "xether - Win32 Debug"


"$(INTDIR)\xarp.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=.\src\xdhcp.c

!IF  "$(CFG)" == "xether - Win32 Release"


".\objects\xdhcp.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "xether - Win32 Debug"


"$(INTDIR)\xdhcp.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=.\src\xether.c

!IF  "$(CFG)" == "xether - Win32 Release"


".\objects\xether.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "xether - Win32 Debug"


"$(INTDIR)\xether.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=.\src\xicmp.c

!IF  "$(CFG)" == "xether - Win32 Release"


".\objects\xicmp.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "xether - Win32 Debug"


"$(INTDIR)\xicmp.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=.\src\xip.c

!IF  "$(CFG)" == "xether - Win32 Release"


".\objects\xip.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "xether - Win32 Debug"


"$(INTDIR)\xip.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=.\src\xlayer.c

!IF  "$(CFG)" == "xether - Win32 Release"


".\objects\xlayer.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "xether - Win32 Debug"


"$(INTDIR)\xlayer.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=.\src\xtcp.c

!IF  "$(CFG)" == "xether - Win32 Release"


".\objects\xtcp.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "xether - Win32 Debug"


"$(INTDIR)\xtcp.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=.\src\xudp.c

!IF  "$(CFG)" == "xether - Win32 Release"


".\objects\xudp.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "xether - Win32 Debug"


"$(INTDIR)\xudp.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 


!ENDIF 

