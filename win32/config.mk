
# Tweak these for your system
!if "$(OPENSSLINC)" == ""
OPENSSLINC=..\openssl-0.9.8x\inc32
!endif

!if "$(OPENSSLLIB)" == ""
OPENSSLLIB=..\openssl-0.9.8x\out32dll
!endif

!if "$(ZLIBINC)" == ""
ZLIBINC=-DLIBSSH2_HAVE_ZLIB=1 /I..\zlib-1.2.7
!endif

!if "$(ZLIBLIB)" == ""
ZLIBLIB=..\zlib-1.2.7
!endif

!if "$(TARGET)" == ""
TARGET=Release
!endif

!if "$(TARGET)" == "Debug"
SUFFIX=_debug
CPPFLAGS=/Od /MDd
DLLFLAGS=/DEBUG /LDd
!else
CPPFLAGS=/Oi /O2 /Oy /GF /Y- /MD /DNDEBUG
DLLFLAGS=/DEBUG /LD
!endif

CPPFLAGS=/nologo /GL /Zi /EHsc $(CPPFLAGS) /Iwin32 /Iinclude /DLIBSSH2_OPENSSL /I$(OPENSSLINC) $(ZLIBINC)
CFLAGS=$(CPPFLAGS)
RCFLAGS=/Iinclude
DLLFLAGS=$(CFLAGS) $(DLLFLAGS)
LIBS=$(OPENSSLLIB)\libeay32.lib $(OPENSSLLIB)\ssleay32.lib $(ZLIBLIB)\zlib.lib ws2_32.lib user32.lib advapi32.lib gdi32.lib

INTDIR=$(TARGET)\$(SUBDIR)


