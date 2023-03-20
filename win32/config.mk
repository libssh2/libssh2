# Tweak these for your system
!if "$(OPENSSLINC)" == ""
OPENSSLINC=..\openssl\include
!endif

!if "$(OPENSSLLIB)" == ""
OPENSSLLIB=..\openssl\lib
!endif

!if "$(ZLIBINC)" == ""
ZLIBINC=..\zlib
!endif

!if "$(ZLIBLIB)" == ""
ZLIBLIB=..\zlib
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

CPPFLAGS=/nologo /GL /Zi /EHsc $(CPPFLAGS) /Iwin32 /Iinclude

!if "$(WITH_WINCNG)" == "1"
CPPFLAGS=$(CPPFLAGS) /DLIBSSH2_WINCNG
# LIBS=bcrypt.lib crypt32.lib
!else
CPPFLAGS=$(CPPFLAGS) /DLIBSSH2_OPENSSL /I$(OPENSSLINC)
LIBS=$(LIBS) $(OPENSSLLIB)\lib\crypto.lib $(OPENSSLLIB)\lib\ssl.lib
!endif

!if "$(WITH_ZLIB)" == "1"
CPPFLAGS=$(CPPFLAGS) /DLIBSSH2_HAVE_ZLIB /I$(ZLIBINC)
LIBS=$(LIBS) $(ZLIBLIB)\zlib.lib
!endif

CFLAGS=$(CPPFLAGS)
RCFLAGS=/Iinclude
DLLFLAGS=$(CFLAGS) $(DLLFLAGS)
LIBS=$(LIBS) ws2_32.lib user32.lib advapi32.lib gdi32.lib

INTDIR=$(TARGET)\$(SUBDIR)
