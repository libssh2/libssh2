
# Tweak these for your system
OPENSSLINC=\local\php\php_build\include
OPENSSLLIB=\local\php\php_build\lib

ZLIBINC=-DLIBSSH2_HAVE_ZLIB=1 /I\local\php\php_build\include
ZLIBLIB=\local\php\php_build\lib

!if "$(TARGET)" == ""
TARGET=Release
!endif

!if "$(TARGET)" == "Debug"
SUFFIX=_debug
CPPFLAGS=/Od /MDd
DLLFLAGS=/DEBUG /LDd
!else
CPPFLAGS=/Og /Oi /O2 /Oy /GF /Y- /MD /DNDEBUG
DLLFLAGS=/DEBUG /LD
!endif

CPPFLAGS=/nologo /GL /Zi /EHsc $(CPPFLAGS) /Iwin32 /Iinclude /I$(OPENSSLINC) $(ZLIBINC) -DLIBSSH2_WIN32
CFLAGS=$(CPPFLAGS)
DLLFLAGS=$(CFLAGS) $(DLLFLAGS)
LIBS=$(OPENSSLLIB)\libeay32.lib $(OPENSSLLIB)\ssleay32.lib ws2_32.lib $(ZLIBLIB)\zlib.lib

INTDIR=$(TARGET)\$(SUBDIR)


