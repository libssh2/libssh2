
# Tweak these for your system
OPENSSLINC=\local\php\php_build\include
OPENSSLLIB=\local\php\php_build\lib

ZLIBINC=-DLIBSSH2_HAVE_ZLIB=1 /I\local\php\php_build\include
ZLIBLIB=\local\php\php_build\lib

CPPFLAGS=/nologo /GL /Zi /EHsc /MD /Iwin32 /Iinclude /I$(OPENSSLINC) $(ZLIBINC) -DLIBSSH2_WIN32
CFLAGS=$(CPPFLAGS)
DLLFLAGS=$(CFLAGS) /LDd
LIBS=$(OPENSSLLIB)\libeay32.lib $(OPENSSLLIB)\ssleay32.lib ws2_32.lib $(ZLIBLIB)\zlib.lib

!if "$(TARGET)" == ""
TARGET=Debug
!endif

!if "$(TARGET)" == "Debug"
SUFFIX=_debug
!endif

INTDIR=$(TARGET)\$(SUBDIR)


