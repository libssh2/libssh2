#########################################################################
#
# Makefile for building libssh2 (Windows version - GNU Make)
# Use: make -f GNUmakefile [help|all|clean|dist|distclean|dll|objclean|test|testclean]
#
# Hacked by: Guenter Knauf
#
#########################################################################

PROOT := ..

### Common

HOMEPAGE := https://www.libssh2.org/

CFLAGS ?=
CPPFLAGS ?=
RCFLAGS ?=
LDFLAGS ?=
LIBSSH2_LDFLAGS_BIN ?=
LIBSSH2_LDFLAGS_LIB ?=
LIBS ?=

CROSSPREFIX ?=

ifeq ($(CC),cc)
  CC := gcc
endif
CC := $(CROSSPREFIX)$(CC)
AR := $(CROSSPREFIX)$(AR)
RC ?= $(CROSSPREFIX)windres

# For compatibility
ARCH ?=
ifeq ($(ARCH),w64)
  TRIPLET := x86_64-w64-mingw32
  CFLAGS  += -m64
  LDFLAGS += -m64
  RCFLAGS += --target=pe-x86-64
else ifdef ARCH
  TRIPLET := i686-w64-mingw32
  CFLAGS  += -m32
  LDFLAGS += -m32
  RCFLAGS += --target=pe-i386
else
  TRIPLET ?= $(shell $(CC) -dumpmachine)
endif

CPPFLAGS += -I$(PROOT)/win32 -I$(PROOT)/include
RCFLAGS  += -I$(PROOT)/include

# src

CPPFLAGS_LIB := -DHAVE_STRTOLL

# examples, tests

LIBSSH2_LDFLAGS_BIN += -L$(PROOT)/win32
LIBS_BIN := -lssh2 -lws2_32

ifdef DYN
  libssh2_DEPENDENCIES += $(PROOT)/win32/libssh2.dll.a
  LIBSSH2_LDFLAGS_BIN += -shared
else
  libssh2_DEPENDENCIES := $(PROOT)/win32/libssh2.a
  LIBSSH2_LDFLAGS_BIN += -static
endif

libssh2_DEPENDENCIES := $(PROOT)/win32/libssh2.a

### Optional features

# must be equal to DEBUG or NDEBUG
DB ?= NDEBUG
CPPFLAGS += -D$(DB)
ifeq ($(DB),NDEBUG)
  OBJDIR := release
else
  OBJDIR := debug
  CFLAGS += -g
  CPPFLAGS += -DLIBSSH2DEBUG
endif

# Linker options to exclude for shared mode executables.
_LDFLAGS :=
_LIBS :=

ifdef WITH_WINCNG
  CPPFLAGS += -DLIBSSH2_WINCNG
  include $(PROOT)/Makefile.WinCNG.inc
else ifdef MBEDTLS_PATH
  CPPFLAGS += -DLIBSSH2_MBEDTLS
  CPPFLAGS += -I"$(MBEDTLS_PATH)/include"
  _LDFLAGS += -L"$(MBEDTLS_PATH)/lib"
  _LIBS += -lmbedtls -lmbedx509 -lmbedcrypto
  include $(PROOT)/Makefile.mbedTLS.inc
else ifdef WOLFSSL_PATH
  CPPFLAGS += -DLIBSSH2_WOLFSSL
  CPPFLAGS += -I"$(WOLFSSL_PATH)/include"
  CPPFLAGS += -I"$(WOLFSSL_PATH)/include/wolfssl"
  _LDFLAGS += -L"$(WOLFSSL_PATH)/lib"
  _LIBS += -lwolfssl
  include $(PROOT)/Makefile.wolfSSL.inc
else
  OPENSSL_PATH ?= $(PROOT)/../openssl
  CPPFLAGS += -DLIBSSH2_OPENSSL
  OPENSSL_INCLUDE ?= $(OPENSSL_PATH)/include
  OPENSSL_LIBPATH ?= $(OPENSSL_PATH)/lib
  CPPFLAGS += -I"$(OPENSSL_INCLUDE)"
  _LDFLAGS += -L"$(OPENSSL_LIBPATH)"
  OPENSSL_LIBS ?= -lssl -lcrypto
  _LIBS += $(OPENSSL_LIBS)
  include $(PROOT)/Makefile.OpenSSL.inc
endif

ifdef ZLIB_PATH
  CPPFLAGS += -DLIBSSH2_HAVE_ZLIB
  CPPFLAGS += -I"$(ZLIB_PATH)/include"
  _LDFLAGS += -L"$(ZLIB_PATH)/lib"
  _LIBS += -lz
endif

_LIBS += -lws2_32 -lcrypt32 -lbcrypt

LIBSSH2_LDFLAGS_LIB += $(_LDFLAGS)
LIBS_LIB += $(_LIBS)

ifndef DYN
  LIBSSH2_LDFLAGS_BIN += $(_LDFLAGS)
  LIBS_BIN += $(_LIBS)
endif

### Rules

# Platform-dependent helper tool macros
ifneq ($(findstring /sh,$(SHELL)),)
DEL   = rm -f $1
RMDIR = rm -fr $1
MKDIR = mkdir -p $1
COPY  = -cp -afv $1 $2
DL    = '
else
DEL   = -del 2>NUL /q /f $(subst /,\,$1)
RMDIR = -rd 2>NUL /q /s $(subst /,\,$1)
MKDIR = -md 2>NUL $(subst /,\,$1)
COPY  = -copy 2>NUL /y $(subst /,\,$1) $(subst /,\,$2)
endif
AWK := awk
ZIP := zip -qzr9

# Include the version info retrieved from libssh2.h
-include $(OBJDIR)/version.inc

vpath %.c $(PROOT)/src

# include Makefile.inc to get CSOURCES define
include $(PROOT)/Makefile.inc

OBJECTS := $(patsubst %.c,%.o,$(CSOURCES))
OBJS    := $(addprefix $(OBJDIR)/,$(OBJECTS))

TARGET := libssh2

# Override the path below to point to your Distribution folder.
DISTDIR ?= $(TARGET)-$(LIBSSH2_VERSION_STR)-bin-$(word 1,$(subst -, ,$(TRIPLET)))
DISTARC := $(DISTDIR).zip

LIBSSH2_DLL_SUFFIX ?=
libssh2_dll_LIBRARY := $(TARGET)$(LIBSSH2_DLL_SUFFIX).dll
libssh2_dll_a_LIBRARY := $(TARGET).dll.a

EXAMPLES := $(PROOT)/example
TARGETS_EXAMPLES := $(filter-out $(EXAMPLES)/x11.exe,$(patsubst %.c,%.exe,$(strip $(wildcard $(EXAMPLES)/*.c))))

all: lib dll

dll: prebuild $(libssh2_dll_LIBRARY)

lib: prebuild $(TARGET).a

prebuild: $(OBJDIR) $(OBJDIR)/version.inc

test: $(TARGETS_EXAMPLES)

%.exe: %.c $(libssh2_DEPENDENCIES)
	$(CC) -W -Wall $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) $(LIBSSH2_LDFLAGS_BIN) $< -o $@ $(LIBS) $(LIBS_BIN)

$(OBJDIR)/%.o: %.c
	$(CC) -W -Wall $(CFLAGS) $(CPPFLAGS) $(CPPFLAGS_LIB) -c $< -o $@

$(libssh2_dll_LIBRARY) $(libssh2_dll_a_LIBRARY): $(OBJS) $(OBJDIR)/$(TARGET).res
	@$(call DEL, $@)
	$(CC) $(LDFLAGS) -shared $(LIBSSH2_LDFLAGS_LIB) $^ -o $@ $(LIBS) $(LIBS_LIB) \
	  -Wl,--output-def,$(libssh2_dll_LIBRARY:.dll=.def),--out-implib,$(libssh2_dll_a_LIBRARY)

$(OBJDIR)/%.res: %.rc
	$(RC) -O coff $(RCFLAGS) -i $< -o $@

$(TARGET).a: $(OBJS)
	@$(call DEL, $@)
	$(AR) rcs $@ $^

$(OBJDIR)/version.inc: $(PROOT)/get_ver.awk $(PROOT)/include/libssh2.h $(OBJDIR)
	$(AWK) -f $^ > $@

dist: all $(DISTDIR) $(DISTDIR)/readme.txt
	@$(call MKDIR, $(DISTDIR)/bin)
	@$(call MKDIR, $(DISTDIR)/include)
	@$(call MKDIR, $(DISTDIR)/win32)
	@$(call COPY, $(PROOT)/COPYING, $(DISTDIR))
	@$(call COPY, $(PROOT)/README, $(DISTDIR))
	@$(call COPY, $(PROOT)/RELEASE-NOTES, $(DISTDIR))
	@$(call COPY, $(libssh2_dll_LIBRARY), $(DISTDIR)/bin)
	@$(call COPY, $(PROOT)/include/*.h, $(DISTDIR)/include)
	@$(call COPY, libssh2_config.h, $(DISTDIR)/include)
	@$(call COPY, *.a, $(DISTDIR)/win32)
	@echo Creating... $(DISTARC)
	@$(ZIP) $(DISTARC) $(DISTDIR)/* < $(DISTDIR)/readme.txt

distclean vclean: clean
	$(call RMDIR, $(DISTDIR))
	$(call DEL, $(DISTARC))

objclean: all
	$(call RMDIR, $(OBJDIR))

testclean: clean
	$(call DEL, $(TARGETS_EXAMPLES))

clean:
	$(call DEL, $(libssh2_dll_LIBRARY) $(libssh2_dll_LIBRARY:.dll=.def) $(TARGET).a $(libssh2_dll_a_LIBRARY))
	$(call RMDIR, $(OBJDIR))

$(OBJDIR):
	@$(call MKDIR, $@)

$(DISTDIR):
	@$(call MKDIR, $@)

$(DISTDIR)/readme.txt: GNUmakefile
	@echo Creating... $@
	@echo $(DL)This is a binary distribution for Windows.$(DL) > $@
	@echo $(DL)libssh2 version $(LIBSSH2_VERSION_STR)$(DL) >> $@
	@echo $(DL)Please download the complete libssh2 package for$(DL) >> $@
	@echo $(DL)any further documentation:$(DL) >> $@
	@echo $(DL)$(HOMEPAGE)$(DL) >> $@

help: $(OBJDIR)/version.inc
	@echo $(DL)===========================================================$(DL)
	@echo $(DL)OpenSSL path    = $(OPENSSL_PATH)$(DL)
	@echo $(DL)wolfSSL path    = $(WOLFSSL_PATH)$(DL)
	@echo $(DL)mbedTLS path    = $(MBEDTLS_PATH)$(DL)
	@echo $(DL)zlib path       = $(ZLIB_PATH)$(DL)
	@echo $(DL)===========================================================$(DL)
	@echo $(DL)libssh2 $(LIBSSH2_VERSION_STR) - available targets are:$(DL)
	@echo $(DL)$(MAKE) all$(DL)
	@echo $(DL)$(MAKE) dll$(DL)
	@echo $(DL)$(MAKE) lib$(DL)
	@echo $(DL)$(MAKE) clean$(DL)
	@echo $(DL)$(MAKE) dist$(DL)
	@echo $(DL)$(MAKE) distclean$(DL)
	@echo $(DL)$(MAKE) objclean$(DL)
	@echo $(DL)$(MAKE) test$(DL)
	@echo $(DL)$(MAKE) testclean$(DL)
	@echo $(DL)===========================================================$(DL)
