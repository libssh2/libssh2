#########################################################################
#
# Makefile for building libssh2 (Windows version - GNU Make)
# Use: make -f GNUmakefile [help|all|clean|dev|devclean|dist|distclean|dll|objclean]
#
# Hacked by: Guenter Knauf
#
#########################################################################

# Project root
PROOT := ..

# Edit the path below to point to the base of your Zlib sources.
ZLIB_PATH ?= $(PROOT)/../zlib

# Edit the path below to point to the base of your OpenSSL package.
OPENSSL_PATH ?= $(PROOT)/../openssl

# Edit the path below to point to your Distribution folder.
DISTDIR ?= libssh2-$(LIBSSH2_VERSION_STR)-bin-$(ARCH)
DISTARC = $(DISTDIR).zip

# Edit the path below to point to your Development folder.
DEVLDIR ?= libssh2-$(LIBSSH2_VERSION_STR)-dev-$(ARCH)
DEVLARC = $(DEVLDIR).zip

# Edit the vars below to change target settings.
TARGET := libssh2
WWWURL := https://www.libssh2.org/
DESCR  = libssh2 $(LIBSSH2_VERSION_STR)

CFLAGS ?=
CPPFLAGS ?=
RCFLAGS ?=
LDFLAGS ?=
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

libssh2_dll_LIBRARY := $(TARGET)$(LIBSSH2_DLL_SUFFIX).dll
libssh2_dll_a_LIBRARY := $(TARGET).dll.a

# Include the version info retrieved from libssh2.h
-include $(OBJDIR)/version.inc

CFLAGS += -DHAVE_STRTOLL
CPPFLAGS += -I$(PROOT)/win32 -I$(PROOT)/include
RCFLAGS += -I$(PROOT)/include

# must be equal to DEBUG or NDEBUG
DB ?= NDEBUG
CPPFLAGS += -D$(DB)
ifeq ($(DB),NDEBUG)
  CFLAGS += -O2
  OBJDIR := release
else
  CFLAGS += -g
  CPPFLAGS += -DLIBSSH2DEBUG
  OBJDIR := debug
endif

ifdef WITH_WINCNG
  CPPFLAGS += -DLIBSSH2_WINCNG
  include $(PROOT)/Makefile.WinCNG.inc
else ifdef MBEDTLS_PATH
  CPPFLAGS += -DLIBSSH2_MBEDTLS
  CPPFLAGS += -I"$(MBEDTLS_PATH)/include"
  LDFLAGS += -L"$(MBEDTLS_PATH)/lib"
  LIBS += -lmbedtls -lmbedx509 -lmbedcrypto
  include $(PROOT)/Makefile.mbedTLS.inc
else ifdef WOLFSSL_PATH
  CPPFLAGS += -DLIBSSH2_WOLFSSL
  CPPFLAGS += -I"$(WOLFSSL_PATH)/include"
  CPPFLAGS += -I"$(WOLFSSL_PATH)/include/wolfssl"
  LDFLAGS += -L"$(WOLFSSL_PATH)/lib"
  LIBS += -lwolfssl
  include $(PROOT)/Makefile.wolfSSL.inc
else
  CPPFLAGS += -DLIBSSH2_OPENSSL
  OPENSSL_INCLUDE ?= $(OPENSSL_PATH)/include
  OPENSSL_LIBPATH ?= $(OPENSSL_PATH)/lib
  CPPFLAGS += -I"$(OPENSSL_INCLUDE)"
  OPENSSL_LIBS_STAT = crypto ssl
  OPENSSL_LIBS_DYN = crypto.dll ssl.dll
  ifdef LINK_OPENSSL_STATIC
    LIBS += $(patsubst %,$(OPENSSL_LIBPATH)/lib%.a, $(OPENSSL_LIBS_STAT))
  else
    LIBS += $(patsubst %,$(OPENSSL_LIBPATH)/lib%.a, $(OPENSSL_LIBS_DYN))
  endif
  include $(PROOT)/Makefile.OpenSSL.inc
endif
LIBS += -lws2_32 -lcrypt32 -lbcrypt

ifdef ZLIB_PATH
  CPPFLAGS += -DLIBSSH2_HAVE_ZLIB
  CPPFLAGS += -I"$(ZLIB_PATH)/include"
  ifdef LINK_ZLIB_STATIC
    LIBS += $(ZLIB_PATH)/lib/libz.a
  else
    LIBS += $(ZLIB_PATH)/lib/libz.dll.a
  endif
endif


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


vpath %.c $(PROOT)/src

# include Makefile.inc to get CSOURCES define
include $(PROOT)/Makefile.inc

OBJECTS := $(patsubst %.c,%.o,$(CSOURCES))
OBJS    := $(addprefix $(OBJDIR)/,$(OBJECTS))


all: lib dll

dll: prebuild $(libssh2_dll_LIBRARY)

lib: prebuild $(TARGET).a

prebuild: $(OBJDIR) $(OBJDIR)/version.inc
# libssh2_config.h

test: all
	$(MAKE) -C test -f GNUmakefile

$(OBJDIR)/%.o: %.c
	$(CC) -W -Wall $(CFLAGS) $(CPPFLAGS) -c $< -o $@

$(OBJDIR)/version.inc: $(PROOT)/get_ver.awk $(PROOT)/include/libssh2.h $(OBJDIR)
	$(AWK) -f $^ > $@

dist: all $(DISTDIR) $(DISTDIR)/readme.txt
	@$(call MKDIR, $(DISTDIR)/bin)
	@$(call COPY, $(PROOT)/AUTHORS, $(DISTDIR))
	@$(call COPY, $(PROOT)/COPYING, $(DISTDIR))
	@$(call COPY, $(PROOT)/INSTALL, $(DISTDIR))
	@$(call COPY, $(PROOT)/README, $(DISTDIR))
	@$(call COPY, $(PROOT)/RELEASE-NOTES, $(DISTDIR))
	@$(call COPY, $(libssh2_dll_LIBRARY), $(DISTDIR)/bin)
	@echo Creating $(DISTARC)
	@$(ZIP) $(DISTARC) $(DISTDIR)/* < $(DISTDIR)/readme.txt

dev: all $(DEVLDIR) $(DEVLDIR)/readme.txt
	@$(call MKDIR, $(DEVLDIR)/bin)
	@$(call MKDIR, $(DEVLDIR)/include)
	@$(call MKDIR, $(DEVLDIR)/win32)
	@$(call COPY, $(PROOT)/AUTHORS, $(DEVLDIR))
	@$(call COPY, $(PROOT)/COPYING, $(DEVLDIR))
	@$(call COPY, $(PROOT)/INSTALL, $(DEVLDIR))
	@$(call COPY, $(PROOT)/README, $(DEVLDIR))
	@$(call COPY, $(PROOT)/RELEASE-NOTES, $(DEVLDIR))
	@$(call COPY, $(libssh2_dll_LIBRARY), $(DEVLDIR)/bin)
	@$(call COPY, $(PROOT)/include/*.h, $(DEVLDIR)/include)
	@$(call COPY, libssh2_config.h, $(DEVLDIR)/include)
	@$(call COPY, *.a, $(DEVLDIR)/win32)
	@echo Creating $(DEVLARC)
	@$(ZIP) $(DEVLARC) $(DEVLDIR)/* < $(DEVLDIR)/readme.txt

distclean vclean: clean
	$(call RMDIR, $(DISTDIR))
	$(call DEL, $(DISTARC))

devclean: clean
	$(call RMDIR, $(DEVLDIR))
	$(call DEL, $(DEVLARC))

objclean: all
	$(call RMDIR, $(OBJDIR))

testclean: clean
	$(MAKE) -C test -f GNUmakefile clean

clean:
	$(call DEL, $(libssh2_dll_LIBRARY) $(libssh2_dll_LIBRARY:.dll=.def) $(TARGET).a $(libssh2_dll_a_LIBRARY))
	$(call RMDIR, $(OBJDIR))

$(OBJDIR):
	@$(call MKDIR, $@)

$(DISTDIR):
	@$(call MKDIR, $@)

$(DEVLDIR):
	@$(call MKDIR, $@)

$(TARGET).a: $(OBJS)
	@$(call DEL, $@)
	$(AR) rcs $@ $^

$(libssh2_dll_LIBRARY) $(libssh2_dll_a_LIBRARY): $(OBJS) $(OBJDIR)/$(TARGET).res
	@$(call DEL, $@)
	$(CC) $(LDFLAGS) -shared $^ -o $@ $(LIBS) \
	  -Wl,--output-def,$(libssh2_dll_LIBRARY:.dll=.def),--out-implib,$(libssh2_dll_a_LIBRARY)


$(OBJDIR)/%.res: %.rc
	$(RC) -O coff $(RCFLAGS) -i $< -o $@


$(DISTDIR)/readme.txt: GNUmakefile
	@echo Creating $@
	@echo $(DL)This is a binary distribution for Win32 platform.$(DL) > $@
	@echo $(DL)libssh version $(LIBSSH2_VERSION_STR)$(DL) >> $@
	@echo $(DL)Please download the complete libssh package for$(DL) >> $@
	@echo $(DL)any further documentation:$(DL) >> $@
	@echo $(DL)$(WWWURL)$(DL) >> $@

$(DEVLDIR)/readme.txt: GNUmakefile
	@echo Creating $@
	@echo $(DL)This is a development distribution for Win32 platform.$(DL) > $@
	@echo $(DL)libssh version $(LIBSSH2_VERSION_STR)$(DL) >> $@
	@echo $(DL)Please download the complete libssh package for$(DL) >> $@
	@echo $(DL)any further documentation:$(DL) >> $@
	@echo $(DL)$(WWWURL)$(DL) >> $@

help: $(OBJDIR)/version.inc
	@echo $(DL)===========================================================$(DL)
	@echo $(DL)OpenSSL path    = $(OPENSSL_PATH)$(DL)
	@echo $(DL)Zlib path       = $(ZLIB_PATH)$(DL)
	@echo $(DL)===========================================================$(DL)
	@echo $(DL)libssh $(LIBSSH2_VERSION_STR) - available targets are:$(DL)
	@echo $(DL)$(MAKE) all$(DL)
	@echo $(DL)$(MAKE) dll$(DL)
	@echo $(DL)$(MAKE) lib$(DL)
	@echo $(DL)$(MAKE) clean$(DL)
	@echo $(DL)$(MAKE) dev$(DL)
	@echo $(DL)$(MAKE) devclean$(DL)
	@echo $(DL)$(MAKE) dist$(DL)
	@echo $(DL)$(MAKE) distclean$(DL)
	@echo $(DL)$(MAKE) objclean$(DL)
	@echo $(DL)$(MAKE) test$(DL)
	@echo $(DL)===========================================================$(DL)
