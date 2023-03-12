#########################################################################
#
## Makefile for building libssh2 samples (Win32 version - gnu make)
## Use: make -f GNUmakefile [help]
##
## Hacked by: Guenter Knauf
#
#########################################################################

# Project root
PROOT := ../..

# Edit the path below to point to the base of your Zlib sources.
ZLIB_PATH ?= $(PROOT)/../zlib

# Edit the path below to point to the base of your OpenSSL package.
OPENSSL_PATH ?= $(PROOT)/../openssl

# Edit the var below to enable static linking of libssh2 and libz
LINK_STATIC := 1

# Edit the vars below to change target settings.
SAMPLES := $(PROOT)/example
TARGETS := $(filter-out x11.exe,$(patsubst $(SAMPLES)/%.c,%.exe,$(strip $(wildcard $(SAMPLES)/*.c))))
WWWURL := https://www.libssh2.org/
DESCR  = libssh2 $(subst .rc,,$(notdir $@)) $(LIBSSH2_VERSION_STR)

# must be equal to DEBUG or NDEBUG
DB ?= NDEBUG
# Optimization: -O<n> or debugging: -g
ifeq ($(DB),NDEBUG)
  OPT := -O2
  OBJDIR := release
else
  OPT := -g
  OBJDIR := debug
endif

# Here you can find a native Win32 binary of the original awk:
# http://www.gknw.net/development/prgtools/awk-20100523.zip
AWK := awk
ZIP := zip -qzr9

# Platform-dependent helper tool macros
ifeq ($(findstring /sh,$(SHELL)),/sh)
DEL    = rm -f $1
RMDIR  = rm -fr $1
MKDIR  = mkdir -p $1
COPY   = -cp -afv $1 $2
COPYR  = -rsync -aC $1/* $2
TOUCH  = touch $1
CAT    = cat
ECHONL = echo ""
DL     = '
NUL    = \\0
else
ifeq "$(OS)" "Windows_NT"
DEL    = -del 2>NUL /q /f $(subst /,\,$1)
RMDIR  = -rd 2>NUL /q /s $(subst /,\,$1)
else
DEL    = -del 2>NUL $(subst /,\,$1)
RMDIR  = -deltree 2>NUL /y $(subst /,\,$1)
endif
MKDIR  = -md 2>NUL $(subst /,\,$1)
COPY   = -copy 2>NUL /y $(subst /,\,$1) $(subst /,\,$2)
COPYR  = -xcopy 2>NUL /q /y /e $(subst /,\,$1) $(subst /,\,$2)
TOUCH  = copy 2>&1>NUL /b $(subst /,\,$1) +,,
CAT    = type
ECHONL = $(ComSpec) /c echo.
NUL    = \0
endif

ifeq ($(CC),cc)
  CC := gcc
endif
CC := $(CROSSPREFIX)$(CC)
AR := $(CROSSPREFIX)$(AR)
RC ?= $(CROSSPREFIX)windres

# Set environment var ARCH to your architecture to override autodetection.
ifndef ARCH
  ifeq ($(findstring gcc,$(CC)),gcc)
    ifeq ($(findstring x86_64,$(shell $(CC) -dumpmachine)),x86_64)
      ARCH := w64
    else
      ARCH := w32
    endif
  else
    ARCH := w32
  endif
endif

# Include the version info retrieved from libssh2.h
-include $(OBJDIR)/version.inc

CFLAGS ?=
CPPFLAGS ?=
RCFLAGS ?=
LDFLAGS ?=
LIBS ?=

# Compatibility
CFLAGS += $(LIBSSH2_CFLAG_EXTRAS)
LDFLAGS += $(LIBSSH2_LDFLAG_EXTRAS) $(LIBPATH)
RCFLAGS += $(LIBSSH2_RCFLAG_EXTRAS)
LIBS += $(LDLIBS)

CFLAGS += $(OPT)
CPPFLAGS += -D$(DB)
LDFLAGS += -s
RCFLAGS += -I$(PROOT)/include
ifeq ($(ARCH),w64)
  CFLAGS  += -m64
  LDFLAGS += -m64
  RCFLAGS += -F pe-x86-64
else ifeq ($(ARCH),w32)
  CFLAGS  += -m32
  LDFLAGS += -m32
  RCFLAGS += -F pe-i386
endif

CPPFLAGS += -I$(PROOT)/win32 -I$(PROOT)/include
LDFLAGS += -L$(PROOT)/win32

ifdef LINK_STATIC
  LIBS += -llibssh2
else
  LIBS += -llibssh2dll
endif

ifdef WITH_WINCNG
else ifdef MBEDTLS_PATH
  LDFLAGS += -L"$(MBEDTLS_PATH)/lib"
  LIBS += -lmbedtls -lmbedx509 -lmbedcrypto
else ifdef WOLFSSL_PATH
  LDFLAGS += -L"$(WOLFSSL_PATH)/lib"
  LIBS += -lwolfssl
else
  OPENSSL_INCLUDE ?= $(OPENSSL_PATH)/include
  OPENSSL_LIBPATH ?= $(OPENSSL_PATH)/lib
  OPENSSL_LIBS_STAT := crypto ssl
  OPENSSL_LIBS_DYN := crypto.dll ssl.dll
  ifdef LINK_STATIC
    ifdef LINK_OPENSSL_STATIC
      LIBS += $(patsubst %,$(OPENSSL_LIBPATH)/lib%.a, $(OPENSSL_LIBS_STAT)) -lgdi32
    else
      LIBS += $(patsubst %,$(OPENSSL_LIBPATH)/lib%.a, $(OPENSSL_LIBS_DYN))
    endif
  endif
endif
LIBS += -lws2_32 -lcrypt32 -lbcrypt

ifdef ZLIB_PATH
  ifdef LINK_ZLIB_STATIC
    LIBS += $(ZLIB_PATH)/lib/libz.a
  else
    LIBS += $(ZLIB_PATH)/lib/libz.dll.a
  endif
endif

vpath %.c $(PROOT)/example

.PRECIOUS: $(OBJDIR)/%.o $(OBJDIR)/%.rc $(OBJDIR)/%.res


all: prebuild $(TARGETS)

prebuild: $(OBJDIR) $(OBJDIR)/version.inc

$(OBJDIR)/%.o: %.c
	$(CC) -W -Wall $(CFLAGS) $(CPPFLAGS) -c $< -o $@

$(OBJDIR)/version.inc: $(PROOT)/include/libssh2.h $(OBJDIR)
	@echo Creating $@
	@$(AWK) -f $(PROOT)/get_ver.awk $< > $@

objclean:
	$(call RMDIR, $(OBJDIR))

clean: objclean
	$(call DEL, $(TARGETS))

$(OBJDIR):
	$(call MKDIR, $@)

%.exe: $(OBJDIR)/%.o $(OBJDIR)/%.res
	@echo Linking $@
	@$(call DEL, $@)
	$(CC) $(LDFLAGS) $^ -o $@ $(LIBS)

$(OBJDIR)/%.res: $(OBJDIR)/%.rc
	@echo Creating $@
	$(RC) -O coff $(RCFLAGS) -i $< -o $@

$(OBJDIR)/%.rc: GNUmakefile $(OBJDIR)/version.inc
	@echo $(DL)1 VERSIONINFO$(DL) > $@
	@echo $(DL) FILEVERSION $(LIBSSH2_VERSION),0$(DL) >> $@
	@echo $(DL) PRODUCTVERSION $(LIBSSH2_VERSION),0$(DL) >> $@
	@echo $(DL) FILEFLAGSMASK 0x3fL$(DL) >> $@
	@echo $(DL) FILEOS 0x40004L$(DL) >> $@
	@echo $(DL) FILEFLAGS 0x0L$(DL) >> $@
	@echo $(DL) FILETYPE 0x1L$(DL) >> $@
	@echo $(DL) FILESUBTYPE 0x0L$(DL) >> $@
	@echo $(DL)BEGIN$(DL) >> $@
	@echo $(DL)  BLOCK "StringFileInfo"$(DL) >> $@
	@echo $(DL)  BEGIN$(DL) >> $@
	@echo $(DL)    BLOCK "040904E4"$(DL) >> $@
	@echo $(DL)    BEGIN$(DL) >> $@
	@echo $(DL)      VALUE "LegalCopyright","(C) $(LIBSSH2_COPYRIGHT_STR)$(NUL)"$(DL) >> $@
ifdef COMPANY
	@echo $(DL)      VALUE "CompanyName","$(COMPANY)$(NUL)"$(DL) >> $@
endif
	@echo $(DL)      VALUE "ProductName","$(notdir $(@:.rc=.exe))$(NUL)"$(DL) >> $@
	@echo $(DL)      VALUE "ProductVersion","$(LIBSSH2_VERSION_STR)$(NUL)"$(DL) >> $@
	@echo $(DL)      VALUE "License","Released under GPL.$(NUL)"$(DL) >> $@
	@echo $(DL)      VALUE "FileDescription","$(DESCR)$(NUL)"$(DL) >> $@
	@echo $(DL)      VALUE "FileVersion","$(LIBSSH2_VERSION_STR)$(NUL)"$(DL) >> $@
	@echo $(DL)      VALUE "InternalName","$(notdir $(@:.rc=))$(NUL)"$(DL) >> $@
	@echo $(DL)      VALUE "OriginalFilename","$(notdir $(@:.rc=.exe))$(NUL)"$(DL) >> $@
	@echo $(DL)      VALUE "WWW","$(WWWURL)$(NUL)"$(DL) >> $@
	@echo $(DL)    END$(DL) >> $@
	@echo $(DL)  END$(DL) >> $@
	@echo $(DL)  BLOCK "VarFileInfo"$(DL) >> $@
	@echo $(DL)  BEGIN$(DL) >> $@
	@echo $(DL)    VALUE "Translation", 0x409, 1200$(DL) >> $@
	@echo $(DL)  END$(DL) >> $@
	@echo $(DL)END$(DL) >> $@
ifdef ICON
	@echo $(DL)10 ICON DISCARDABLE "$(ICON)"$(DL) >> $@
endif

help: $(OBJDIR)/version.inc
	@echo $(DL)===========================================================$(DL)
	@echo $(DL)OpenSSL path    = $(OPENSSL_PATH)$(DL)
	@echo $(DL)Zlib path       = $(ZLIB_PATH)$(DL)
	@echo $(DL)===========================================================$(DL)
	@echo $(DL)libssh $(LIBSSH2_VERSION_STR) - available targets are:$(DL)
	@echo $(DL)$(MAKE) all$(DL)
	@echo $(DL)$(MAKE) clean$(DL)
	@echo $(DL)$(MAKE) objclean$(DL)
	@echo $(DL)===========================================================$(DL)
