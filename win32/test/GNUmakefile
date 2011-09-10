#########################################################################
#
## Makefile for building libssh2 samples (Win32 version - gnu make)
## Use: make -f GNUmakefile [help]
##
## Hacked by: Guenter Knauf
#
#########################################################################

# Edit the path below to point to the base of your Zlib sources.
ifndef ZLIB_PATH
ZLIB_PATH = ../../../zlib-1.2.5
endif

# Edit the path below to point to the base of your OpenSSL package.
ifndef OPENSSL_PATH
OPENSSL_PATH = ../../../openssl-0.9.8r
endif

# Edit the var below to set to your architecture or set environment var.
ifndef ARCH
ARCH = w32
endif

# Edit the var below to enable static linking of libssh2 and libz
LINK_STATIC = 1

# Edit the vars below to change target settings.
SAMPLES	= ../../example
TARGETS := $(filter-out x11.exe,$(patsubst $(SAMPLES)/%.c,%.exe,$(strip $(wildcard $(SAMPLES)/*.c))))
VERSION	= $(LIBSSH2_VERSION)
COPYR   = (c) $(LIBSSH2_COPYRIGHT_STR)
WWWURL	= http://www.libssh2.org/
DESCR	= libssh2 $(subst .rc,,$(notdir $@)) $(LIBSSH2_VERSION_STR)
#STACK	= 64000

# must be equal to DEBUG or NDEBUG
ifndef DB
	DB	= NDEBUG
	# DB	= DEBUG
endif
# Optimization: -O<n> or debugging: -g
ifeq ($(DB),NDEBUG)
	OPT	= -O2
	OBJDIR	= release
else
	OPT	= -g
	OBJDIR	= debug
endif

# Include the version info retrieved from libssh2.h
-include $(OBJDIR)/version.inc

ifeq ($(findstring /sh,$(SHELL)),/sh)
CP      = cp -afv
# RM    = rm -f
MD      = mkdir
RD      = rm -fr
DL      = '
DS      = /
else
CP      = copy
RM      = del /q /f 2>NUL
MD      = md
RD      = rd /q /s 2>NUL
XX      =
DS      = $(XX)\$(XX)
endif
# Here you can find a native Win32 binary of the original awk:
# http://www.gknw.net/development/prgtools/awk-20100523.zip
AWK     = awk
ZIP     = zip -qzr9

# The following line defines your compiler.
ifdef METROWERKS
	CC = mwcc
else
	CC = $(CROSSPREFIX)gcc
endif

# Global flags for all compilers
CFLAGS	= $(OPT) -D$(DB) -DWIN32 -DLIBSSH2_WIN32 # -DHAVE_CONFIG_H
ifeq ($(ARCH),w64)
CFLAGS  += -D_AMD64_
endif

ifeq ($(CC),mwcc)
LD	= mwld
RC	= mwwinrc
LDFLAGS	= -nostdlib
AR	= $(LD)
ARFLAGS	= -nostdlib -library -o
LIBEXT	= lib
LIBPATH	+= -lr "$(METROWERKS)/MSL" -lr "$(METROWERKS)/Win32-x86 Support"
LDLIBS	+= -lMSL_Runtime_x86.lib -lMSL_C_x86.lib -lMSL_Extras_x86.lib
LDLIBS	+= -lkernel32.lib -luser32.lib -lwsock32.lib
RCFLAGS	=
CFLAGS	+= -nostdinc -gccinc -msgstyle gcc -inline off -opt nointrinsics -proc 586
CFLAGS	+= -ir "$(METROWERKS)/MSL" -ir "$(METROWERKS)/Win32-x86 Support"
CFLAGS	+= -w on,nounused,nounusedexpr # -ansi strict
else
LD	= $(CROSSPREFIX)gcc
RC	= $(CROSSPREFIX)windres
LDFLAGS	= -s
AR	= $(CROSSPREFIX)ar
ARFLAGS	= -cq
LIBEXT	= a
#LDLIBS	+= -lwsock32
LDLIBS	+= -lws2_32
RCFLAGS	= -O coff -i
CFLAGS	+= -fno-strict-aliasing
CFLAGS	+= -Wall #-Wno-unused #-pedantic
endif

INCLUDES = -I.. -I../../include
INCLUDES += -I$(OPENSSL_PATH)/outinc -I$(OPENSSL_PATH)/outinc/openssl
#LIBPATH += -L$(OPENSSL_PATH)/out
LIBPATH += -L..

ifdef LINK_STATIC
	LDLIBS += -llibssh2
	#LDLIBS += $(OPENSSL_PATH)/out/libcrypto.$(LIBEXT) $(OPENSSL_PATH)/out/libssl.$(LIBEXT)
else
	LDLIBS += -llibssh2dll
	#LDLIBS += $(OPENSSL_PATH)/out/libeay32.$(LIBEXT) $(OPENSSL_PATH)/out/libssl32.$(LIBEXT)
endif

ifdef WITH_ZLIB
	INCLUDES += -I$(ZLIB_PATH)
	#LIBPATH = -L$(ZLIB_PATH)
#ifdef LINK_STATIC
#	LDLIBS += $(ZLIB_PATH)/libz.$(LIBEXT)
#else
#	LDLIBS += $(ZLIB_PATH)/libzdll.$(LIBEXT)
#endif
endif

CFLAGS	+= $(INCLUDES)

vpath %.c ../../example

.PRECIOUS: $(OBJDIR)/%.o $(OBJDIR)/%.rc $(OBJDIR)/%.res


all: prebuild $(TARGETS)

prebuild: $(OBJDIR) $(OBJDIR)/version.inc

$(OBJDIR)/%.o: %.c
#	@echo Compiling $<
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR)/version.inc: ../../include/libssh2.h $(OBJDIR)
	@echo Creating $@
	@$(AWK) -f ../../get_ver.awk $< > $@

objclean:
	-$(RD) $(OBJDIR)

clean: objclean
	-$(RM) $(TARGETS)

$(OBJDIR):
	$(MD) $@

%.exe: $(OBJDIR)/%.o $(OBJDIR)/%.res
	@echo Linking $@
	@-$(RM) $@
	$(LD) $(LDFLAGS) $^ -o $@ $(LIBPATH) $(LDLIBS)

$(OBJDIR)/%.res: $(OBJDIR)/%.rc
	@echo Creating $@
	@$(RC) $(RCFLAGS) $< -o $@

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
	@echo $(DL)      VALUE "LegalCopyright","$(COPYR)\0"$(DL) >> $@
ifdef COMPANY
	@echo $(DL)      VALUE "CompanyName","$(COMPANY)\0"$(DL) >> $@
endif
	@echo $(DL)      VALUE "ProductName","$(notdir $(@:.rc=.exe))\0"$(DL) >> $@
	@echo $(DL)      VALUE "ProductVersion","$(LIBSSH2_VERSION_STR)\0"$(DL) >> $@
	@echo $(DL)      VALUE "License","Released under GPL.\0"$(DL) >> $@
	@echo $(DL)      VALUE "FileDescription","$(DESCR)\0"$(DL) >> $@
	@echo $(DL)      VALUE "FileVersion","$(LIBSSH2_VERSION_STR)\0"$(DL) >> $@
	@echo $(DL)      VALUE "InternalName","$(notdir $(@:.rc=))\0"$(DL) >> $@
	@echo $(DL)      VALUE "OriginalFilename","$(notdir $(@:.rc=.exe))\0"$(DL) >> $@
	@echo $(DL)      VALUE "WWW","$(WWWURL)\0"$(DL) >> $@
	@echo $(DL)    END$(DL) >> $@
	@echo $(DL)  END$(DL) >> $@
	@echo $(DL)  BLOCK "VarFileInfo"$(DL) >> $@
	@echo $(DL)  BEGIN$(DL) >> $@
	@echo $(DL)    VALUE "Translation", 0x409, 1252$(DL) >> $@
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


