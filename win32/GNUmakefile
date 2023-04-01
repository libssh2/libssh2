#########################################################################
#
# Makefile for building libssh2 with GCC-like toolchains.
# Use: make -f GNUmakefile [help|all|clean|dist|distclean|dyn|objclean|test|testclean]
#
# Hacked by: Guenter Knauf
#
# Look for ' ?=' to find accepted customization variables.
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
LIBSSH2_LDFLAGS_DYN ?=
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

ifneq ($(findstring -w,$(TRIPLET)),)
  WIN32 := 1
  BIN_EXT := .exe
  DYN_EXT := .dll
endif

CPPFLAGS += -I$(PROOT)/win32 -I$(PROOT)/include
RCFLAGS  += -I$(PROOT)/include

OBJ_DIR := $(TRIPLET)

# examples, tests

LIBSSH2_LDFLAGS_BIN += -L$(PROOT)/win32
LIBS_BIN := -lssh2
ifdef WIN32
  LIBS_BIN += -lws2_32
endif

ifdef DYN
  ifdef WIN32
    libssh2_DEPENDENCIES := $(PROOT)/win32/libssh2.dll.a
  else
    libssh2_DEPENDENCIES := $(PROOT)/win32/libssh2$(DYN_EXT)
  endif
  LIBSSH2_LDFLAGS_BIN += -shared
else
  libssh2_DEPENDENCIES := $(PROOT)/win32/libssh2.a
  LIBSSH2_LDFLAGS_BIN += -static
endif

### Optional features

# must be equal to DEBUG or NDEBUG
DB ?= NDEBUG
CPPFLAGS += -D$(DB)
ifeq ($(DB),NDEBUG)
  OBJ_DIR := release-$(OBJ_DIR)
else
  OBJ_DIR := debug-$(OBJ_DIR)
  CFLAGS += -g
  CPPFLAGS += -DLIBSSH2DEBUG
endif

# Linker options to exclude for shared mode executables.
_LDFLAGS :=
_LIBS :=

ifdef OPENSSL_PATH
  CPPFLAGS += -DLIBSSH2_OPENSSL
  OPENSSL_INCLUDE ?= $(OPENSSL_PATH)/include
  OPENSSL_LIBPATH ?= $(OPENSSL_PATH)/lib
  CPPFLAGS += -I"$(OPENSSL_INCLUDE)"
  _LDFLAGS += -L"$(OPENSSL_LIBPATH)"
  OPENSSL_LIBS ?= -lssl -lcrypto
  _LIBS += $(OPENSSL_LIBS)
  include $(PROOT)/Makefile.OpenSSL.inc
else ifdef WOLFSSL_PATH
  CPPFLAGS += -DLIBSSH2_WOLFSSL
  CPPFLAGS += -I"$(WOLFSSL_PATH)/include"
  CPPFLAGS += -I"$(WOLFSSL_PATH)/include/wolfssl"
  _LDFLAGS += -L"$(WOLFSSL_PATH)/lib"
  _LIBS += -lwolfssl
  include $(PROOT)/Makefile.wolfSSL.inc
else ifdef LIBGCRYPT_PATH
  CPPFLAGS += -DLIBSSH2_LIBGCRYPT
  CPPFLAGS += -I"$(LIBGCRYPT_PATH)/include"
  _LDFLAGS += -L"$(LIBGCRYPT_PATH)/lib"
  _LIBS += -lgcrypt
  include $(PROOT)/Makefile.libgcrypt.inc
else ifdef MBEDTLS_PATH
  CPPFLAGS += -DLIBSSH2_MBEDTLS
  CPPFLAGS += -I"$(MBEDTLS_PATH)/include"
  _LDFLAGS += -L"$(MBEDTLS_PATH)/lib"
  _LIBS += -lmbedtls -lmbedx509 -lmbedcrypto
  include $(PROOT)/Makefile.mbedTLS.inc
else ifdef WIN32
  CPPFLAGS += -DLIBSSH2_WINCNG
  include $(PROOT)/Makefile.WinCNG.inc
endif

ifdef ZLIB_PATH
  CPPFLAGS += -DLIBSSH2_HAVE_ZLIB
  CPPFLAGS += -I"$(ZLIB_PATH)/include"
  _LDFLAGS += -L"$(ZLIB_PATH)/lib"
  _LIBS += -lz
endif

ifdef WIN32
  _LIBS += -lws2_32 -lcrypt32 -lbcrypt
endif

LIBSSH2_LDFLAGS_DYN += $(_LDFLAGS)
LIBS_DYN += $(_LIBS)

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
-include $(OBJ_DIR)/version.inc

vpath %.c $(PROOT)/src

# include Makefile.inc to get CSOURCES define
include $(PROOT)/Makefile.inc

OBJECTS := $(patsubst %.c,%.o,$(CSOURCES))
OBJS    := $(addprefix $(OBJ_DIR)/,$(OBJECTS))

TARGET := libssh2

# Override the path below to point to your Distribution folder.
DISTDIR ?= $(TARGET)-$(LIBSSH2_VERSION_STR)-bin-$(word 1,$(subst -, ,$(TRIPLET)))
DISTARC := $(DISTDIR).zip

LIBSSH2_DYN_SUFFIX ?=
libssh2_dyn_LIBRARY := $(TARGET)$(LIBSSH2_DYN_SUFFIX)$(DYN_EXT)
OBJS_dyn := $(OBJS)
ifdef WIN32
  libssh2_dyn_a_LIBRARY := $(TARGET).dll.a
  OBJS_dyn += $(OBJ_DIR)/$(TARGET).res
  LIBSSH2_LDFLAGS_DYN += -Wl,--output-def,$(libssh2_dyn_LIBRARY:$(DYN_EXT)=.def),--out-implib,$(libssh2_dyn_a_LIBRARY)
endif

TARGETS_EXAMPLES := $(patsubst %.c,%$(BIN_EXT),$(strip $(wildcard $(PROOT)/example/*.c)))

all: lib dyn

# For compatibility
dll: dyn

dyn: prebuild $(libssh2_dyn_LIBRARY)

lib: prebuild $(TARGET).a

prebuild: $(OBJ_DIR) $(OBJ_DIR)/version.inc

test: $(TARGETS_EXAMPLES)

%$(BIN_EXT): %.c $(libssh2_DEPENDENCIES)
	$(CC) -W -Wall $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) $(LIBSSH2_LDFLAGS_BIN) $< -o $@ $(LIBS) $(LIBS_BIN)

$(OBJ_DIR)/%.o: %.c
	$(CC) -W -Wall $(CFLAGS) $(CPPFLAGS) -c $< -o $@

$(libssh2_dyn_LIBRARY) $(libssh2_dyn_a_LIBRARY): $(OBJS_dyn)
	@$(call DEL, $@)
	$(CC) $(LDFLAGS) -shared $(LIBSSH2_LDFLAGS_DYN) $^ -o $@ $(LIBS) $(LIBS_DYN)

ifdef WIN32
$(OBJ_DIR)/%.res: %.rc
	$(RC) -O coff $(RCFLAGS) -i $< -o $@
endif

$(TARGET).a: $(OBJS)
	@$(call DEL, $@)
	$(AR) rcs $@ $^

$(OBJ_DIR)/version.inc: $(PROOT)/get_ver.awk $(PROOT)/include/libssh2.h $(OBJ_DIR)
	$(AWK) -f $^ > $@

dist: all $(DISTDIR) $(DISTDIR)/readme.txt
	@$(call MKDIR, $(DISTDIR)/bin)
	@$(call MKDIR, $(DISTDIR)/include)
	@$(call MKDIR, $(DISTDIR)/lib)
	@$(call COPY, $(PROOT)/COPYING, $(DISTDIR))
	@$(call COPY, $(PROOT)/README, $(DISTDIR))
	@$(call COPY, $(PROOT)/RELEASE-NOTES, $(DISTDIR))
	@$(call COPY, $(libssh2_dyn_LIBRARY), $(DISTDIR)/bin)
	@$(call COPY, $(PROOT)/include/*.h, $(DISTDIR)/include)
	@$(call COPY, libssh2_config.h, $(DISTDIR)/include)
	@$(call COPY, *.a, $(DISTDIR)/lib)
	@echo Creating... $(DISTARC)
	@$(ZIP) $(DISTARC) $(DISTDIR)/* < $(DISTDIR)/readme.txt

distclean vclean: clean
	$(call RMDIR, $(DISTDIR))
	$(call DEL, $(DISTARC))

objclean: all
	$(call RMDIR, $(OBJ_DIR))

testclean: clean
	$(call DEL, $(TARGETS_EXAMPLES))

clean:
	$(call DEL, $(libssh2_dyn_LIBRARY) $(libssh2_dyn_LIBRARY:$(DYN_EXT)=.def) $(TARGET).a $(libssh2_dyn_a_LIBRARY))
	$(call RMDIR, $(OBJ_DIR))

$(OBJ_DIR):
	@$(call MKDIR, $@)

$(DISTDIR):
	@$(call MKDIR, $@)

$(DISTDIR)/readme.txt: GNUmakefile
	@echo Creating... $@
	@echo $(DL)This is a binary distribution for $(TRIPLET).$(DL) > $@
	@echo $(DL)libssh2 version $(LIBSSH2_VERSION_STR)$(DL) >> $@
	@echo $(DL)Please download the complete libssh2 package for$(DL) >> $@
	@echo $(DL)any further documentation:$(DL) >> $@
	@echo $(DL)$(HOMEPAGE)$(DL) >> $@

help: $(OBJ_DIR)/version.inc
	@echo $(DL)===========================================================$(DL)
	@echo $(DL)OpenSSL path    = $(OPENSSL_PATH)$(DL)
	@echo $(DL)wolfSSL path    = $(WOLFSSL_PATH)$(DL)
	@echo $(DL)mbedTLS path    = $(MBEDTLS_PATH)$(DL)
	@echo $(DL)zlib path       = $(ZLIB_PATH)$(DL)
	@echo $(DL)===========================================================$(DL)
	@echo $(DL)libssh2 $(LIBSSH2_VERSION_STR) - available targets are:$(DL)
	@echo $(DL)$(MAKE) all$(DL)
	@echo $(DL)$(MAKE) dyn$(DL)
	@echo $(DL)$(MAKE) lib$(DL)
	@echo $(DL)$(MAKE) clean$(DL)
	@echo $(DL)$(MAKE) dist$(DL)
	@echo $(DL)$(MAKE) distclean$(DL)
	@echo $(DL)$(MAKE) objclean$(DL)
	@echo $(DL)$(MAKE) test$(DL)
	@echo $(DL)$(MAKE) testclean$(DL)
	@echo $(DL)===========================================================$(DL)
