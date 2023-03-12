#########################################################################
#
# Makefile for building libssh2 samples (Windows version - GNU Make)
# Use: make -f GNUmakefile [help]
#
# Hacked by: Guenter Knauf
#
#########################################################################

# Build libssh2 via win32/GNUmakefike first.

PROOT := ../..

ifndef LINK_STATIC
  DYN := 1
endif

### Common

include $(PROOT)/win32/GNUmakefile

### Local

LDFLAGS += -L$(PROOT)/win32
LIBS    += -llibssh2

ifdef DYN
  libssh2_DEPENDENCIES += $(PROOT)/win32/libssh2.dll.a
else
  libssh2_DEPENDENCIES := $(PROOT)/win32/libssh2.a
  LDFLAGS += -static
endif

LIBS += -lws2_32

vpath %.c $(PROOT)/example

SAMPLES := $(PROOT)/example
TARGETS := $(filter-out x11.exe,$(patsubst $(SAMPLES)/%.c,%.exe,$(strip $(wildcard $(SAMPLES)/*.c))))

all: $(TARGETS)

%.exe: %.c $(libssh2_DEPENDENCIES)
	$(CC) -W -Wall $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) $< -o $@ $(LIBS)

clean:
	$(call DEL, $(TARGETS))

help:
	@echo $(DL)===========================================================$(DL)
	@echo $(DL)OpenSSL path    = $(OPENSSL_PATH)$(DL)
	@echo $(DL)Zlib path       = $(ZLIB_PATH)$(DL)
	@echo $(DL)===========================================================$(DL)
	@echo $(DL)libssh2 - available targets are:$(DL)
	@echo $(DL)$(MAKE) all$(DL)
	@echo $(DL)$(MAKE) clean$(DL)
	@echo $(DL)===========================================================$(DL)
