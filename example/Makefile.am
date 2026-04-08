# Copyright (C) The libssh2 project and its contributors.
# SPDX-License-Identifier: BSD-3-Clause
AUTOMAKE_OPTIONS = foreign nostdinc

EXTRA_DIST = CMakeLists.txt

# Get noinst_PROGRAMS variable
include Makefile.inc

AM_CPPFLAGS = -I$(top_builddir)/src -I$(top_srcdir)/src -I$(top_srcdir)/include

# for fileno(), tcsetattr() in glibc ISO mode
AM_CPPFLAGS += -D_DEFAULT_SOURCE

LDADD = $(top_builddir)/src/libssh2.la

# This might hold -Werror
AM_CFLAGS = @LIBSSH2_CFLAG_EXTRAS@
