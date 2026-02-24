# Copyright (C) The libssh2 project and its contributors.
# SPDX-License-Identifier: BSD-3-Clause

AUTOMAKE_OPTIONS = foreign no-dependencies

if BUILD_DOCS
# Get man_MANS variable
include Makefile.inc

MANPAGES = $(man_MANS:.3=.md)
CLEANFILES = $(man_MANS)
SUFFIXES = .3 .md

.md.3:
	$(srcdir)/cd2nroff $< >$@

endif

EXTRA_DIST = $(MANPAGES) template.md cd2nroff AUTHORS BINDINGS.md HACKING.md \
  HACKING-CRYPTO INSTALL_AUTOTOOLS INSTALL_CMAKE.md SECURITY.md TODO \
  CMakeLists.txt
