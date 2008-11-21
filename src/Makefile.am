# $Id: Makefile.am,v 1.13 2008/11/21 14:34:03 jas4711 Exp $
AUTOMAKE_OPTIONS = foreign nostdinc

libssh2_la_SOURCES = channel.c comp.c crypt.c hostkey.c kex.c mac.c	\
misc.c packet.c publickey.c scp.c session.c sftp.c userauth.c		\
libssh2_priv.h openssl.h libgcrypt.h transport.c

if LIBGCRYPT
libssh2_la_SOURCES += libgcrypt.c pem.c
else
libssh2_la_SOURCES += openssl.c
endif

EXTRA_DIST = libssh2_config.h.in NMakefile

lib_LTLIBRARIES = libssh2.la

# srcdir/include for the shipped headers
# builddir/src for the generated config header when building out of the source
# tree
AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_builddir)/src

VERSION=-version-info 1:0:0

# This flag accepts an argument of the form current[:revision[:age]]. So,
# passing -version-info 3:12:1 sets current to 3, revision to 12, and age to
# 1.
#
# If either revision or age are omitted, they default to 0. Also note that age
# must be less than or equal to the current interface number.
#
# Here are a set of rules to help you update your library version information:
#
# 1.Start with version information of 0:0:0 for each libtool library.
#
# 2.Update the version information only immediately before a public release of
# your software. More frequent updates are unnecessary, and only guarantee
# that the current interface number gets larger faster.
#
# 3.If the library source code has changed at all since the last update, then
# increment revision (c:r+1:a)
#
# 4.If any interfaces have been added, removed, or changed since the last
# update, increment current, and set revision to 0. (c+1:r=0:a)
#
# 5.If any interfaces have been added since the last public release, then
# increment age. (c:r:a+1)
#
# 6.If any interfaces have been removed since the last public release, then
# set age to 0. (c:r:a=0)
#

libssh2_la_LDFLAGS = $(VERSION) -no-undefined \
	$(LTLIBGCRYPT) $(LTLIBSSL) $(LTLIBZ)
