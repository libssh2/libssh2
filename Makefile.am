SUBDIRS = src example tests docs

include_HEADERS =			\
	include/libssh2.h		\
	include/libssh2_publickey.h	\
	include/libssh2_sftp.h

NETWAREFILES =  nw/keepscreen.c \
 nw/Makefile \
 nw/Makefile.netware \
 nw/nwlib.c \
 nw/test/Makefile.netware

WIN32FILES = win32/libssh2_dll.dsp win32/libssh2.dsw win32/Makefile.win32      \
win32/config.mk win32/Makefile win32/test/Makefile.win32 win32/libssh2_lib.dsp \
win32/libssh2_config.h win32/tests.dsp win32/rules.mk

EXTRA_DIST = $(WIN32FILES) buildconf $(NETWAREFILES) get_ver.awk HACKING \
 maketgz NMakefile

ACLOCAL_AMFLAGS = -I m4

.PHONY: ChangeLog
ChangeLog:
	if test -f .cvsusers; then \
	  cvs2cl --utc --fsf --FSF --usermap .cvsusers -I ChangeLog -I .cvs; \
	fi

dist-hook:
	rm -rf $(top_builddir)/tests/log
	find $(distdir) -name "*.dist" -exec rm {} \;
	(distit=`find $(srcdir) -name "*.dist"`; \
	for file in $$distit; do \
	  strip=`echo $$file | sed -e s/^$(srcdir)// -e s/\.dist//`; \
	  cp $$file $(distdir)$$strip; \
	done)
