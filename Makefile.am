SUBDIRS = src example tests docs

include_HEADERS =			\
	include/libssh2.h		\
	include/libssh2_publickey.h	\
	include/libssh2_sftp.h

EXTRA_DIST = win32 buildconf

ACLOCAL_AMFLAGS = -I m4

.PHONY: ChangeLog
ChangeLog:
	if test -f .cvsusers; then \
	  cvs2cl --utc --fsf --FSF --usermap .cvsusers -I ChangeLog -I .cvs; \
	fi
