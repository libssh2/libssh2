AUTOMAKE_OPTIONS = foreign nostdinc

SUBDIRS = src tests

include_HEADERS = include/libssh2.h include/libssh2_publickey.h	\
 include/libssh2_sftp.h

# and a sample tool
noinst_PROGRAMS = ssh2_sample

INCLUDES = -I$(top_srcdir)/include

ssh2_sample_SOURCES = ssh2_sample.c

ssh2_sample_LDADD = src/libssh2.la

EXTRA_DIST = LICENSE win32

ACLOCAL_AMFLAGS = -I m4
