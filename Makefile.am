AUTOMAKE_OPTIONS = foreign nostdinc

SUBDIRS = src

include_HEADERS = include/libssh2.h include/libssh2_publickey.h	\
 include/libssh2_sftp.h

# and a sample tool
noinst_PROGRAMS = ssh2_sample

ssh2_sample_SOURCES = ssh2_sample.c

ssh2_sample_LDADD = src/libssh2.la

EXTRA_DIST = LICENSE win32
