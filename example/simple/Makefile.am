AUTOMAKE_OPTIONS = foreign nostdinc

# samples
noinst_PROGRAMS = ssh2 scp_nonblock sftp_nonblock sftp scp sftpdir

INCLUDES = -I$(top_srcdir)/include
LDADD = $(top_builddir)/src/libssh2.la

ssh2_SOURCES = ssh2.c

sftp_SOURCES = sftp.c

sftpdir_SOURCES = sftpdir.c

scp_nonblock_SOURCES = scp_nonblock.c

sftp_nonblock_SOURCES = sftp_nonblock.c

scp_SOURCES = scp.c
