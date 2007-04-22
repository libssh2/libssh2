AUTOMAKE_OPTIONS = foreign nostdinc

# samples
noinst_PROGRAMS = ssh2 \
		scp scp_nonblock \
		sftp sftp_nonblock \
		sftp_write sftp_write_nonblock \
		sftp_mkdir sftp_mkdir_nonblock \
		sftp_RW_nonblock \
		sftpdir sftpdir_nonblock

INCLUDES = -I$(top_srcdir)/include
LDADD = $(top_builddir)/src/libssh2.la

ssh2_SOURCES = ssh2.c

scp_SOURCES = scp.c

scp_nonblock_SOURCES = scp_nonblock.c

sftp_SOURCES = sftp.c

sftp_nonblock_SOURCES = sftp_nonblock.c

sftp_write_SOURCES = sftp_write.c

sftp_write_nonblock_SOURCES = sftp_write_nonblock.c

sftp_mkdir_SOURCES = sftp_mkdir.c

sftp_mkdir_nonblock_SOURCES = sftp_mkdir_nonblock.c

sftpdir_SOURCES = sftpdir.c

sftpdir_nonblock_SOURCES = sftpdir_nonblock.c

sftp_RW_nonblock_SOURCES = sftp_RW_nonblock.c

