AUTOMAKE_OPTIONS = foreign nostdinc

# samples
noinst_PROGRAMS = ssh2 \
		scp scp_nonblock \
		scp_write scp_write_nonblock \
		sftp sftp_nonblock \
		sftp_write sftp_write_nonblock \
		sftp_mkdir sftp_mkdir_nonblock \
		sftp_RW_nonblock \
		sftpdir sftpdir_nonblock

INCLUDES = -I. -I$(top_srcdir)/include
LDADD = $(top_builddir)/src/libssh2.la

