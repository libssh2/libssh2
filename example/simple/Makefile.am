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

# the examples need the $(top_builddir)/src since when building outside of the
# source dir they still need to reach the libssh2_config.h header
AM_CPPFLAGS = -I$(top_srcdir)/src -I$(top_srcdir)/include -I$(top_builddir)/src
LDADD = $(top_builddir)/src/libssh2.la
