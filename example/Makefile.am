# Copyright (C) The libssh2 project and its contributors.
# SPDX-License-Identifier: BSD-3-Clause
AUTOMAKE_OPTIONS = foreign nostdinc

EXTRA_DIST = CMakeLists.txt

# examples
noinst_PROGRAMS = \
  direct_tcpip \
  scp \
  scp_nonblock \
  scp_write \
  scp_write_nonblock \
  sftp \
  sftp_RW_nonblock \
  sftp_append \
  sftp_mkdir \
  sftp_mkdir_nonblock \
  sftp_nonblock \
  sftp_write \
  sftp_write_nonblock \
  sftp_write_sliding \
  sftpdir \
  sftpdir_nonblock \
  ssh2 \
  ssh2_agent \
  ssh2_agent_forwarding \
  ssh2_echo \
  ssh2_exec \
  subsystem_netconf \
  tcpip-forward \
  x11

AM_CPPFLAGS = -I$(top_builddir)/src -I$(top_srcdir)/src -I$(top_srcdir)/include
LDADD = $(top_builddir)/src/libssh2.la
