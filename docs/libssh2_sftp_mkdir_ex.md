---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_sftp_mkdir_ex
Section: 3
Source: libssh2
See-also:
  - libssh2_sftp_init(3)
  - libssh2_sftp_open_ex(3)
---

# NAME

libssh2_sftp_mkdir_ex - create a directory on the remote file system

# SYNOPSIS

~~~c
#include <libssh2.h>
#include <libssh2_sftp.h>

int
libssh2_sftp_mkdir_ex(LIBSSH2_SFTP *sftp,
                      const char *path, unsigned int path_len,
                      long mode);

int
libssh2_sftp_mkdir(LIBSSH2_SFTP *sftp,
                   const char *path,
                   long mode);
~~~

# DESCRIPTION

*sftp* - SFTP instance as returned by libssh2_sftp_init(3)

*path* - full path of the new directory to create. Note that the new
directory's parents must all exist prior to making this call.

*path_len* - length of the full path of the new directory to create.

*mode* - directory creation mode (e.g. 0755).

Create a directory on the remote file system.

# RETURN VALUE

Return 0 on success or negative on failure.
LIBSSH2_ERROR_EAGAIN when it would otherwise block. While
LIBSSH2_ERROR_EAGAIN is a negative number, it is not really a failure per se.

# ERRORS

*LIBSSH2_ERROR_ALLOC* - An internal memory allocation call failed.

*LIBSSH2_ERROR_SOCKET_SEND* - Unable to send data on socket.

*LIBSSH2_ERROR_SOCKET_TIMEOUT* -

*LIBSSH2_ERROR_SFTP_PROTOCOL* - An invalid SFTP protocol response was
received on the socket, or an SFTP operation caused an errorcode to be
returned by the server.
