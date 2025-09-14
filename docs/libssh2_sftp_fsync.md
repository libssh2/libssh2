---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_sftp_fsync
Section: 3
Source: libssh2
See-also:
  - fsync(2)
  - libssh2_sftp_open_ex(3)
---

# NAME

libssh2_sftp_fsync - synchronize file to disk

# SYNOPSIS

~~~c
#include <libssh2.h>
#include <libssh2_sftp.h>

int
libssh2_sftp_fsync(LIBSSH2_SFTP_HANDLE *handle)
~~~

# DESCRIPTION

This function causes the remote server to synchronize the file
data and metadata to disk (like fsync(2)).

For this to work requires fsync@openssh.com support on the server.

*handle* - SFTP File Handle as returned by libssh2_sftp_open_ex(3)

# RETURN VALUE

Returns 0 on success or negative on failure. If used in non-blocking mode, it
returns LIBSSH2_ERROR_EAGAIN when it would otherwise block. While
LIBSSH2_ERROR_EAGAIN is a negative number, it is not really a failure per se.

# ERRORS

*LIBSSH2_ERROR_ALLOC* - An internal memory allocation call failed.

*LIBSSH2_ERROR_SOCKET_SEND* - Unable to send data on socket.

*LIBSSH2_ERROR_SFTP_PROTOCOL* - An invalid SFTP protocol response
was received on the socket, or an SFTP operation caused an errorcode
to be returned by the server. In particular, this can be returned if
the SSH server does not support the fsync operation: the SFTP subcode
*LIBSSH2_FX_OP_UNSUPPORTED* will be returned in this case.

# AVAILABILITY

Added in libssh2 1.4.4 and OpenSSH 6.3.
