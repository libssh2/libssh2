---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_sftp_copydata
Section: 3
Source: libssh2
See-also:
  - libssh2_sftp_open_ex(3)
---

# NAME

libssh2_sftp_copydata - copy SFTP data from one handle to another

# SYNOPSIS

~~~c
#include <libssh2.h>
#include <libssh2_sftp.h>

int
libssh2_sftp_copydata(LIBSSH2_SFTP_HANDLE *source_handle,
                      const size_t source_offset,
                      const size_t len,
                      LIBSSH2_SFTP_HANDLE *dest_handle,
                      const size_t dest_offset);
~~~

# DESCRIPTION

**libssh2_sftp_copydata(3)** copies a block of data from source_handle to dest_handle locally on the server.

*source_handle* - SFTP file handle as returned by *libssh2_sftp_open_ex(3)*.

*source_offset* - offset in source_handle to start copy

*len* - Length of data to copy

*dest_handle* - SFTP file handle as returned by *libssh2_sftp_open_ex(3)*.

*dest_offset* - offset in dest_handle to copy to

*libssh2_sftp_copydata(3)* will copy *len* data from position *source_offset*
in *source_handle* to position *dest_offset* in *dest_handle*. If *len* is zero, the data is copied until EOF.

# RETURN VALUE

Zero or negative on failure.

If used in non-blocking mode, it returns LIBSSH2_ERROR_EAGAIN when it would
otherwise block. While LIBSSH2_ERROR_EAGAIN is a negative number, it is not
really a failure per se.

# ERRORS

*LIBSSH2_ERROR_ALLOC* - An internal memory allocation call failed.

*LIBSSH2_ERROR_SOCKET_SEND* - Unable to send data on socket.

*LIBSSH2_ERROR_SOCKET_TIMEOUT* -

*LIBSSH2_ERROR_SFTP_PROTOCOL* - An invalid SFTP protocol response was
received on the socket, or an SFTP operation caused an errorcode to
be returned by the server or operation not supported by server
(last_errno set to LIBSSH2_FX_OP_UNSUPPORTED.
