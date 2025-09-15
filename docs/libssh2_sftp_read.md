---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_sftp_read
Section: 3
Source: libssh2
See-also:
  - libssh2_sftp_open_ex(3)
  - libssh2_sftp_read(3)
  - read(2)
---

# NAME

libssh2_sftp_read - read data from an SFTP handle

# SYNOPSIS

~~~c
#include <libssh2.h>
#include <libssh2_sftp.h>

ssize_t
libssh2_sftp_read(LIBSSH2_SFTP_HANDLE *handle,
                  char *buffer, size_t buffer_maxlen);
~~~

# DESCRIPTION

*handle* is the SFTP File Handle as returned by libssh2_sftp_open_ex(3)

*buffer* is a pointer to a pre-allocated buffer of at least

*buffer_maxlen* bytes to read data into.

Reads a block of data from an LIBSSH2_SFTP_HANDLE. This method is modelled
after the POSIX read(2)
function and uses the same calling semantics. libssh2_sftp_read(3)
will attempt to read as much as possible however it may not fill all of buffer
if the file pointer reaches the end or if further reads would cause the socket
to block.

# RETURN VALUE

Number of bytes actually populated into buffer, or negative on failure.
It returns LIBSSH2_ERROR_EAGAIN when it would otherwise block. While
LIBSSH2_ERROR_EAGAIN is a negative number, it is not really a failure per se.

# ERRORS

*LIBSSH2_ERROR_ALLOC* - An internal memory allocation call failed.

*LIBSSH2_ERROR_SOCKET_SEND* - Unable to send data on socket.

*LIBSSH2_ERROR_SOCKET_TIMEOUT* -

*LIBSSH2_ERROR_SFTP_PROTOCOL* - An invalid SFTP protocol response was
received on the socket, or an SFTP operation caused an errorcode to be
returned by the server.
