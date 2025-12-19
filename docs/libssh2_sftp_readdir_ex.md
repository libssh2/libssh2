---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_sftp_readdir_ex
Section: 3
Source: libssh2
See-also:
  - libssh2_sftp_close_handle(3)
  - libssh2_sftp_open_ex(3)
---

# NAME

libssh2_sftp_readdir_ex - read directory data from an SFTP handle

# SYNOPSIS

~~~c
#include <libssh2.h>
#include <libssh2_sftp.h>

int
libssh2_sftp_readdir_ex(LIBSSH2_SFTP_HANDLE *handle,
                        char *buffer, size_t buffer_maxlen,
                        char *longentry, size_t longentry_maxlen,
                        LIBSSH2_SFTP_ATTRIBUTES *attrs);
~~~

# DESCRIPTION

Reads a block of data from a LIBSSH2_SFTP_HANDLE and returns file entry
information for the next entry, if any.

*handle* - is the SFTP File Handle as returned by libssh2_sftp_open_ex(3)

*buffer* - is a pointer to a pre-allocated buffer of at least
*buffer_maxlen* bytes to read data into.

*buffer_maxlen* - is the length of buffer in bytes. If the length of the
filename is longer than the space provided by buffer_maxlen it will be
truncated to fit.

*longentry* - is a pointer to a pre-allocated buffer of at least
*longentry_maxlen* bytes to read data into. The format of the `longname'
field is unspecified by SFTP protocol. It MUST be suitable for use in the
output of a directory listing command (in fact, the recommended operation for
a directory listing command is to display this data).

*longentry_maxlen* - is the length of longentry in bytes. If the length of
the full directory entry is longer than the space provided by
*longentry_maxlen* it will be truncated to fit.

*attrs* - is a pointer to LIBSSH2_SFTP_ATTRIBUTES storage to populate
statbuf style data into.

# RETURN VALUE

Number of bytes actually populated into buffer (not counting the terminating
zero), or negative on failure. It returns LIBSSH2_ERROR_EAGAIN when it would
otherwise block. While LIBSSH2_ERROR_EAGAIN is a negative number, it is not
really a failure per se.

# BUG

Passing in a too small buffer for 'buffer' or 'longentry' when receiving data
only results in libssh2 1.2.7 or earlier to not copy the entire data amount,
and it is not possible for the application to tell when it happens!

# ERRORS

*LIBSSH2_ERROR_ALLOC* - An internal memory allocation call failed.

*LIBSSH2_ERROR_SOCKET_SEND* - Unable to send data on socket.

*LIBSSH2_ERROR_SOCKET_TIMEOUT* -

*LIBSSH2_ERROR_SFTP_PROTOCOL* - An invalid SFTP protocol response was
received on the socket, or an SFTP operation caused an errorcode to be
returned by the server.

From 1.2.8, LIBSSH2_ERROR_BUFFER_TOO_SMALL is returned if any of the
given 'buffer' or 'longentry' buffers are too small to fit the requested
object name.
