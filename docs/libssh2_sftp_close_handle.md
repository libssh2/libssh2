---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_sftp_close_handle
Section: 3
Source: libssh2
See-also:
  - libssh2_sftp_open_ex(3)
---

# NAME

libssh2_sftp_close_handle - close filehandle

# SYNOPSIS

~~~c
#include <libssh2.h>
#include <libssh2_sftp.h>

int
libssh2_sftp_close_handle(LIBSSH2_SFTP_HANDLE *handle);

int
libssh2_sftp_close(LIBSSH2_SFTP_HANDLE *handle);

int
libssh2_sftp_closedir(LIBSSH2_SFTP_HANDLE *handle);
~~~

# DESCRIPTION

*handle* - SFTP File Handle as returned by **libssh2_sftp_open_ex(3)**
or **libssh2_sftp_opendir(3)** (which is a macro).

Close an active LIBSSH2_SFTP_HANDLE. Because files and directories share the
same underlying storage mechanism these methods may be used
interchangeably. **libssh2_sftp_close(3)** and **libssh2_sftp_closedir(3)**
are macros for **libssh2_sftp_close_handle(3)**.

# RETURN VALUE

Return 0 on success or negative on failure. It returns
LIBSSH2_ERROR_EAGAIN when it would otherwise block. While
LIBSSH2_ERROR_EAGAIN is a negative number, it is not really a failure per se.

# ERRORS

*LIBSSH2_ERROR_ALLOC* - An internal memory allocation call failed.

*LIBSSH2_ERROR_SOCKET_SEND* - Unable to send data on socket.

*LIBSSH2_ERROR_SOCKET_TIMEOUT* -

*LIBSSH2_ERROR_SFTP_PROTOCOL* - An invalid SFTP protocol response was
received on the socket, or an SFTP operation caused an errorcode to
be returned by the server.
