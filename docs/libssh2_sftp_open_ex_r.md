---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_sftp_open_ex_r
Section: 3
Source: libssh2
See-also:
  - libssh2_sftp_close_handle(3)
  - libssh2_sftp_fstat_ex(3)
---

# NAME

libssh2_sftp_open_ex_r - open filehandle for file on SFTP.

# SYNOPSIS

~~~c
#include <libssh2.h>
#include <libssh2_sftp.h>

LIBSSH2_SFTP_HANDLE *
libssh2_sftp_open_ex_r(LIBSSH2_SFTP *sftp, const char *filename,
                       size_t filename_len,
                       unsigned long flags,
                       long mode,
                       int open_type,
                       LIBSSH2_SFTP_ATTRIBUTES *attrs);
~~~

# DESCRIPTION

*sftp* - SFTP instance as returned by *libssh2_sftp_init(3)*

*filename* - Remote file/directory resource to open

*filename_len* - Length of filename

*flags* - Any reasonable combination of the LIBSSH2_FXF_* constants:

## LIBSSH2_FXF_READ

Open the file for reading.

## LIBSSH2_FXF_WRITE

Open the file for writing. If both this and LIBSSH2_FXF_READ are specified,
the file is opened for both reading and writing.

## LIBSSH2_FXF_APPEND

Force all writes to append data at the end of the file.

## LIBSSH2_FXF_CREAT,

If this flag is specified, then a new file will be created if one does not
already exist (if LIBSSH2_FXF_TRUNC is specified, the new file will be
truncated to zero length if it previously exists)

## LIBSSH2_FXF_TRUNC

Forces an existing file with the same name to be truncated to zero length when
creating a file by specifying LIBSSH2_FXF_CREAT. LIBSSH2_FXF_CREAT MUST also
be specified if this flag is used.

## LIBSSH2_FXF_EXCL

Causes the request to fail if the named file already exists.
LIBSSH2_FXF_CREAT MUST also be specified if this flag is used.

*mode* - POSIX file permissions to assign if the file is being newly
created. See the LIBSSH2_SFTP_S_\* convenience defines in \<libssh2_sftp.h\>

*open_type* - Either of LIBSSH2_SFTP_OPENFILE (to open a file) or
LIBSSH2_SFTP_OPENDIR (to open a directory).

*attrs* - Pointer to LIBSSH2_SFTP_ATTRIBUTES struct. See
libssh2_sftp_fstat_ex for detailed usage.

# RETURN VALUE

A pointer to the newly created LIBSSH2_SFTP_HANDLE instance or NULL on
failure.

# ERRORS

*LIBSSH2_ERROR_ALLOC* - An internal memory allocation call failed.

*LIBSSH2_ERROR_SOCKET_SEND* - Unable to send data on socket.

*LIBSSH2_ERROR_SOCKET_TIMEOUT* -

*LIBSSH2_ERROR_SFTP_PROTOCOL* - An invalid SFTP protocol response was
received on the socket, or an SFTP operation caused an errorcode to be
returned by the server.

*LIBSSH2_ERROR_EAGAIN* - Marked for non-blocking I/O but the call would
block.

# AVAILABILITY

Added in libssh2 1.11.0
