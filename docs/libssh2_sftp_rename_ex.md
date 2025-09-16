---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_sftp_rename_ex
Section: 3
Source: libssh2
See-also:
  - libssh2_sftp_init(3)
---

# NAME

libssh2_sftp_rename_ex - rename an SFTP file

# SYNOPSIS

~~~c
#include <libssh2.h>
#include <libssh2_sftp.h>

int
libssh2_sftp_rename_ex(LIBSSH2_SFTP *sftp,
                       const char *source_filename,
                       unsigned int source_filename_len,
                       const char *dest_filename,
                       unsigned int dest_filename_len,
                       long flags);

int
libssh2_sftp_rename_ex(LIBSSH2_SFTP *sftp,
                       const char *source_filename,
                       const char *dest_filename);
~~~

# DESCRIPTION

*sftp* - SFTP instance as returned by libssh2_sftp_init(3)

*sourcefile* - Path and name of the existing filesystem entry

*sourcefile_len* - Length of the path and name of the existing
filesystem entry

*destfile* - Path and name of the target filesystem entry

*destfile_len* - Length of the path and name of the target
filesystem entry

*flags* -
Bitmask flags made up of LIBSSH2_SFTP_RENAME_* constants.

Rename a filesystem object on the remote filesystem. The semantics of
this command typically include the ability to move a filesystem object
between folders and/or filesystem mounts. If the LIBSSH2_SFTP_RENAME_OVERWRITE
flag is not set and the destfile entry already exists, the operation
will fail. Use of the other two flags indicate a preference (but not a
requirement) for the remote end to perform an atomic rename operation
and/or using native system calls when possible.

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
