---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_sftp_posix_rename_ex
Section: 3
Source: libssh2
See-also:
  - libssh2_sftp_init(3)
---

# NAME

libssh2_sftp_posix_rename_ex - rename an SFTP file using POSIX semantics

# SYNOPSIS

~~~c
#include <libssh2.h>
#include <libssh2_sftp.h>

int
libssh2_sftp_posix_rename_ex(LIBSSH2_SFTP *sftp,
                             const char *source_filename,
                             size_t source_filename_len,
                             const char *dest_filename,
                             size_t dest_filename_len);
~~~

# DESCRIPTION

*sftp* - SFTP instance as returned by libssh2_sftp_init(3)

*sourcefile* - Path and name of the existing filesystem entry

*sourcefile_len* - Length of the path and name of the existing
filesystem entry

*destfile* - Path and name of the target filesystem entry

*destfile_len* - Length of the path and name of the target
filesystem entry

This function implements the posix-rename@openssh.com extension, which is
useful when, for example, moving files across filesystems on a remote server.
SSH_FXP_RENAME does not specify a specific implementation, but many servers
will attempt to user hard links when moving files using SSH_FXP_RENAME.

If the server does not support posix-rename@openssh.com, this function will
return LIBSSH2_FX_OP_UNSUPPORTED and you can call libssh2_sftp_rename_ex (3) as
a backup.

# RETURN VALUE

Return 0 on success or negative on failure. It returns
LIBSSH2_ERROR_EAGAIN when it would otherwise block. While
LIBSSH2_ERROR_EAGAIN is a negative number, it is not really a failure per se.

# ERRORS

*LIBSSH2_FX_OP_UNSUPPORTED* - Server does not support
posix-rename@openssh.com

*LIBSSH2_ERROR_ALLOC* - An internal memory allocation call failed.

*LIBSSH2_ERROR_SOCKET_SEND* - Unable to send data on socket.

*LIBSSH2_ERROR_SOCKET_TIMEOUT* -

*LIBSSH2_ERROR_SFTP_PROTOCOL* - An invalid SFTP protocol response was
received on the socket, or an SFTP operation caused an errorcode to
be returned by the server.
