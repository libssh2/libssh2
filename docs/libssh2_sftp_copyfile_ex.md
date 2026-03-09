---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_sftp_copyfile_ex
Section: 3
Source: libssh2
See-also:
  - libssh2_sftp_init(3)
---

# NAME

libssh2_sftp_copyfile_ex - copy a remote file 

# SYNOPSIS

~~~c
#include <libssh2.h>
#include <libssh2_sftp.h>

int
libssh2_sftp_copyfile_ex(LIBSSH2_SFTP *sftp,
                         const char *source_path,
                         unsigned int source_path_len,
                         const char *dest_path,
                         unsigned int dest_path_len,
                         int overwrite_flg);

int
libssh2_sftp_copyfile(LIBSSH2_SFTP *sftp,
                         const char *source_path,
                         const char *dest_path);
~~~

# DESCRIPTION

*sftp* - SFTP instance as returned by libssh2_sftp_init(3)

*source_path* - Path and name of the existing filesystem entry

*sourc_path_len* - Length of the path and name of the existing
filesystem entry

*dest_path* - Path and name of the target filesystem entry

*dest_path_len* - Length of the path and name of the target
filesystem entry

*overwrite_flg* -
flag indicate if dest_path should be overwritten (if it exists).

Copy a filesystem object on the remote filesystem. The semantics of
this command typically include the ability to copy a filesystem object
between folders and/or filesystem mounts. If the overwrite_flg is not set
and the destfile entry already exists, the operation
will fail. This operation is done local on the remote server.

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
be returned by the server, or operation not supported by server
(last_errno set to LIBSSH2_FX_OP_UNSUPPORTED.
