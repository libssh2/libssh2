---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_sftp_expand_path
Section: 3
Source: libssh2
See-also:
  - libssh2_sftp_init(3)
  - libssh2_sftp_open_ex(3)
  - libssh2_sftp_open_ex(3)
---

# NAME

libssh2_sftp_expand_path - expand a remote path on SFTP

# SYNOPSIS

~~~c
#include <libssh2.h>
#include <libssh2_sftp.h>

int libssh2_sftp_expand_path(LIBSSH2_SFTP *sftp,
                             const char *path, size_t path_len,
                             char *target, size_t target_len);
~~~

# DESCRIPTION

Expands a remote path and requires the expand-path@openssh.com extension to be supported on the server.

*sftp* - SFTP instance as returned by *libssh2_sftp_init(3)*

*path* - The path to expand, eg. ~username.

*path_len* - length of the full path.

*target* - is a pointer to a pre-allocated buffer of at least
*target_len* bytes to read the expanded path into.

# RETURN VALUE

Number of bytes actually populated into the target buffer (not counting the
null-terminator), or negative on failure. It returns LIBSSH2_ERROR_EAGAIN when
it would otherwise block. While LIBSSH2_ERROR_EAGAIN is a negative number, it is
not really a failure per se.

# ERRORS

*LIBSSH2_ERROR_ALLOC* - An internal memory allocation call failed.

*LIBSSH2_ERROR_SOCKET_SEND* - Unable to send data on socket.

*LIBSSH2_ERROR_SOCKET_TIMEOUT* -

*LIBSSH2_ERROR_SFTP_PROTOCOL* - An invalid SFTP protocol response was
received on the socket, or an SFTP operation caused an errorcode to be returned
by the server.
