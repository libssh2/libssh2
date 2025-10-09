---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_scp_recv2
Section: 3
Source: libssh2
See-also:
  - libssh2_channel_open_ex(3)
  - libssh2_session_init_ex(3)
  - libssh2_session_init_ex(3)
---

# NAME

libssh2_scp_recv2 - request a remote file via SCP

# SYNOPSIS

~~~c
#include <libssh2.h>

LIBSSH2_CHANNEL *
libssh2_scp_recv2(LIBSSH2_SESSION *session, const char *path, struct_stat *sb);
~~~

# DESCRIPTION

*session* - Session instance as returned by

*path* - Full path and filename of file to transfer. That is the remote
file name.

*sb* - Populated with remote file's size, mode, mtime, and atime

Request a file from the remote host via SCP.

# RETURN VALUE

Pointer to a newly allocated LIBSSH2_CHANNEL instance, or NULL on errors.

# ERRORS

*LIBSSH2_ERROR_ALLOC* - An internal memory allocation call failed.

*LIBSSH2_ERROR_INVAL* - Invalid argument used in function call.

*LIBSSH2_ERROR_SCP_PROTOCOL* -

*LIBSSH2_ERROR_EAGAIN* - Marked for non-blocking I/O but the call would
block.
