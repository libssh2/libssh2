---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_scp_send_ex
Section: 3
Source: libssh2
See-also:
  - libssh2_channel_open_ex(3)
  - libssh2_session_init_ex(3)
---

# NAME

libssh2_scp_send_ex - Send a file via SCP

# SYNOPSIS

~~~c
#include <libssh2.h>

LIBSSH2_CHANNEL *
libssh2_scp_send_ex(LIBSSH2_SESSION *session, const char *path, int mode,
                    size_t size, long mtime, long atime);
~~~

# DESCRIPTION

This function has been deemed deprecated since libssh2 1.2.6. See
*libssh2_scp_send64(3)*.

*session* - Session instance as returned by libssh2_session_init_ex(3)

*path* - Full path and filename of file to transfer to. That is the remote
file name.

*mode* - File access mode to create file with

*size* - Size of file being transmitted (Must be known
ahead of time precisely)

*mtime* - mtime to assign to file being created

*atime* - atime to assign to file being created (Set this and
mtime to zero to instruct remote host to use current time).

Send a file to the remote host via SCP.

# RETURN VALUE

Pointer to a newly allocated LIBSSH2_CHANNEL instance, or NULL on errors.

# ERRORS

*LIBSSH2_ERROR_ALLOC* - An internal memory allocation call failed.

*LIBSSH2_ERROR_SOCKET_SEND* - Unable to send data on socket.

*LIBSSH2_ERROR_SCP_PROTOCOL* -

*LIBSSH2_ERROR_EAGAIN* - Marked for non-blocking I/O but the call would
block.

# AVAILABILITY

This function was marked deprecated in libssh2 1.2.6 as
*libssh2_scp_send64(3)* has been introduced to replace this function.
