---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_scp_send64
Section: 3
Source: libssh2
See-also:
  - libssh2_channel_open_ex(3)
  - libssh2_session_init_ex(3)
---

# NAME

libssh2_scp_send64 - Send a file via SCP

# SYNOPSIS

~~~c
#include <libssh2.h>

LIBSSH2_CHANNEL *
libssh2_scp_send64(LIBSSH2_SESSION *session, const char *path, int mode,
                   libssh2_uint64_t size, time_t mtime, time_t atime);
~~~

# DESCRIPTION

*session* - Session instance as returned by libssh2_session_init_ex(3)

*path* - Full path and filename of file to transfer to. That is the remote
file name.

*mode* - File access mode to create file with

*size* - Size of file being transmitted (Must be known ahead of
time). Note that this needs to be passed on as variable type
libssh2_uint64_t. This type is 64 bit on modern operating systems and
compilers.

*mtime* - mtime to assign to file being created

*atime* - atime to assign to file being created (Set this and
mtime to zero to instruct remote host to use current time).

Send a file to the remote host via SCP.

# RETURN VALUE

Pointer to a newly allocated LIBSSH2_CHANNEL instance, or NULL on errors.

# ERRORS

*LIBSSH2_ERROR_ALLOC* - An internal memory allocation call failed.

*LIBSSH2_ERROR_INVAL* - Invalid argument used in function call.

*LIBSSH2_ERROR_SOCKET_SEND* - Unable to send data on socket.

*LIBSSH2_ERROR_SCP_PROTOCOL* -

*LIBSSH2_ERROR_EAGAIN* - Marked for non-blocking I/O but the call would
block.

# AVAILABILITY

This function was added in libssh2 1.2.6 and is meant to replace the former
*libssh2_scp_send_ex(3)* function.
