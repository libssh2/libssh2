---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_sftp_init
Section: 3
Source: libssh2
See-also:
  - libssh2_session_init_ex(3)
  - libssh2_sftp_open_ex(3)
  - libssh2_sftp_shutdown(3)
---

# NAME

libssh2_sftp_init - open SFTP channel for the given SSH session.

# SYNOPSIS

~~~c
#include <libssh2.h>
#include <libssh2_sftp.h>

LIBSSH2_SFTP *
libssh2_sftp_init(LIBSSH2_SESSION *session);
~~~

# DESCRIPTION

*session* - Session instance as returned by libssh2_session_init_ex(3)

Open a channel and initialize the SFTP subsystem. Although the SFTP subsystem
operates over the same type of channel as those exported by the Channel API,
the protocol itself implements its own unique binary packet protocol which
must be managed with the libssh2_sftp_*() family of functions. When an SFTP
session is complete, it must be destroyed using the libssh2_sftp_shutdown(3)
function.

# RETURN VALUE

A pointer to the newly allocated SFTP instance or NULL on failure.

# ERRORS

*LIBSSH2_ERROR_ALLOC* - An internal memory allocation call failed.

*LIBSSH2_ERROR_SOCKET_SEND* - Unable to send data on socket.

*LIBSSH2_ERROR_SOCKET_TIMEOUT* -

*LIBSSH2_ERROR_SFTP_PROTOCOL* - An invalid SFTP protocol response was
received on the socket, or an SFTP operation caused an errorcode to be
returned by the server.

*LIBSSH2_ERROR_EAGAIN* - Marked for non-blocking I/O but the call would
block.
