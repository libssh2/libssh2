---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_session_startup
Section: 3
Source: libssh2
See-also:
  - libssh2_session_free(3)
  - libssh2_session_init_ex(3)
---

# NAME

libssh2_session_startup - begin transport layer

# SYNOPSIS

~~~c
#include <libssh2.h>

int
libssh2_session_startup(LIBSSH2_SESSION *session, int socket);
~~~

# DESCRIPTION

Starting in libssh2 version 1.2.8 this function is considered deprecated. Use
*libssh2_session_handshake(3)* instead.

*session* - Session instance as returned by libssh2_session_init_ex(3)

*socket* - Connected socket descriptor. Typically a TCP connection
though the protocol allows for any reliable transport and the library will
attempt to use any berkeley socket.

Begin transport layer protocol negotiation with the connected host.

# RETURN VALUE

Returns 0 on success, negative on failure.

# ERRORS

*LIBSSH2_ERROR_SOCKET_NONE* - The socket is invalid.

*LIBSSH2_ERROR_BANNER_SEND* - Unable to send banner to remote host.

*LIBSSH2_ERROR_KEX_FAILURE* - Encryption key exchange with the remote
host failed.

*LIBSSH2_ERROR_SOCKET_SEND* - Unable to send data on socket.

*LIBSSH2_ERROR_SOCKET_DISCONNECT* - The socket was disconnected.

*LIBSSH2_ERROR_PROTO* - An invalid SSH protocol response was received on
the socket.

*LIBSSH2_ERROR_EAGAIN* - Marked for non-blocking I/O but the call would block.
