---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_session_handshake
Section: 3
Source: libssh2
See-also:
  - libssh2_session_free(3)
  - libssh2_session_init_ex(3)
---

# NAME

libssh2_session_handshake - perform the SSH handshake

# SYNOPSIS

~~~c
#include <libssh2.h>

int
libssh2_session_handshake(LIBSSH2_SESSION *session, libssh2_socket_t socket);
~~~

# DESCRIPTION

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

# SECURITY

After a successful handshake, applications should verify the server's host key
before proceeding with authentication. Use libssh2_knownhost_init(3) to create
a known-hosts collection, libssh2_knownhost_readfile(3) to load trusted keys,
and libssh2_knownhost_checkp(3) to verify the server's key. If the check does
not return LIBSSH2_KNOWNHOST_CHECK_MATCH, the connection should be aborted to
prevent man-in-the-middle attacks.

See the **ssh2_exec.c** example in the distribution for a complete
demonstration.

# AVAILABILITY

Added in 1.2.8
