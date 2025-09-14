---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_channel_forward_listen_ex
Section: 3
Source: libssh2
See-also:
  - libssh2_channel_forward_accept(3)
---

# NAME

libssh2_channel_forward_listen_ex - listen to inbound connections

# SYNOPSIS

~~~c
#include <libssh2.h>

LIBSSH2_LISTENER *
libssh2_channel_forward_listen_ex(LIBSSH2_SESSION *session,
                                  char *host, int port,
                                  int *bound_port, int queue_maxsize);

LIBSSH2_LISTENER *
libssh2_channel_forward_listen(LIBSSH2_SESSION *session, int port);
~~~

# DESCRIPTION

Instruct the remote SSH server to begin listening for inbound TCP/IP
connections. New connections will be queued by the library until accepted by
*libssh2_channel_forward_accept(3)*.

*session* - instance as returned by libssh2_session_init().

*host* - specific address to bind to on the remote host. Binding to
0.0.0.0 (default when NULL is passed) will bind to all available addresses.

*port* - port to bind to on the remote host. When 0 is passed, the remote
host will select the first available dynamic port.

*bound_port* - Populated with the actual port bound on the remote
host. Useful when requesting dynamic port numbers.

*queue_maxsize* - Maximum number of pending connections to queue before
rejecting further attempts.

*libssh2_channel_forward_listen(3)* is a macro.

# RETURN VALUE

A newly allocated LIBSSH2_LISTENER instance or NULL on failure.

# ERRORS

*LIBSSH2_ERROR_ALLOC* - An internal memory allocation call failed.

*LIBSSH2_ERROR_SOCKET_SEND* - Unable to send data on socket.

*LIBSSH2_ERROR_PROTO* - An invalid SSH protocol response was received on the socket.

*LIBSSH2_ERROR_REQUEST_DENIED* - The remote server refused the request.

*LIBSSH2_ERROR_EAGAIN* - Marked for non-blocking I/O but the call would block.
