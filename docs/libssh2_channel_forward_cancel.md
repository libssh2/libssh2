---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_channel_forward_cancel
Section: 3
Source: libssh2
See-also:
  - libssh2_channel_forward_listen_ex(3)
---

# NAME

libssh2_channel_forward_cancel - cancel a forwarded TCP port

# SYNOPSIS

~~~c
#include <libssh2.h>

int
libssh2_channel_forward_cancel(LIBSSH2_LISTENER *listener);
~~~

# DESCRIPTION

*listener* - Forwarding listener instance as returned by
libssh2_channel_forward_listen_ex(3)

Instruct the remote host to stop listening for new connections on a previously
requested host/port.

# RETURN VALUE

Return 0 on success or negative on failure. It returns
LIBSSH2_ERROR_EAGAIN when it would otherwise block. While
LIBSSH2_ERROR_EAGAIN is a negative number, it is not really a failure per se.

# ERRORS

*LIBSSH2_ERROR_ALLOC* - An internal memory allocation call failed.

*LIBSSH2_ERROR_SOCKET_SEND* - Unable to send data on socket.
