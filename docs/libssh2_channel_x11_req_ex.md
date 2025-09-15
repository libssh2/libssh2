---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_channel_x11_req_ex
Section: 3
Source: libssh2
See-also:
  - libssh2_channel_open_ex(3)
  - libssh2_session_callback_set2(3)
---

# NAME

libssh2_channel_x11_req_ex - request an X11 forwarding channel

# SYNOPSIS

~~~c
#include <libssh2.h>

int
libssh2_channel_x11_req_ex(LIBSSH2_CHANNEL *channel, int single_connection,
                           const char *auth_proto, const char *auth_cookie,
                           int screen_number);

int
libssh2_channel_x11_req(LIBSSH2_CHANNEL *channel,
                        int screen_number);
~~~

# DESCRIPTION

*channel* - Previously opened channel instance such as returned by
libssh2_channel_open_ex(3).

*single_connection* - non-zero to only forward a single connection.

*auth_proto* - X11 authentication protocol to use

*auth_cookie* - the cookie (hexadecimal encoded).

*screen_number* - the XLL screen to forward

Request an X11 forwarding on *channel*. To use X11 forwarding,
libssh2_session_callback_set2(3)
must first be called to set **LIBSSH2_CALLBACK_X11**. This callback will be
invoked when the remote host accepts the X11 forwarding.

# RETURN VALUE

Return 0 on success or negative on failure. It returns
LIBSSH2_ERROR_EAGAIN when it would otherwise block. While
LIBSSH2_ERROR_EAGAIN is a negative number, it is not really a failure per se.

# ERRORS

*LIBSSH2_ERROR_ALLOC* - An internal memory allocation call failed.

*LIBSSH2_ERROR_SOCKET_SEND* - Unable to send data on socket.

*LIBSSH2_ERROR_CHANNEL_REQUEST_DENIED* -
