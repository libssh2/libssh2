---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_channel_request_pty_ex
Section: 3
Source: libssh2
See-also:
  - libssh2_channel_open_ex(3)
---

# NAME

libssh2_channel_request_pty_ex - short function description

# SYNOPSIS

~~~c
#include <libssh2.h>

int
libssh2_channel_request_pty_ex(LIBSSH2_CHANNEL *channel, const char *term,
                               unsigned int term_len,
                               const char *modes, unsigned int modes_len,
                               int width, int height,
                               int width_px, int height_px);

int
libssh2_channel_request_pty(LIBSSH2_CHANNEL *channel, const char *term);
~~~

# DESCRIPTION

*channel* - Previously opened channel instance such as returned by
libssh2_channel_open_ex(3)

*term* - Terminal emulation (e.g. vt102, ansi, etc...)

*term_len* - Length of term parameter

*modes* - Terminal mode modifier values

*modes_len* - Length of modes parameter.

*width* - Width of pty in characters

*height* - Height of pty in characters

*width_px* - Width of pty in pixels

*height_px* - Height of pty in pixels

Request a PTY on an established channel. Note that this does not make sense
for all channel types and may be ignored by the server despite returning
success.

# RETURN VALUE

Return 0 on success or negative on failure. It returns
LIBSSH2_ERROR_EAGAIN when it would otherwise block. While
LIBSSH2_ERROR_EAGAIN is a negative number, it is not really a failure per se.

# ERRORS

*LIBSSH2_ERROR_ALLOC* - An internal memory allocation call failed.

*LIBSSH2_ERROR_SOCKET_SEND* - Unable to send data on socket.

*LIBSSH2_ERROR_CHANNEL_REQUEST_DENIED* -
