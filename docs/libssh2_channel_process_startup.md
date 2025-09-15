---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_channel_process_startup
Section: 3
Source: libssh2
See-also:
  - libssh2_channel_open_ex(3)
---

# NAME

libssh2_channel_process_startup - request a shell on a channel

# SYNOPSIS

~~~c
#include <libssh2.h>

int
libssh2_channel_process_startup(LIBSSH2_CHANNEL *channel,
                                const char *request,
                                unsigned int request_len,
                                const char *message,
                                unsigned int message_len);
~~~

# DESCRIPTION

*channel* - Active session channel instance.

*request* - Type of process to startup. The SSH2 protocol currently
defines shell, exec, and subsystem as standard process services.

*request_len* - Length of request parameter.

*message* - Request specific message data to include.

*message_len* - Length of message parameter.

Initiate a request on a session type channel such as returned by
libssh2_channel_open_ex(3).

# RETURN VALUE

Return 0 on success or negative on failure. It returns
LIBSSH2_ERROR_EAGAIN when it would otherwise block. While
LIBSSH2_ERROR_EAGAIN is a negative number, it is not really a failure per se.

# ERRORS

*LIBSSH2_ERROR_ALLOC* - An internal memory allocation call failed.

*LIBSSH2_ERROR_SOCKET_SEND* - Unable to send data on socket.

*LIBSSH2_ERROR_CHANNEL_REQUEST_DENIED* -
