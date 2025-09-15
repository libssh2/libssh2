---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_channel_open_ex
Section: 3
Source: libssh2
See-also:
  - libssh2_channel_direct_tcpip(3)
  - libssh2_channel_forward_listen(3)
  - libssh2_channel_open_session(3)
  - libssh2_session_init_ex(3)
---

# NAME

libssh2_channel_open_ex - establish a generic session channel

# SYNOPSIS

~~~c
#include <libssh2.h>

LIBSSH2_CHANNEL *
libssh2_channel_open_ex(LIBSSH2_SESSION *session, const char *channel_type,
                        unsigned int channel_type_len,
                        unsigned int window_size,
                        unsigned int packet_size,
                        const char *message, unsigned int message_len);

LIBSSH2_CHANNEL *
libssh2_channel_open_session(session);
~~~

# DESCRIPTION

*session* - Session instance as returned by libssh2_session_init_ex(3)

*channel_type* - Channel type to open. Typically one of session,
direct-tcpip, or tcpip-forward. The SSH2 protocol allowed for additional
types including local, custom channel types.

*channel_type_len* - Length of channel_type

*window_size* - Maximum amount of unacknowledged data remote host is
allowed to send before receiving an SSH_MSG_CHANNEL_WINDOW_ADJUST packet.

*packet_size* - Maximum number of bytes remote host is allowed to send
in a single SSH_MSG_CHANNEL_DATA or SSG_MSG_CHANNEL_EXTENDED_DATA packet.

*message* - Additional data as required by the selected channel_type.

*message_len* - Length of message parameter.

Allocate a new channel for exchanging data with the server. This method is
typically called through its macroized form:
*libssh2_channel_open_session(3)* or via *libssh2_channel_direct_tcpip(3)*
or *libssh2_channel_forward_listen(3)*

# RETURN VALUE

Pointer to a newly allocated LIBSSH2_CHANNEL instance, or NULL on errors.

# ERRORS

*LIBSSH2_ERROR_ALLOC* - An internal memory allocation call failed.

*LIBSSH2_ERROR_SOCKET_SEND* - Unable to send data on socket.

*LIBSSH2_ERROR_CHANNEL_FAILURE* -

*LIBSSH2_ERROR_EAGAIN* - Marked for non-blocking I/O but the call would block.
Add related functions
