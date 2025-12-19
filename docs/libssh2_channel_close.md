---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_channel_close
Section: 3
Source: libssh2
See-also:
  - libssh2_channel_open_ex(3)
  - libssh2_channel_wait_closed(3)
---

# NAME

libssh2_channel_close - close a channel

# SYNOPSIS

~~~c
#include <libssh2.h>

int
libssh2_channel_close(LIBSSH2_CHANNEL *channel);
~~~

# DESCRIPTION

*channel* - active channel stream to set closed status on.

Close an active data channel. In practice this means sending an SSH_MSG_CLOSE
packet to the remote host which serves as instruction that no further data
will be sent to it. The remote host may still send data back until it sends
its own close message in response. To wait for the remote end to close its
connection as well, follow this command with libssh2_channel_wait_closed(3).

# RETURN VALUE

Return 0 on success or negative on failure. It returns
LIBSSH2_ERROR_EAGAIN when it would otherwise block. While
LIBSSH2_ERROR_EAGAIN is a negative number, it is not really a failure per se.

# ERRORS

*LIBSSH2_ERROR_SOCKET_SEND* - Unable to send data on socket.
