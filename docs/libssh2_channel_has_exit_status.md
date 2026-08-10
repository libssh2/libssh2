---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_channel_has_exit_status
Section: 3
Source: libssh2
See-also:
  - libssh2_channel_get_exit_status(3)
---

# NAME

libssh2_channel_has_exit_status - check if an exit status arrived

# SYNOPSIS

~~~c
#include <libssh2.h>

int libssh2_channel_has_exit_status(LIBSSH2_CHANNEL *channel);
~~~

# DESCRIPTION

*channel* - Closed channel stream to query.

Report whether the remote host sent an `exit-status` request for the named
channel. libssh2_channel_get_exit_status(3) returns 0 both for a real exit
status of 0 and for a channel that never received the request, so it cannot
tell the two apart on its own. A server may close a channel without sending
the request, for example when OpenSSH enforces `ChannelTimeout`, and the
command then keeps running on the remote host.

# RETURN VALUE

Returns 1 if an `exit-status` request was received for the channel,
otherwise 0. Also returns 0 when *channel* is NULL.

# EXAMPLE

~~~c
if(libssh2_channel_close(channel) == 0 &&
   libssh2_channel_has_exit_status(channel))
    exitcode = libssh2_channel_get_exit_status(channel);
~~~

# AVAILABILITY

Added in libssh2 1.12.0
