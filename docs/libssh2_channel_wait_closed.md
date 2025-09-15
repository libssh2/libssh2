---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_channel_wait_closed
Section: 3
Source: libssh2
See-also:
  - libssh2_channel_eof(3)
  - libssh2_channel_send_eof(3)
  - libssh2_channel_wait_eof(3)
---

# NAME

libssh2_channel_wait_closed - wait for the remote to close the channel

# SYNOPSIS

~~~c
#include <libssh2.h>

int
libssh2_channel_wait_closed(LIBSSH2_CHANNEL *channel);
~~~

# DESCRIPTION

Enter a temporary blocking state until the remote host closes the named
channel. Typically sent after *libssh2_channel_close(3)* in order to
examine the exit status.

# RETURN VALUE

Return 0 on success or negative on failure. It returns LIBSSH2_ERROR_EAGAIN
when it would otherwise block. While LIBSSH2_ERROR_EAGAIN is a negative
number, it is not really a failure per se.
