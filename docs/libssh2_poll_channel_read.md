---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_poll_channel_read
Section: 3
Source: libssh2
See-also:
  - libssh2_poll(3)
---

# NAME

libssh2_poll_channel_read - check if data is available

# SYNOPSIS

~~~c
#include <libssh2.h>

int
libssh2_poll_channel_read(LIBSSH2_CHANNEL *channel, int extended);
~~~

# DESCRIPTION

This function is deprecated. Do note use.

*libssh2_poll_channel_read(3)* checks to see if data is available in the
*channel*'s read buffer. No attempt is made with this method to see if
packets are available to be processed. For full polling support, use
*libssh2_poll(3)*.

# RETURN VALUE

Returns 1 when data is available and 0 otherwise.
