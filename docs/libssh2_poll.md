---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_poll
Section: 3
Source: libssh2
See-also:
  - libssh2_poll_channel_read(3)
---

# NAME

libssh2_poll - poll for activity on a socket, channel or listener

# SYNOPSIS

~~~c
#include <libssh2.h>

int
libssh2_poll(LIBSSH2_POLLFD *fds, unsigned int nfds, long timeout);
~~~

# DESCRIPTION

This function is deprecated. Do note use. We encourage users to instead use
the *poll(3)* or *select(3)* functions to check for socket activity or
when specific sockets are ready to get received from or send to.

Poll for activity on a socket, channel, listener, or any combination of these
three types. The calling semantics for this function generally match
*poll(2)* however the structure of fds is somewhat more complex in order
to accommodate the disparate datatypes, POLLFD constants have been namespaced
to avoid platform discrepancies, and revents has additional values defined.

# RETURN VALUE

Number of fds with interesting events.
