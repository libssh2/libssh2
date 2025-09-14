---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_keepalive_config
Section: 3
Source: libssh2
See-also:
  - libssh2_keepalive_send(3)
---

# NAME

libssh2_keepalive_config - short function description

# SYNOPSIS

~~~c
#include <libssh2.h>

void
libssh2_keepalive_config(LIBSSH2_SESSION *session,
                         int want_reply,
                         unsigned int interval);
~~~

# DESCRIPTION

Set how often keepalive messages should be sent. **want_reply** indicates
whether the keepalive messages should request a response from the server.
**interval** is number of seconds that can pass without any I/O, use 0 (the
default) to disable keepalives. To avoid some busy-loop corner-cases, if you
specify an interval of 1 it will be treated as 2.

Note that non-blocking applications are responsible for sending the keepalive
messages using **libssh2_keepalive_send(3)**.

# RETURN VALUE

Nothing

# AVAILABILITY

Added in libssh2 1.2.5
