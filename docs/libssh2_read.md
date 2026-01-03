---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_read
Section: 3
Source: libssh2
See-also:
---

# NAME

libssh2_read - trigger any activity on a session.

# SYNOPSIS

~~~c
#include <libssh2.h>

int
libssh2_read(LIBSSH2_SESSION *session);
~~~

# DESCRIPTION

Collect a packet into the input queue.  When using event callbacks, this will trigger 
any queued events, possibly just
stepping internal states, which create more data to write at the libssh2 level, beyond
what the application layer cares about.

# RETURN VALUE

Returns packet type added to input queue (0 if nothing added), or a
negative error number.

