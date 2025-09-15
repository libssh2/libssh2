---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_channel_get_exit_status
Section: 3
Source: libssh2
See-also:
---

# NAME

libssh2_channel_get_exit_status - get the remote exit code

# SYNOPSIS

~~~c
#include <libssh2.h>

int
libssh2_channel_get_exit_status(LIBSSH2_CHANNEL* channel)
~~~

# DESCRIPTION

*channel* - Closed channel stream to retrieve exit status from.

Returns the exit code raised by the process running on the remote host at
the other end of the named channel. Note that the exit status may not be
available if the remote end has not yet set its status to closed.

# RETURN VALUE

Returns 0 on failure, otherwise the *Exit Status* reported by remote host
