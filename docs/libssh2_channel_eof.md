---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_channel_eof
Section: 3
Source: libssh2
See-also:
  - libssh2_channel_close(3)
---

# NAME

libssh2_channel_eof - check a channel's EOF status

# SYNOPSIS

~~~c
#include <libssh2.h>

int
libssh2_channel_eof(LIBSSH2_CHANNEL *channel);
~~~

# DESCRIPTION

*channel* - active channel stream to set closed status on.

Check if the remote host has sent an EOF status for the selected stream.

# RETURN VALUE

Returns 1 if the remote host has sent EOF, otherwise 0. Negative on
failure.
