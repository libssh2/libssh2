---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_channel_set_blocking
Section: 3
Source: libssh2
See-also:
  - libssh2_channel_read_ex(3)
  - libssh2_channel_write_ex(3)
  - libssh2_session_set_blocking(3)
---

# NAME

libssh2_channel_set_blocking - set or clear blocking mode on channel

# SYNOPSIS

~~~c
#include <libssh2.h>

void
libssh2_channel_set_blocking(LIBSSH2_CHANNEL *channel, int blocking);
~~~

# DESCRIPTION

*channel* - channel stream to set or clean blocking status on.

*blocking* - Set to a non-zero value to make the channel block, or zero to
make it non-blocking.

Currently this is a short cut call to libssh2_session_set_blocking(3)
and therefore will affect the session and all channels.

# RETURN VALUE

None
