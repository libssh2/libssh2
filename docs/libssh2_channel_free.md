---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_channel_free
Section: 3
Source: libssh2
See-also:
  - libssh2_channel_close(3)
---

# NAME

libssh2_channel_free - free all resources associated with a channel

# SYNOPSIS

~~~c
#include <libssh2.h>

int
libssh2_channel_free(LIBSSH2_CHANNEL *channel);
~~~

# DESCRIPTION

*channel* - Channel stream to free.

Release all resources associated with a channel stream. If the channel has
not yet been closed with libssh2_channel_close(3) it will be called
automatically so that the remote end may know that it can safely free its
own resources.

# RETURN VALUE

Return 0 on success or negative on failure. It returns
LIBSSH2_ERROR_EAGAIN when it would otherwise block. While
LIBSSH2_ERROR_EAGAIN is a negative number, it is not really a failure per se.
