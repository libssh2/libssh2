---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_channel_wait_eof
Section: 3
Source: libssh2
See-also:
  - libssh2_channel_eof(3)
  - libssh2_channel_send_eof(3)
---

# NAME

libssh2_channel_wait_eof - wait for the remote to reply to an EOF request

# SYNOPSIS

~~~c
#include <libssh2.h>

int
libssh2_channel_wait_eof(LIBSSH2_CHANNEL *channel);
~~~

# DESCRIPTION

Wait for the remote end to send EOF.

# RETURN VALUE

Return 0 on success or negative on failure. It returns
LIBSSH2_ERROR_EAGAIN when it would otherwise block. While
LIBSSH2_ERROR_EAGAIN is a negative number, it is not really a failure per se.
