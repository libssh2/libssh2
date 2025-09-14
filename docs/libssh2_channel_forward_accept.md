---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_channel_forward_accept
Section: 3
Source: libssh2
See-also:
  - libssh2_channel_forward_listen_ex(3)
---

# NAME

libssh2_channel_forward_accept - accept a queued connection

# SYNOPSIS

~~~c
#include <libssh2.h>

LIBSSH2_CHANNEL *
libssh2_channel_forward_accept(LIBSSH2_LISTENER *listener);
~~~

# DESCRIPTION

*listener* is a forwarding listener instance as returned by
**libssh2_channel_forward_listen_ex(3)**.

# RETURN VALUE

A newly allocated channel instance or NULL on failure.

# ERRORS

When this function returns NULL use *libssh2_session_last_errno(3)* to
extract the error code. If that code is *LIBSSH2_ERROR_EAGAIN*, the
session is set to do non-blocking I/O but the call would block.
