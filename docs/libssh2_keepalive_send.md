---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_keepalive_send
Section: 3
Source: libssh2
See-also:
  - libssh2_keepalive_config(3)
---

# NAME

libssh2_keepalive_send - short function description

# SYNOPSIS

~~~c
#include <libssh2.h>

int
libssh2_keepalive_send(LIBSSH2_SESSION *session,
                       int *seconds_to_next);
~~~

# DESCRIPTION

Send a keepalive message if needed. **seconds_to_next** indicates how many
seconds you can sleep after this call before you need to call it again.

# RETURN VALUE

Returns 0 on success, or LIBSSH2_ERROR_SOCKET_SEND on I/O errors.

# AVAILABILITY

Added in libssh2 1.2.5
