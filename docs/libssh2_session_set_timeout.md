---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_session_set_timeout
Section: 3
Source: libssh2
See-also:
  - libssh2_session_get_timeout(3)
---

# NAME

libssh2_session_set_timeout - set timeout for blocking functions

# SYNOPSIS

~~~c
#include <libssh2.h>

void libssh2_session_set_timeout(LIBSSH2_SESSION *session, long timeout_ms);
~~~

# DESCRIPTION

Set the **timeout_ms** in milliseconds for how long a blocking libssh2 function
call may wait before it considers the situation an error and returns
LIBSSH2_ERROR_TIMEOUT.

By default or if you set the timeout to zero, libssh2 has no timeout for
blocking functions.

# RETURN VALUE

Nothing

# AVAILABILITY

Added in 1.2.9
