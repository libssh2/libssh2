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

void
libssh2_session_set_timeout(LIBSSH2_SESSION *session, long timeout);
~~~

# DESCRIPTION

Set the **timeout** in milliseconds for how long a blocking the libssh2
function calls may wait until they consider the situation an error and return
LIBSSH2_ERROR_TIMEOUT.

By default or if you set the timeout to zero, libssh2 has no timeout for
blocking functions.

# RETURN VALUE

Nothing

# AVAILABILITY

Added in 1.2.9
