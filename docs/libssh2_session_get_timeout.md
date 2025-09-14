---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_session_get_timeout
Section: 3
Source: libssh2
See-also:
  - libssh2_session_set_timeout(3)
---

# NAME

libssh2_session_get_timeout - get the timeout for blocking functions

# SYNOPSIS

~~~c
#include <libssh2.h>

long
libssh2_session_get_timeout(LIBSSH2_SESSION *session);
~~~

# DESCRIPTION

Returns the **timeout** (in milliseconds) for how long a blocking the
libssh2 function calls may wait until they consider the situation an error and
return LIBSSH2_ERROR_TIMEOUT.

By default libssh2 has no timeout (zero) for blocking functions.

# RETURN VALUE

The value of the timeout setting.

# AVAILABILITY

Added in 1.2.9
