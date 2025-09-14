---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_session_get_read_timeout
Section: 3
Source: libssh2
See-also:
  - libssh2_session_set_read_timeout(3)
---

# NAME

libssh2_session_get_read_timeout - get the timeout for packet read functions

# SYNOPSIS

~~~c
#include <libssh2.h>

long
libssh2_session_get_read_timeout(LIBSSH2_SESSION *session);
~~~

# DESCRIPTION

Returns the **timeout** (in seconds) for how long the ssh2 packet receive
function calls may wait until they consider the situation an error and
return LIBSSH2_ERROR_TIMEOUT.

By default the timeout is 60 seconds.

# RETURN VALUE

The value of the timeout setting.

# AVAILABILITY

Added in 1.10.1
