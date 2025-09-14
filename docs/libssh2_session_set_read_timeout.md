---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_session_set_read_timeout
Section: 3
Source: libssh2
See-also:
  - libssh2_session_get_read_timeout(3)
---

# NAME

libssh2_session_set_read_timeout - set timeout for packet read functions

# SYNOPSIS

~~~c
#include <libssh2.h>

void
libssh2_session_set_read_timeout(LIBSSH2_SESSION *session, long timeout);
~~~

# DESCRIPTION

Set the **timeout** in seconds for how long libssh2 packet read
function calls may wait until they consider the situation an error and return
LIBSSH2_ERROR_TIMEOUT.

By default or if you set the timeout to zero, the timeout will be set to
60 seconds.

# RETURN VALUE

Nothing

# AVAILABILITY

Added in 1.10.1
