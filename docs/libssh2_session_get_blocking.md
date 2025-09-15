---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_session_get_blocking
Section: 3
Source: libssh2
See-also:
  - libssh2_session_set_blocking(3)
---

# NAME

libssh2_session_get_blocking - evaluate blocking mode on session

# SYNOPSIS

~~~c
#include <libssh2.h>

int
libssh2_session_get_blocking(LIBSSH2_SESSION *session);
~~~

# DESCRIPTION

Returns 0 if the state of the session has previously be set to non-blocking
and it returns 1 if the state was set to blocking.

# RETURN VALUE

See description.
