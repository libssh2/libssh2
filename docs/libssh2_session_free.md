---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_session_free
Section: 3
Source: libssh2
See-also:
  - libssh2_session_disconnect_ex(3)
  - libssh2_session_disconnect_ex(3)
  - libssh2_session_init_ex(3)
---

# NAME

libssh2_session_free - frees resources associated with a session instance

# SYNOPSIS

~~~c
#include <libssh2.h>

int
libssh2_session_free(LIBSSH2_SESSION *session);
~~~

# DESCRIPTION

Frees all resources associated with a session instance. Typically called after
libssh2_session_disconnect_ex(3).

# RETURN VALUE

Return 0 on success or negative on failure. It returns
LIBSSH2_ERROR_EAGAIN when it would otherwise block. While
LIBSSH2_ERROR_EAGAIN is a negative number, it is not really a failure per se.
