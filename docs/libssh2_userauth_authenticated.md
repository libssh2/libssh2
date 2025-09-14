---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_userauth_authenticated
Section: 3
Source: "libssh2
See-also:
  - libssh2_session_init_ex(3)
  - libssh2_session_init_ex(3)
---

# NAME

libssh2_userauth_authenticated - return authentication status

# SYNOPSIS

~~~c
#include <libssh2.h>

int
libssh2_userauth_authenticated(LIBSSH2_SESSION *session);
~~~

# DESCRIPTION

*session* - Session instance as returned by

Indicates whether or not the named session has been successfully authenticated.

# RETURN VALUE

Returns 1 if authenticated and 0 if not.
