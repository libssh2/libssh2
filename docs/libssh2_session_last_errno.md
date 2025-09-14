---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_session_last_errno
Section: 3
Source: libssh2
See-also:
  - libssh2_session_init_ex(3)
  - libssh2_session_last_error(3)
  - libssh2_session_set_last_error(3)
---

# NAME

libssh2_session_last_errno - get the most recent error number

# SYNOPSIS

~~~c
#include <libssh2.h>

int
libssh2_session_last_errno(LIBSSH2_SESSION *session);
~~~

# DESCRIPTION

*session* - Session instance as returned by libssh2_session_init_ex(3)

Determine the most recent error condition.

# RETURN VALUE

Numeric error code corresponding to the the Error Code constants.
