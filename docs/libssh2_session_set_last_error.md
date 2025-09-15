---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_session_set_last_error
Section: 3
Source: libssh2
See-also:
  - libssh2_session_init_ex(3)
  - libssh2_session_last_errno(3)
  - libssh2_session_last_error(3)
---

# NAME

libssh2_session_set_last_error - sets the internal error state

# SYNOPSIS

~~~c
#include <libssh2.h>

int
libssh2_session_set_last_error(LIBSSH2_SESSION *session,
                               int errcode, const char *errmsg)
~~~

# DESCRIPTION

*session* - Session instance as returned by libssh2_session_init_ex(3)

*errcode* - One of the error codes as defined in the public
libssh2 header file.

*errmsg* - If not NULL, a copy of the given string is stored
inside the session object as the error message.

This function is provided for high level language wrappers
(i.e. Python or Perl) and other libraries that may extend libssh2 with
additional features while still relying on its error reporting
mechanism.

# RETURN VALUE

Numeric error code corresponding to the the Error Code constants.

# AVAILABILITY

Added in 1.6.1
