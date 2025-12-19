---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_session_last_error
Section: 3
Source: libssh2
See-also:
  - libssh2_session_init_ex(3)
  - libssh2_session_last_errno(3)
  - libssh2_session_set_last_error(3)
---

# NAME

libssh2_session_last_error - get the most recent error

# SYNOPSIS

~~~c
#include <libssh2.h>

int
libssh2_session_last_error(LIBSSH2_SESSION *session,
                           char **errmsg, int *errmsg_len, int want_buf);
~~~

# DESCRIPTION

*session* - Session instance as returned by libssh2_session_init_ex(3)

*errmsg* - If not NULL, is populated by reference with the human
readable form of the most recent error message.

*errmsg_len* - If not NULL, is populated by reference with the length
of errmsg. (The string is NUL-terminated, so the length is only useful as
an optimization, to avoid calling strlen.)

*want_buf* - If set to a non-zero value, "ownership" of the errmsg
buffer will be given to the calling scope. If necessary, the errmsg buffer
will be duplicated.

Determine the most recent error condition and its cause.

# RETURN VALUE

Numeric error code corresponding to the the Error Code constants.
