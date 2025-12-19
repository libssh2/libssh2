---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_userauth_banner
Section: 3
Source: libssh2
See-also:
  - libssh2_session_init_ex(3)
  - libssh2_userauth_list(3)
---

# NAME

libssh2_userauth_banner - get the server's userauth banner message

# SYNOPSIS

~~~c
#include <libssh2.h>

int
libssh2_userauth_banner(LIBSSH2_SESSION *session, char **banner);
~~~

# DESCRIPTION

*session* - Session instance as returned by libssh2_session_init_ex(3)

*banner* - Should point to a pointer that gets filled with banner message.

After an authentication has been attempted, such as a
**SSH_USERAUTH_NONE** request sent by *libssh2_userauth_list(3)*
this function can be called to retrieve the userauth banner sent by
the server. If no such banner is sent, or if an authentication has not
yet been attempted, returns **LIBSSH2_ERROR_MISSING_USERAUTH_BANNER**.

# RETURN VALUE

On success returns 0 and an UTF-8 NUL-terminated string is stored in the
*banner*. This string is internally managed by libssh2 and will be
deallocated upon session termination.
On failure returns **LIBSSH2_ERROR_MISSING_USERAUTH_BANNER**.
