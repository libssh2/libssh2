---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_userauth_list
Section: 3
Source: libssh2
See-also:
  - libssh2_session_init_ex(3)
---

# NAME

libssh2_userauth_list - list supported authentication methods

# SYNOPSIS

~~~c
#include <libssh2.h>

char *
libssh2_userauth_list(LIBSSH2_SESSION *session,
                      const char *username,
                      unsigned int username_len);
~~~

# DESCRIPTION

*session* - Session instance as returned by libssh2_session_init_ex(3)

*username* - Username which will be used while authenticating. Note that
most server implementations do not permit attempting authentication with
different usernames between requests. Therefore this must be the same username
you will use on later userauth calls.

*username_len* - Length of username parameter.

Send a **SSH_USERAUTH_NONE** request to the remote host. Unless the remote
host is configured to accept none as a viable authentication scheme
(unlikely), it will return **SSH_USERAUTH_FAILURE** along with a listing of
what authentication schemes it does support. In the unlikely event that none
authentication succeeds, this method with return NULL. This case may be
distinguished from a failing case by examining
*libssh2_userauth_authenticated(3)*.

# RETURN VALUE

On success a comma delimited list of supported authentication schemes. This
list is internally managed by libssh2. On failure returns NULL.

# ERRORS

*LIBSSH2_ERROR_ALLOC* - An internal memory allocation call failed.

*LIBSSH2_ERROR_SOCKET_SEND* - Unable to send data on socket.

*LIBSSH2_ERROR_EAGAIN* - Marked for non-blocking I/O but the call
