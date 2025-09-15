---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_userauth_password_ex
Section: 3
Source: libssh2
See-also:
  - libssh2_session_init_ex(3)
---

# NAME

libssh2_userauth_password_ex - authenticate a session with username and password

# SYNOPSIS

~~~c
#include <libssh2.h>

int
libssh2_userauth_password_ex(LIBSSH2_SESSION *session,
                             const char *username,
                             unsigned int username_len,
                             const char *password,
                             unsigned int password_len,
                           LIBSSH2_PASSWD_CHANGEREQ_FUNC((*passwd_change_cb)));

#define libssh2_userauth_password(session, username, password) \
     libssh2_userauth_password_ex((session), (username), \
                                  strlen(username), \
                                  (password), strlen(password), NULL)
~~~

# DESCRIPTION

*session* - Session instance as returned by libssh2_session_init_ex(3)

*username* - Name of user to attempt plain password authentication for.

*username_len* - Length of username parameter.

*password* - Password to use for authenticating username.

*password_len* - Length of password parameter.

*passwd_change_cb* - If the host accepts authentication but
requests that the password be changed, this callback will be issued.
If no callback is defined, but server required password change,
authentication will fail.

Attempt basic password authentication. Note that many SSH servers
which appear to support ordinary password authentication actually have
it disabled and use Keyboard Interactive authentication (routed via
PAM or another authentication backed) instead.

# RETURN VALUE

Return 0 on success or negative on failure. It returns
LIBSSH2_ERROR_EAGAIN when it would otherwise block. While
LIBSSH2_ERROR_EAGAIN is a negative number, it is not really a failure per se.

# ERRORS

Some of the errors this function may return include:

*LIBSSH2_ERROR_ALLOC* - An internal memory allocation call failed.

*LIBSSH2_ERROR_SOCKET_SEND* - Unable to send data on socket.

*LIBSSH2_ERROR_PASSWORD_EXPIRED* -

*LIBSSH2_ERROR_AUTHENTICATION_FAILED* - failed, invalid username/password
or public/private key.
