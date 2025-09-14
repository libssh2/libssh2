---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_session_disconnect_ex
Section: 3
Source: libssh2
See-also:
  - libssh2_session_disconnect(3)
  - libssh2_session_disconnect_ex(3)
  - libssh2_session_init_ex(3)
---

# NAME

libssh2_session_disconnect_ex - terminate transport layer

# SYNOPSIS

~~~c
#include <libssh2.h>

int
libssh2_session_disconnect_ex(LIBSSH2_SESSION *session, int reason,
                              const char *description,
                              const char *lang);

int
libssh2_session_disconnect(LIBSSH2_SESSION *session,
                           const char *description);
~~~

# DESCRIPTION

*session* - Session instance as returned by libssh2_session_init_ex(3)

*reason* - One of the Disconnect Reason constants.

*description* - Human readable reason for disconnection.

*lang* - Localization string describing the language/encoding of the description provided.

Send a disconnect message to the remote host associated with *session*,
along with a *reason* symbol and a verbose *description*.

As a convenience, the macro libssh2_session_disconnect(3)
is provided. It calls libssh2_session_disconnect_ex(3)
with *reason* set to SSH_DISCONNECT_BY_APPLICATION
and *lang* set to an empty string.

# RETURN VALUE

Return 0 on success or negative on failure. It returns
LIBSSH2_ERROR_EAGAIN when it would otherwise block. While
LIBSSH2_ERROR_EAGAIN is a negative number, it is not really a failure per se.
