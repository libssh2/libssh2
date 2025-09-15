---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_banner_set
Section: 3
Source: libssh2
See-also:
  - libssh2_session_handshake(3)
  - libssh2_session_init_ex(3)
---

# NAME

libssh2_banner_set - set the SSH protocol banner for the local client

# SYNOPSIS

~~~c
#include <libssh2.h>

int
libssh2_banner_set(LIBSSH2_SESSION *session, const char *banner);
~~~

# DESCRIPTION

This function is **DEPRECATED** in 1.4.0. Use the
*libssh2_session_banner_set(3)* function instead!

*session* - Session instance as returned by libssh2_session_init_ex(3)

*banner* - A pointer to a user defined banner

Set the banner that will be sent to the remote host when the SSH session is
started with libssh2_session_handshake(3)
This is optional; a banner corresponding to the protocol and libssh2 version
will be sent by default.

# RETURN VALUE

Return 0 on success or negative on failure. It returns
LIBSSH2_ERROR_EAGAIN when it would otherwise block. While
LIBSSH2_ERROR_EAGAIN is a negative number, it is not really a failure per se.

# AVAILABILITY

Marked as deprecated since 1.4.0

# ERRORS

*LIBSSH2_ERROR_ALLOC* - An internal memory allocation call failed.
