---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_session_banner_set
Section: 3
Source: libssh2
See-also:
  - libssh2_session_banner_get(3)
  - libssh2_session_handshake(3)
  - libssh2_session_init_ex(3)
---

# NAME

libssh2_session_banner_set - set the SSH protocol banner for the local client

# SYNOPSIS

~~~c
#include <libssh2.h>

int
libssh2_session_banner_set(LIBSSH2_SESSION *session, const char *banner);
~~~

# DESCRIPTION

*session* - Session instance as returned by libssh2_session_init_ex(3)

*banner* - A pointer to a zero-terminated string holding the user defined
banner

Set the banner that will be sent to the remote host when the SSH session is
started with *libssh2_session_handshake(3)* This is optional; a banner
corresponding to the protocol and libssh2 version will be sent by default.

# RETURN VALUE

Returns 0 on success or negative on failure. It returns LIBSSH2_ERROR_EAGAIN
when it would otherwise block. While LIBSSH2_ERROR_EAGAIN is a negative
number, it is not really a failure per se.

# ERRORS

*LIBSSH2_ERROR_ALLOC* - An internal memory allocation call failed.

# AVAILABILITY

Added in 1.4.0.

Before 1.4.0 this function was known as libssh2_banner_set(3)
