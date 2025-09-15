---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_session_method_pref
Section: 3
Source: libssh2
See-also:
  - libssh2_session_handshake(3)
  - libssh2_session_init_ex(3)
---

# NAME

libssh2_session_method_pref - set preferred key exchange method

# SYNOPSIS

~~~c
#include <libssh2.h>

int
libssh2_session_method_pref(LIBSSH2_SESSION *session,
                            int method_type, const char *prefs);
~~~

# DESCRIPTION

*session* - Session instance as returned by libssh2_session_init_ex(3)

*method_type* - One of the Method Type constants.

*prefs* - Coma delimited list of preferred methods to use with
the most preferred listed first and the least preferred listed last.
If a method is listed which is not supported by libssh2 it will be
ignored and not sent to the remote host during protocol negotiation.

Set preferred methods to be negotiated. These
preferences must be set prior to calling libssh2_session_handshake(3)
as they are used during the protocol initiation phase.

# RETURN VALUE

Return 0 on success or negative on failure. It returns
LIBSSH2_ERROR_EAGAIN when it would otherwise block. While
LIBSSH2_ERROR_EAGAIN is a negative number, it is not really a failure per se.

# ERRORS

*LIBSSH2_ERROR_INVAL* - The requested method type was invalid.

*LIBSSH2_ERROR_ALLOC* - An internal memory allocation call failed.

*LIBSSH2_ERROR_METHOD_NOT_SUPPORTED* - The requested method is not supported.
