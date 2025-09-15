---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_session_methods
Section: 3
Source: libssh2
See-also:
  - libssh2_session_init_ex(3)
---

# NAME

libssh2_session_methods - return the currently active algorithms

# SYNOPSIS

~~~c
#include <libssh2.h>

const char *
libssh2_session_methods(LIBSSH2_SESSION *session, int method_type);
~~~

# DESCRIPTION

*session* - Session instance as returned by libssh2_session_init_ex(3)

*method_type* - one of the method type constants: LIBSSH2_METHOD_KEX,
LIBSSH2_METHOD_HOSTKEY, LIBSSH2_METHOD_CRYPT_CS, LIBSSH2_METHOD_CRYPT_SC,
LIBSSH2_METHOD_MAC_CS, LIBSSH2_METHOD_MAC_SC, LIBSSH2_METHOD_COMP_CS,
LIBSSH2_METHOD_COMP_SC, LIBSSH2_METHOD_LANG_CS, LIBSSH2_METHOD_LANG_SC,
LIBSSH2_METHOD_SIGN_ALGO.

Returns the actual method negotiated for a particular transport parameter.

# RETURN VALUE

Negotiated method or NULL if the session has not yet been started.

# ERRORS

*LIBSSH2_ERROR_INVAL* - The requested method type was invalid.

*LIBSSH2_ERROR_METHOD_NONE* - no method has been set
