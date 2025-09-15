---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_session_callback_set
Section: 3
Source: libssh2
See-also:
  - libssh2_agent_sign(3)
  - libssh2_session_callback_set2(3)
  - libssh2_session_init_ex(3)
---

# NAME

libssh2_session_callback_set - set a callback function

# SYNOPSIS

~~~c
#include <libssh2.h>

void *
libssh2_session_callback_set(LIBSSH2_SESSION *session,
                             int cbtype, void *callback);
~~~

# DESCRIPTION

This function is **DEPRECATED** in 1.11.1. Use the
*libssh2_session_callback_set2(3)* function instead!

This implementation is expecting and returning a data pointer for callback
functions.

For the details about the replacement function, see libssh2_session_callback_set2(3)
which is expecting and returning a function pointer.

# RETURN VALUE

Pointer to previous callback handler. Returns NULL if no prior callback
handler was set or the callback type was unknown.
