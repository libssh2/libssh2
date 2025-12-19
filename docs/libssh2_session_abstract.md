---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_session_abstract
Section: 3
Source: libssh2
See-also:
  - libssh2_session_init_ex(3)
---

# NAME

libssh2_session_abstract - return a pointer to a session's abstract pointer

# SYNOPSIS

~~~c
#include <libssh2.h>

void **
libssh2_session_abstract(LIBSSH2_SESSION *session);
~~~

# DESCRIPTION

*session* - Session instance as returned by libssh2_session_init_ex(3)

Return a pointer to where the abstract pointer provided to
**libssh2_session_init_ex(3)** is stored. By providing a doubly
de-referenced pointer, the internal storage of the session instance may be
modified in place.

# RETURN VALUE

A pointer to session internal storage whose contents point to previously
provided abstract data.
