---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_free
Section: 3
Source: libssh2
See-also:
  - libssh2_session_init_ex(3)
---

# NAME

libssh2_free - deallocate libssh2 memory

# SYNOPSIS

~~~c
#include <libssh2.h>

void
libssh2_free(LIBSSH2_SESSION *session, void *ptr);
~~~

# DESCRIPTION

Deallocate memory allocated by earlier call to libssh2 functions. It
uses the memory allocation callbacks provided by the application, if any.
Otherwise, this will call free().

This function is mostly useful under Windows when libssh2 is linked to
one run-time library and the application to another.

# AVAILABILITY

Added in libssh2 1.2.8
