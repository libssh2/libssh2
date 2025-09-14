---
c: Copyright (C) Daniel Stenberg
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_knownhost_init
Section: 3
Source: libssh2
See-also:
  - libssh2_knownhost_add(3)
  - libssh2_knownhost_check(3)
  - libssh2_knownhost_free(3)
---

# NAME

libssh2_knownhost_init - init a collection of known hosts

# SYNOPSIS

~~~c
#include <libssh2.h>

LIBSSH2_KNOWNHOSTS *
libssh2_knownhost_init(LIBSSH2_SESSION *session);
~~~

# DESCRIPTION

Init a collection of known hosts for this session. Returns the handle to an
internal representation of a known host collection.

Call **libssh2_knownhost_free(3)** to free the collection again after you are
doing using it.

# RETURN VALUE

Returns a handle pointer or NULL if something went wrong. The returned handle
is used as input to all other known host related functions libssh2 provides.

# AVAILABILITY

Added in libssh2 1.2
