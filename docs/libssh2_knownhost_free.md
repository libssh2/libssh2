---
c: Copyright (C) Daniel Stenberg
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_knownhost_free
Section: 3
Source: libssh2
See-also:
  - libssh2_knownhost_add(3)
  - libssh2_knownhost_check(3)
  - libssh2_knownhost_init(3)
---

# NAME

libssh2_knownhost_free - free a collection of known hosts

# SYNOPSIS

~~~c
#include <libssh2.h>

void
libssh2_knownhost_free(LIBSSH2_KNOWNHOSTS *hosts);
~~~

# DESCRIPTION

Free a collection of known hosts.

# RETURN VALUE

None.

# AVAILABILITY

Added in libssh2 1.2
