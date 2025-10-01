---
c: Copyright (C) Daniel Stenberg
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_knownhost_del
Section: 3
Source: libssh2
See-also:
  - libssh2_knownhost_add(3)
  - libssh2_knownhost_check(3)
  - libssh2_knownhost_free(3)
  - libssh2_knownhost_init(3)
---

# NAME

libssh2_knownhost_del - delete a known host entry

# SYNOPSIS

~~~c
#include <libssh2.h>

int
libssh2_knownhost_del(LIBSSH2_KNOWNHOSTS *hosts,
                      struct libssh2_knownhost *entry);
~~~

# DESCRIPTION

Delete a known host entry from the collection of known hosts.

*entry* is a pointer to a struct that you can extract with
*libssh2_knownhost_check(3)* or *libssh2_knownhost_get(3)*.

# RETURN VALUE

Returns a regular libssh2 error code, where negative values are error codes
and 0 indicates success.

# AVAILABILITY

Added in libssh2 1.2
