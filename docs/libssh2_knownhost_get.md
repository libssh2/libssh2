---
c: Copyright (C) Daniel Stenberg
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_knownhost_get
Section: 3
Source: libssh2
See-also:
  - libssh2_knownhost_add(3)
  - libssh2_knownhost_readfile(3)
  - libssh2_knownhost_writefile(3)
---

# NAME

libssh2_knownhost_get - get a known host off the collection of known hosts

# SYNOPSIS

~~~c
#include <libssh2.h>

int
libssh2_knownhost_get(LIBSSH2_KNOWNHOSTS *hosts,
                      struct libssh2_knownhost **store,
                      struct libssh2_knownhost *prev):
~~~

# DESCRIPTION

*libssh2_knownhost_get(3)* allows an application to iterate over all known
hosts in the collection.

*store* should point to a pointer that gets filled in to point to the
known host data.

*prev* is a pointer to a previous 'struct libssh2_knownhost' as returned
by a previous invoke of this function, or NULL to get the first entry in the
internal collection.

# RETURN VALUE

Returns 0 if everything is fine and information about a host was stored in
the *store* struct.

Returns 1 if it reached the end of hosts.

Returns negative values for error

# AVAILABILITY

Added in libssh2 1.2
