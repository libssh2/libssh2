---
c: Copyright (C) Daniel Stenberg
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_knownhost_readfile
Section: 3
Source: libssh2
See-also:
  - libssh2_knownhost_check(3)
  - libssh2_knownhost_free(3)
  - libssh2_knownhost_init(3)
---

# NAME

libssh2_knownhost_readfile - parse a file of known hosts

# SYNOPSIS

~~~c
#include <libssh2.h>

int
libssh2_knownhost_readfile(LIBSSH2_KNOWNHOSTS *hosts,
                           const char *filename, int type);
~~~

# DESCRIPTION

Reads a collection of known hosts from a specified file and adds them to the
collection of known hosts.

*filename* specifies which file to read

*type* specifies what file type it is, and
*LIBSSH2_KNOWNHOST_FILE_OPENSSH* is the only currently supported
format. This file is normally found named ~/.ssh/known_hosts

# RETURN VALUE

Returns a negative value, a regular libssh2 error code for errors, or a
positive number as number of parsed known hosts in the file.

# AVAILABILITY

Added in libssh2 1.2
