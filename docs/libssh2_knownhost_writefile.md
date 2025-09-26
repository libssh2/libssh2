---
c: Copyright (C) Daniel Stenberg
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_knownhost_writefile
Section: 3
Source: libssh2
See-also:
  - libssh2_knownhost_add(3)
  - libssh2_knownhost_readfile(3)
---

# NAME

libssh2_knownhost_writefile - write a collection of known hosts to a file

# SYNOPSIS

~~~c
#include <libssh2.h>

int
libssh2_knownhost_writefile(LIBSSH2_KNOWNHOSTS *hosts,
                            const char *filename, int type);
~~~

# DESCRIPTION

Writes all the known hosts to the specified file using the specified file
format.

*filename* specifies what filename to create

*type* specifies what file type it is, and
*LIBSSH2_KNOWNHOST_FILE_OPENSSH* is the only currently supported
format.

# RETURN VALUE

Returns a regular libssh2 error code, where negative values are error codes
and 0 indicates success.

# AVAILABILITY

Added in libssh2 1.2
