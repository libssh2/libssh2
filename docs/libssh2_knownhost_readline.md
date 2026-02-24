---
c: Copyright (C) Daniel Stenberg
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_knownhost_readline
Section: 3
Source: libssh2
See-also:
  - libssh2_knownhost_get(3)
  - libssh2_knownhost_readfile(3)
  - libssh2_knownhost_writeline(3)
---

# NAME

libssh2_knownhost_readline - read a known host line

# SYNOPSIS

~~~c
#include <libssh2.h>

int
libssh2_knownhost_readline(LIBSSH2_KNOWNHOSTS *hosts,
                           const char *line, size_t len, int type):
~~~

# DESCRIPTION

Tell libssh2 to read a buffer as it if is a line from a known hosts file.

*line* points to the start of the line

*len* is the length of the line in bytes

*type* specifies what file type it is, and
*LIBSSH2_KNOWNHOST_FILE_OPENSSH* is the only currently supported
format. This file is normally found named ~/.ssh/known_hosts

# RETURN VALUE

Returns a regular libssh2 error code, where negative values are error codes
and 0 indicates success.

# AVAILABILITY

Added in libssh2 1.2
