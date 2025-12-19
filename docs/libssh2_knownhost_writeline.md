---
c: Copyright (C) Daniel Stenberg
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_knownhost_writeline
Section: 3
Source: libssh2
See-also:
  - libssh2_knownhost_get(3)
  - libssh2_knownhost_readline(3)
  - libssh2_knownhost_writefile(3)
---

# NAME

libssh2_knownhost_writeline - convert a known host to a line for storage

# SYNOPSIS

~~~c
#include <libssh2.h>

int
libssh2_knownhost_writeline(LIBSSH2_KNOWNHOSTS *hosts,
                            struct libssh2_knownhost *known,
                            char *buffer, size_t buflen,
                            size_t *outlen,
                            int type);
~~~

# DESCRIPTION

Converts a single known host to a single line of output for storage, using
the 'type' output format.

*known* identifies which particular known host

*buffer* points to an allocated buffer

*buflen* is the size of the *buffer*. See RETURN VALUE about the size.

*outlen* must be a pointer to a size_t variable that will get the output
length of the stored data chunk. The number does not included the trailing
zero!

*type* specifies what file type it is, and
*LIBSSH2_KNOWNHOST_FILE_OPENSSH* is the only currently supported
format.

# RETURN VALUE

Returns a regular libssh2 error code, where negative values are error codes
and 0 indicates success.

If the provided buffer is deemed too small to fit the data libssh2 wants to
store in it, LIBSSH2_ERROR_BUFFER_TOO_SMALL will be returned. The application
is then advised to call the function again with a larger buffer. The
*outlen* size will then hold the requested size.

# AVAILABILITY

Added in libssh2 1.2
