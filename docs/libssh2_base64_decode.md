---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_base64_decode
Section: 3
Source: libssh2
See-also:
---

# NAME

libssh2_base64_decode - decode a base64 encoded string

# SYNOPSIS

~~~c
#include <libssh2.h>

int
libssh2_base64_decode(LIBSSH2_SESSION *session, char **dest,
                      unsigned int *dest_len, const char *src,
                      unsigned int src_len);
~~~

# DESCRIPTION

This function is deemed DEPRECATED in 1.0 and will be removed from libssh2
in a future version. Do not use it!

Decode a base64 chunk and store it into a newly allocated buffer. 'dest_len'
will be set to hold the length of the returned buffer that '*dest' will point
to.

The returned buffer is allocated by this function, but it is not clear how to
free that memory!

# BUGS

The memory that *dest points to is allocated by the malloc function libssh2
uses, but there is no way for an application to free this data in a safe and
reliable way!

# RETURN VALUE

0 if successful, -1 if any error occurred.
