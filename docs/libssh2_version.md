---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_version
Section: 3
Source: libssh2
See-also:
---

# NAME

libssh2_version - return the libssh2 version number

# SYNOPSIS

~~~c
#include <libssh2.h>

const char *
libssh2_version(int required_version);
~~~

# DESCRIPTION

If *required_version* is lower than or equal to the version number of the
libssh2 in use, the version number of libssh2 is returned as a pointer to a
zero terminated string.

The *required_version* should be the version number as constructed by the
LIBSSH2_VERSION_NUM define in the libssh2.h public header file, which is a 24
bit number in the 0xMMmmpp format. MM for major, mm for minor and pp for patch
number.

# RETURN VALUE

The version number of libssh2 is returned as a pointer to a zero terminated
string or NULL if the *required_version* is not fulfilled.

# EXAMPLE

To make sure you run with the correct libssh2 version:

~~~c
if(!libssh2_version(LIBSSH2_VERSION_NUM)) {
  fprintf(stderr, \&"Runtime libssh2 version too old.\&");
  return -1;  /* return error */
}
~~~

Unconditionally get the version number:

~~~c
printf(\&"libssh2 version: %s\&", libssh2_version(0));
~~~

# AVAILABILITY

This function was added in libssh2 1.1, in previous versions there way no way
to extract this info in run-time.
