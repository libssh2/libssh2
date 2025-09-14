---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_exit
Section: 3
Source: libssh2
See-also:
  - libssh2_init(3)
---

# NAME

libssh2_exit - global library deinitialization

# SYNOPSIS

~~~c
#include <libssh2.h>

void
libssh2_exit(void);
~~~

# DESCRIPTION

Exit the libssh2 functions and frees all memory used internal.

# AVAILABILITY

Added in libssh2 1.2.5
