---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_channel_close
Section: 3
Source: libssh2
See-also:
---

# NAME

libssh2_listener_abstract - get the current abstract value associated with a listener.

# SYNOPSIS

~~~c
#include <libssh2.h>

void**
libssh2_listener_abstract(LIBSSH2_LISTENER *listener);
~~~

# DESCRIPTION

*listener* - active remote socket listener to get a reference of the abstract value.


# RETURN VALUE

Returns a reference address of the abstract of a listener; allowing potentially 
overriding the existing value with a new value.

