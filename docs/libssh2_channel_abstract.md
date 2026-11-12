---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_channel_close
Section: 3
Source: libssh2
See-also:
---

# NAME

libssh2_channel_abstract - get the current abstract value associated with a channel.

# SYNOPSIS

~~~c
#include <libssh2.h>

void **
libssh2_channel_abstract(LIBSSH2_CHANNEL *channel);
~~~

# DESCRIPTION

*channel* - active channel stream to get a reference of the abstract value.

# RETURN VALUE

Returns a reference address of the abstract of a channel; allowing potentially
overriding the existing value with a new value.
