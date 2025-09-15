---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_channel_flush_ex
Section: 3
Source: libssh2
See-also:
---

# NAME

libssh2_channel_flush_ex - flush a channel

# SYNOPSIS

~~~c
#include <libssh2.h>

int
libssh2_channel_flush_ex(LIBSSH2_CHANNEL *channel, int streamid);

int
libssh2_channel_flush(LIBSSH2_CHANNEL *channel);

int
libssh2_channel_flush_stderr(LIBSSH2_CHANNEL *channel);
~~~

# DESCRIPTION

*channel* - Active channel stream to flush.

*streamid* - Specific substream number to flush. Groups of substreams may
be flushed by passing on of the following Constants.

**LIBSSH2_CHANNEL_FLUSH_EXTENDED_DATA**: Flush all extended data substreams

**LIBSSH2_CHANNEL_FLUSH_ALL**: Flush all substreams

Flush the read buffer for a given channel instance. Individual substreams may
be flushed by number or using one of the provided macros.

# RETURN VALUE

Return the number of bytes flushed or negative on failure.
It returns LIBSSH2_ERROR_EAGAIN when it would otherwise block. While
LIBSSH2_ERROR_EAGAIN is a negative number, it is not really a failure per se.
