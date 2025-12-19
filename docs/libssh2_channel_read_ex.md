---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_channel_read_ex
Section: 3
Source: libssh2
See-also:
  - libssh2_poll_channel_read(3)
---

# NAME

libssh2_channel_read_ex - read data from a channel stream

# SYNOPSIS

~~~c
#include <libssh2.h>

ssize_t
libssh2_channel_read_ex(LIBSSH2_CHANNEL *channel, int stream_id,
                        char *buf, size_t buflen);

ssize_t
libssh2_channel_read(LIBSSH2_CHANNEL *channel,
                     char *buf, size_t buflen);

ssize_t
libssh2_channel_read_stderr(LIBSSH2_CHANNEL *channel,
                            char *buf, size_t buflen);
~~~

# DESCRIPTION

Attempt to read data from an active channel stream. All channel streams have
one standard I/O substream (stream_id == 0), and may have up to 2^32 extended
data streams as identified by the selected *stream_id*. The SSH2 protocol
currently defines a stream ID of 1 to be the stderr substream.

*channel* - active channel stream to read from.

*stream_id* - substream ID number (e.g. 0 or SSH_EXTENDED_DATA_STDERR)

*buf* - pointer to storage buffer to read data into

*buflen* - size of the buf storage

*libssh2_channel_read(3)* and *libssh2_channel_read_stderr(3)* are
macros.

# RETURN VALUE

Actual number of bytes read or negative on failure. It returns
LIBSSH2_ERROR_EAGAIN when it would otherwise block. While
LIBSSH2_ERROR_EAGAIN is a negative number, it is not really a failure per se.

Note that a return value of zero (0) can in fact be a legitimate value and
only signals that no payload data was read. It is not an error.

# ERRORS

*LIBSSH2_ERROR_SOCKET_SEND* - Unable to send data on socket.

*LIBSSH2_ERROR_CHANNEL_CLOSED* - The channel has been closed.
