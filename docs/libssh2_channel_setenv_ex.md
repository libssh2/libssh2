---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_channel_setenv_ex
Section: 3
Source: libssh2
See-also:
  - libssh2_channel_open_ex(3)
---

# NAME

libssh2_channel_setenv_ex - set an environment variable on the channel

# SYNOPSIS

~~~c
#include <libssh2.h>

int
libssh2_channel_setenv_ex(LIBSSH2_CHANNEL *channel,
                          char *varname, unsigned int varname_len,
                          const char *value, unsigned int value_len);

int
libssh2_channel_setenv(LIBSSH2_CHANNEL *channel,
                       char *varname, const char *value);
~~~

# DESCRIPTION

*channel* - Previously opened channel instance such as returned by
libssh2_channel_open_ex(3)

*varname* - Name of environment variable to set on the remote
channel instance.

*varname_len* - Length of passed varname parameter.

*value* - Value to set varname to.

*value_len* - Length of value parameter.

Set an environment variable in the remote channel's process space. Note that
this does not make sense for all channel types and may be ignored by the
server despite returning success.

# RETURN VALUE

Return 0 on success or negative on failure. It returns
LIBSSH2_ERROR_EAGAIN when it would otherwise block. While
LIBSSH2_ERROR_EAGAIN is a negative number, it is not really a failure per se.

# ERRORS

*LIBSSH2_ERROR_ALLOC* - An internal memory allocation call failed.

*LIBSSH2_ERROR_SOCKET_SEND* - Unable to send data on socket.

*LIBSSH2_ERROR_CHANNEL_REQUEST_DENIED* -
