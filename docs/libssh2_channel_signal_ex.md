---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_channel_signal_ex
Section: 3
Source: libssh2
See-also:
  - libssh2_channel_get_exit_signal(3)
  - libssh2_channel_open_ex(3)
---

# NAME

libssh2_channel_signal_ex -- Send a signal to process previously opened on channel.

# SYNOPSIS

~~~c
#include <libssh2.h>

int
libssh2_channel_signal_ex(LIBSSH2_CHANNEL *channel,
                          const char *signame,
                          size_t signame_len)
~~~

# DESCRIPTION

A signal can be delivered to the remote process/service. Some servers or
systems may not implement signals, in which case they will probably ignore this
message.

*channel* - Previously opened channel instance such as returned by libssh2_channel_open_ex(3).

*signame* - The signal name is the same as the signal name constant, without the leading "SIG".

*signame_len* - Length of passed signal name parameter.

There is also a macro *libssh2_channel_signal(channel, signame)* that supplies the strlen of the signame.

# RETURN VALUE

Normal channel error codes.
LIBSSH2_ERROR_EAGAIN when it would block.
