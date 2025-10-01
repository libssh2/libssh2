---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_channel_get_exit_signal
Section: 3
Source: libssh2
See-also:
---

# NAME

libssh2_channel_get_exit_signal - get the remote exit signal

# SYNOPSIS

~~~c
#include <libssh2.h>

int
libssh2_channel_get_exit_signal(LIBSSH2_CHANNEL *channel,
                                char **exitsignal, size_t *exitsignal_len,
                                char **errmsg, size_t *errmsg_len,
                                char **langtag, size_t *langtag_len);
~~~

# DESCRIPTION

*channel* - Closed channel stream to retrieve exit signal from.

*exitsignal* - If not NULL, is populated by reference with the exit signal
(without leading "SIG"). Note that the string is stored in a newly allocated
buffer. If the remote program exited cleanly, the referenced string pointer
will be set to NULL.

*exitsignal_len* - If not NULL, is populated by reference with the length
of exitsignal.

*errmsg* - If not NULL, is populated by reference with the error message
(if provided by remote server, if not it will be set to NULL). Note that the
string is stored in a newly allocated buffer.

*errmsg_len* - If not NULL, is populated by reference with the length of errmsg.

*langtag* - If not NULL, is populated by reference with the language tag
(if provided by remote server, if not it will be set to NULL). Note that the
string is stored in a newly allocated buffer.

*langtag_len* - If not NULL, is populated by reference with the length of langtag.

# RETURN VALUE

Numeric error code corresponding to the the Error Code constants.
