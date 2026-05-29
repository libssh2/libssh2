---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_session_callback_set
Section: 3
Source: libssh2
See-also:
  - libssh2_session_callback_set2(3)
  - libssh2_channel_callback_set(3)
---

# NAME

libssh2_listener_callback_set - set a callback function

# SYNOPSIS

~~~c
#include <libssh2.h>

libssh2_cb_generic *
libssh2_listener_callback_set(LIBSSH2_SESSION *session,
                              int cbtype, libssh2_cb_generic *callback);
~~~

# DESCRIPTION

Sets a custom callback handler for a previously initialized session
object. Callbacks are triggered by the receipt of special packets related to a channel layer. 
To disable a callback, set it to NULL.

# RETURN VALUE

Pointer to previous callback handler. Returns NULL if no prior callback
handler was set or the callback type was unknown.


# CALLBACK TYPES

Symbols defined with LIBSSH2_CALLBACK_LISTENER_ prefix:

## LIBSSH2_CALLBACK_LISTENER_ACCEPT

A remote socket has accepted a connection, this event passes the newly created
channel to the callback.

The prototype of the callback:

~~~c
void listener_accept_callback(LIBSSH2_SESSION *session,    void**session_abstract
                             , LIBSSH2_LISTENER *listener, void **listener_abstract
                             , LIBSSH2_CHANNEL* channel) {
}
~~~

