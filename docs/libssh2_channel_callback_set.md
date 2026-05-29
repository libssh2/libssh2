---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_session_callback_set
Section: 3
Source: libssh2
See-also:
  - libssh2_session_callback_set2(3)
  - libssh2_listener_callback_set(3)
---

# NAME

libssh2_channel_callback_set - set a callback function on a channel

# SYNOPSIS

~~~c
#include <libssh2.h>

libssh2_cb_generic *
libssh2_channel_callback_set(LIBSSH2_CHANNEL *channel,
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

Symbols defined with LIBSSH2_CALLBACK_CHANNEL_ prefix:

## LIBSSH2_CALLBACK_CHANNEL_EOF

Channel has process an end of file, the channel's stream is set to end of file before 
this is called.

The prototype of the callback:

```c
void eof_callback(LIBSSH2_SESSION *session, void **session_abstract, 
                  LIBSSH2_CHANNEL *channel, void **channel_abstract) {
}
```

## LIBSSH2_CALLBACK_CHANNEL_CLOSE

Channel has processed a close, and is no longer open by the time this callback is implemented.
Do not use this channel after this event.


The prototype of the callback:

```c
void close_callback(LIBSSH2_SESSION *session, void **session_abstract, 
                    LIBSSH2_CHANNEL *channel, void **channel_abstract) {
}
```


## LIBSSH2_CALLBACK_CHANNEL_DATA

Channel has received a data packet.  This is typically forwarded to the application layer to
handle the channel data received.

Stream is 0 or 1 for `stdout`/`stderr`, but depending on options, 
`stderr` may be merged into `stdout`.

The prototype of the callback:

```c
void channel_data_callback(LIBSSH2_SESSION *session, void **session_abstract,
                           LIBSSH2_CHANNEL *channel, void **channel_abstract
                           int stream,
                           uint8_t const *buffer,
                           size_t length
                           );
```

