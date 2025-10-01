---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_userauth_keyboard_interactive_ex
Section: 3
Source: libssh2
See-also:
  - libssh2_session_init_ex(3)
---

# NAME

libssh2_userauth_keyboard_interactive_ex - authenticate a session using
keyboard-interactive authentication

# SYNOPSIS

~~~c
#include <libssh2.h>

int
libssh2_userauth_keyboard_interactive_ex(LIBSSH2_SESSION *session,
                                         const char *username,
                                         unsigned int username_len,
                   LIBSSH2_USERAUTH_KBDINT_RESPONSE_FUNC(*response_callback));
~~~

# DESCRIPTION

*session* - Session instance as returned by
*libssh2_session_init_ex(3)*.

*username* - Name of user to attempt keyboard-interactive authentication
for.

*username_len* - Length of username parameter.

*response_callback* - As authentication proceeds, the host issues several
(1 or more) challenges and requires responses. This callback will be called at
this moment. The callback is responsible to obtain responses for the
challenges, fill the provided data structure and then return
control. Responses will be sent to the host. String values will be free(3)ed
by the library. The callback prototype must match this:

~~~c
void response(const char *name,
              int name_len, const char *instruction,
              int instruction_len,
              int num_prompts,
              const LIBSSH2_USERAUTH_KBDINT_PROMPT *prompts,
              LIBSSH2_USERAUTH_KBDINT_RESPONSE *responses,
              void **abstract);
~~~

Attempts keyboard-interactive (challenge/response) authentication.

Note that many SSH servers will always issue a single "password" challenge,
requesting actual password as response, but it is not required by the
protocol, and various authentication schemes, such as smartcard authentication
may use keyboard-interactive authentication type too.

# RETURN VALUE

Return 0 on success or negative on failure. It returns LIBSSH2_ERROR_EAGAIN
when it would otherwise block. While LIBSSH2_ERROR_EAGAIN is a negative
number, it is not really a failure per se.

# ERRORS

*LIBSSH2_ERROR_ALLOC* - An internal memory allocation call failed.

*LIBSSH2_ERROR_SOCKET_SEND* - Unable to send data on socket.

*LIBSSH2_ERROR_AUTHENTICATION_FAILED* - failed, invalid username/password
or public/private key.
