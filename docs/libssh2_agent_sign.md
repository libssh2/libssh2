---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_agent_sign
Section: 3
Source: libssh2
See-also:
  - libssh2_agent_get_identity(3)
  - libssh2_agent_init(3)
  - libssh2_agent_userauth(3)
  - libssh2_session_callback_set2(3)
---

# NAME

libssh2_agent_sign - sign data, with the help of ssh-agent

# SYNOPSIS

~~~c
#include <libssh2.h>

int
libssh2_agent_sign(LIBSSH2_AGENT *agent,
                   struct libssh2_agent_publickey *identity,
                   unsigned char **sig,
                   size_t *s_len,
                   const unsigned char *data,
                   size_t d_len,
                   const char *method,
                   unsigned int method_len);
~~~

# DESCRIPTION

*agent* - ssh-agent handle as returned by libssh2_agent_init(3).

*identity* - Public key to authenticate with, as returned by
libssh2_agent_get_identity(3)

*sig* - A pointer to a buffer in which to place the signature. The caller
is responsible for freeing the signature with LIBSSH2_FREE.

*s_len* - A pointer to the length of the sig parameter.

*data* - The data to sign.

*d_len* - The length of the data parameter.

*method* - A buffer indicating the signing method. This should match the
string at the start of identity-\>blob.

*method_len* - The length of the method parameter.

Sign data using an ssh-agent. This function can be used in a callback
registered with libssh2_session_callback_set2(3) using
LIBSSH2_CALLBACK_AUTHAGENT_SIGN to sign an authentication challenge from a
server. However, the client is responsible for implementing the code that calls
this callback in response to a SSH2_AGENTC_SIGN_REQUEST message.

# RETURN VALUE

Returns 0 if succeeded, or a negative value for error.

# AVAILABILITY

Added in libssh2 1.11.0
