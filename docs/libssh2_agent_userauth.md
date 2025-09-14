---
c: Copyright (C) Daiki Ueno
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_agent_userauth
Section: 3
Source: libssh2
See-also:
  - libssh2_agent_get_identity(3)
  - libssh2_agent_init(3)
  - libssh2_agent_sign(3)
---

# NAME

libssh2_agent_userauth - authenticate a session with a public key, with the help of ssh-agent

# SYNOPSIS

~~~c
#include <libssh2.h>

int
libssh2_agent_userauth(LIBSSH2_AGENT *agent,
                       const char *username,
                       struct libssh2_agent_publickey *identity);
~~~

# DESCRIPTION

*agent* - ssh-agent handle as returned by libssh2_agent_init(3)

*username* - Remote user name to authenticate as.

*identity* - Public key to authenticate with, as returned by
libssh2_agent_get_identity(3)

Attempt public key authentication with the help of ssh-agent.

# RETURN VALUE

Returns 0 if succeeded, or a negative value for error.

# AVAILABILITY

Added in libssh2 1.2
