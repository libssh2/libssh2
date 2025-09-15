---
c: Copyright (C) Daiki Ueno
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_agent_list_identities
Section: 3
Source: libssh2
See-also:
  - libssh2_agent_connect(3)
  - libssh2_agent_get_identity(3)
---

# NAME

libssh2_agent_list_identities - request an ssh-agent to list of public keys.

# SYNOPSIS

~~~c
#include <libssh2.h>

int
libssh2_agent_list_identities(LIBSSH2_AGENT *agent);
~~~

# DESCRIPTION

Request an ssh-agent to list of public keys, and stores them in the
internal collection of the handle. Call *libssh2_agent_get_identity(3)*
to get a public key off the collection.

# RETURN VALUE

Returns 0 if succeeded, or a negative value for error.

# AVAILABILITY

Added in libssh2 1.2
