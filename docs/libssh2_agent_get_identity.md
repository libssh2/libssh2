---
c: Copyright (C) Daiki Ueno
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_agent_get_identity
Section: 3
Source: libssh2
See-also:
  - libssh2_agent_list_identities(3)
  - libssh2_agent_userauth(3)
---

# NAME

libssh2_agent_get_identity - get a public key off the collection of public keys managed by ssh-agent

# SYNOPSIS

~~~c
#include <libssh2.h>

int
libssh2_agent_get_identity(LIBSSH2_AGENT *agent,
                           struct libssh2_agent_publickey **store,
                           struct libssh2_agent_publickey *prev);
~~~

# DESCRIPTION

*libssh2_agent_get_identity(3)* allows an application to iterate
over all public keys in the collection managed by ssh-agent.

*store* should point to a pointer that gets filled in to point to the
public key data.

*prev* is a pointer to a previous 'struct libssh2_agent_publickey'
as returned by a previous invoke of this function, or NULL to get the
first entry in the internal collection.

# RETURN VALUE

Returns 0 if everything is fine and information about a host was stored in
the *store* struct.

Returns 1 if it reached the end of public keys.

Returns negative values for error

# AVAILABILITY

Added in libssh2 1.2
