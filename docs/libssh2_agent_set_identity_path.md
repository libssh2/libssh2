---
c: Copyright (C) Will Cosgrove
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_agent_set_identity_path
Section: 3
Source: libssh2
See-also:
  - libssh2_agent_get_identity_path(3)
  - libssh2_agent_init(3)
---

# NAME

libssh2_agent_set_identity_path - set an ssh-agent socket path on disk

# SYNOPSIS

~~~c
#include <libssh2.h>

void
libssh2_agent_set_identity_path(LIBSSH2_AGENT *agent, const char *path);
~~~

# DESCRIPTION

Allows a custom agent identity socket path instead of the default SSH_AUTH_SOCK env value

# RETURN VALUE

Returns void

# AVAILABILITY

Added in libssh2 1.9
