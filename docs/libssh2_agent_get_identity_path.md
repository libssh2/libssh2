---
c: Copyright (C) Will Cosgrove
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_agent_get_identity_path
Section: 3
Source: libssh2
See-also:
  - libssh2_agent_init(3)
  - libssh2_agent_set_identity_path(3)
---

# NAME

libssh2_agent_get_identity_path - gets the custom ssh-agent socket path

# SYNOPSIS

~~~c
#include <libssh2.h>

const char *
libssh2_agent_get_identity_path(LIBSSH2_AGENT *agent);
~~~

# DESCRIPTION

Returns the custom agent identity socket path if set using libssh2_agent_set_identity_path()

# RETURN VALUE

Returns the socket path on disk.

# AVAILABILITY

Added in libssh2 1.9
