---
c: Copyright (C) Daiki Ueno
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_agent_disconnect
Section: 3
Source: libssh2
See-also:
  - libssh2_agent_connect(3)
  - libssh2_agent_free(3)
---

# NAME

libssh2_agent_disconnect - close a connection to an ssh-agent

# SYNOPSIS

~~~c
#include <libssh2.h>

int
libssh2_agent_disconnect(LIBSSH2_AGENT *agent);
~~~

# DESCRIPTION

Close a connection to an ssh-agent.

# RETURN VALUE

Returns 0 if succeeded, or a negative value for error.

# AVAILABILITY

Added in libssh2 1.2
