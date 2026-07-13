---
c: Copyright (C) Michel Gillet
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_agent_get_backend_used
Section: 3
Source: libssh2
See-also:
  - libssh2_agent_get_backend_to_use(3)
  - libssh2_agent_connect(3)
---

# NAME

libssh2_agent_get_backend_used - get the ssh-agent backend selected for a connection

# SYNOPSIS

~~~c
#include <libssh2.h>

int libssh2_agent_get_backend_used(LIBSSH2_AGENT *agent);
~~~

# DESCRIPTION

*libssh2_agent_get_backend_used(3)* returns the index of the backend that was
selected when the agent was connected. This is useful after a successful call
to *libssh2_agent_connect(3)* when the application wants to inspect which
backend was actually used.

# RETURN VALUE

Returns the backend index that was used, or -1 if no backend has been
selected yet.

# AVAILABILITY
