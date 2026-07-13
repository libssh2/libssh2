---
c: Copyright (C) Michel Gillet
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_agent_get_backend_to_use
Section: 3
Source: libssh2
See-also:
  - libssh2_agent_set_backend_to_use(3)
  - libssh2_agent_get_backend_used(3)
---

# NAME

libssh2_agent_get_backend_to_use - get the preferred ssh-agent backend index

# SYNOPSIS

~~~c
#include <libssh2.h>

int libssh2_agent_get_backend_to_use(LIBSSH2_AGENT *agent);
~~~

# DESCRIPTION

*libssh2_agent_get_backend_to_use(3)* returns the backend index that has been
selected for the agent with *libssh2_agent_set_backend_to_use(3)*. A value of
-1 indicates that no specific backend has been selected and libssh2 will try
the available backends in its default order.

# RETURN VALUE

Returns the configured backend index, or -1 if no explicit backend has been
selected.

# AVAILABILITY
