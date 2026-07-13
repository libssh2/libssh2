---
c: Copyright (C) Michel Gillet
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_agent_set_backend_to_use
Section: 3
Source: libssh2
See-also:
  - libssh2_agent_get_backend_to_use(3)
  - libssh2_agent_connect(3)
---

# NAME

libssh2_agent_set_backend_to_use - select the ssh-agent backend to use

# SYNOPSIS

~~~c
#include <libssh2.h>

void libssh2_agent_set_backend_to_use(LIBSSH2_AGENT *agent, int idx);
~~~

# DESCRIPTION

*libssh2_agent_set_backend_to_use(3)* sets the preferred backend index for
subsequent calls to *libssh2_agent_connect(3)*. The *idx* value must be a
valid index returned by *libssh2_agent_get_backend_list_size(3)*, or -1 to
allow libssh2 to choose the backend automatically.

# RETURN VALUE

This function does not return a value.

# AVAILABILITY
