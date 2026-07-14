---
c: Copyright (C) Michel Gillet
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_agent_get_backend_list_size
Section: 3
Source: libssh2
See-also:
  - libssh2_agent_get_backend_name(3)
  - libssh2_agent_connect(3)
---

# NAME

libssh2_agent_get_backend_list_size - get the number of available ssh-agent backends

# SYNOPSIS

~~~c
#include <libssh2.h>

int libssh2_agent_get_backend_list_size(void);
~~~

# DESCRIPTION

*libssh2_agent_get_backend_list_size(3)* returns the number of ssh-agent
backend implementations exposed by libssh2. This value can be used together
with *libssh2_agent_get_backend_name(3)* to iterate over the supported
backends.

# RETURN VALUE

Returns the number of supported backends, or a negative value on error.

# AVAILABILITY
