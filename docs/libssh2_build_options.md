---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_build_options
Section: 3
Source: libssh2
See-also:
  - libssh2_crypto_engine(3)
  - libssh2_version(3)
---

# NAME

libssh2_build_options - return build-time options

# SYNOPSIS

~~~c
#include <libssh2.h>

const char *libssh2_build_options(void);
~~~

# DESCRIPTION

Return the full list of options available at build time, along with their
enabled/disabled statuses.

# RETURN VALUE

A read-only, space-separated list of key:value pairs describing build options.
Options use `on` or `off`, except:

`crypto`, which reports one of these values:
`AWS-LC`, `BoringSSL`, `Libgcrypt`, `LibreSSL`, `mbedTLS`, `OpenSSL`,
`OpenSSL/1.1.1`, `OS400QC3`, `WinCNG`, `wolfSSL`.

`agent`, which is listed for each supported agent backend:
`Pageant` (Windows-specific), `OpenSSH` (Windows-specific), `Unix`.

# EXAMPLE

~~~c
printf("libssh2 build options: %s", libssh2_build_options());
~~~

# AVAILABILITY

Added in libssh2 1.12.0
