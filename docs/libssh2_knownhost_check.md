---
c: Copyright (C) Daniel Stenberg
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_knownhost_check
Section: 3
Source: libssh2
See-also:
  - libssh2_knownhost_add(3)
  - libssh2_knownhost_free(3)
  - libssh2_knownhost_init(3)
---

# NAME

libssh2_knownhost_check - check a host+key against the list of known hosts

# SYNOPSIS

~~~c
#include <libssh2.h>

int
libssh2_knownhost_check(LIBSSH2_KNOWNHOSTS *hosts,
                        const char *host,
                        const char *key, size_t keylen,
                        int typemask,
                        struct libssh2_knownhost **knownhost);
~~~

# DESCRIPTION

Checks a host and its associated key against the collection of known hosts,
and returns info back about the (partially) matched entry.

*host* is a pointer the host name in plain text. The host name can be the
IP numerical address of the host or the full name.

*key* is a pointer to the key for the given host.

*keylen* is the total size in bytes of the key pointed to by the *key*
argument

*typemask* is a bitmask that specifies format and info about the data
passed to this function. Specifically, it details what format the host name is,
what format the key is and what key type it is.

The host name is given as one of the following types:
LIBSSH2_KNOWNHOST_TYPE_PLAIN or LIBSSH2_KNOWNHOST_TYPE_CUSTOM.

The key is encoded using one of the following encodings:
LIBSSH2_KNOWNHOST_KEYENC_RAW or LIBSSH2_KNOWNHOST_KEYENC_BASE64.

*knownhost* if set to non-NULL, it must be a pointer to a 'struct
libssh2_knownhost' pointer that gets filled in to point to info about a known
host that matches or partially matches.

# RETURN VALUE

*libssh2_knownhost_check(3)* returns info about how well the provided
host + key pair matched one of the entries in the list of known hosts.

LIBSSH2_KNOWNHOST_CHECK_FAILURE - something prevented the check to be made

LIBSSH2_KNOWNHOST_CHECK_NOTFOUND - no host match was found

LIBSSH2_KNOWNHOST_CHECK_MATCH - hosts and keys match.

LIBSSH2_KNOWNHOST_CHECK_MISMATCH - host was found, but the keys did not match!

# AVAILABILITY

Added in libssh2 1.2

# EXAMPLE

See the ssh2_exec.c example as provided in the tarball.
