---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_trace
Section: 3
Source: libssh2
See-also:
---

# NAME

libssh2_trace - enable debug info from inside libssh2

# SYNOPSIS

~~~c
#include <libssh2.h>

int
libssh2_trace(LIBSSH2_SESSION *session, int bitmask);
~~~

# DESCRIPTION

This is a function present in the library that can be used to get debug info
from within libssh2 when it is running. Helpful when trying to trace or debug
behaviors. Note that this function has no effect unless libssh2 was built to
support tracing! It is usually disabled in release builds.

**bitmask** can be set to the logical OR of none, one or more of these:

## LIBSSH2_TRACE_SOCKET

Socket low-level debugging

## LIBSSH2_TRACE_TRANS

Transport layer debugging

## LIBSSH2_TRACE_KEX

Key exchange debugging

## LIBSSH2_TRACE_AUTH

Authentication debugging

## LIBSSH2_TRACE_CONN

Connection layer debugging

## LIBSSH2_TRACE_SCP

SCP debugging

## LIBSSH2_TRACE_SFTP

SFTP debugging

## LIBSSH2_TRACE_ERROR

Error debugging

## LIBSSH2_TRACE_PUBLICKEY

Public Key debugging

# RETURN VALUE

Currently always 0, no error.
