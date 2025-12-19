---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_session_supported_algs
Section: 3
Source: libssh2
See-also:
  - libssh2_free(3)
  - libssh2_session_method_pref(3)
  - libssh2_session_methods(3)
---

# NAME

libssh2_session_supported_algs - get list of supported algorithms

# SYNOPSIS

~~~c
#include <libssh2.h>

int
libssh2_session_supported_algs(LIBSSH2_SESSION* session,
                               int method_type,
                               const char*** algs);
~~~

# DESCRIPTION

*session* - An instance of initialized LIBSSH2_SESSION (the function will
use its pointer to the memory allocation function). *method_type* -
Method type. See *libssh2_session_method_pref(3)*. *algs* - Address
of a pointer that will point to an array of returned algorithms

Get a list of supported algorithms for the given *method_type*. The
method_type parameter is equivalent to method_type in
*libssh2_session_method_pref(3)*. If successful, the function will
allocate the appropriate amount of memory. When not needed anymore, it must be
deallocated by calling *libssh2_free(3)*. When this function is
unsuccessful, this must not be done.

In order to get a list of all supported compression algorithms,
libssh2_session_flag(session, LIBSSH2_FLAG_COMPRESS, 1) must be called before
calling this function, otherwise only "none" will be returned.

If successful, the function will allocate and fill the array with supported
algorithms (the same names as defined in RFC 4253). The array is not NULL
terminated.

# EXAMPLE

~~~c
#include "libssh2.h"

const char **algorithms;
int rc, i;
LIBSSH2_SESSION *session;

/* initialize session */
session = libssh2_session_init();
rc = libssh2_session_supported_algs(session,
                                    LIBSSH2_METHOD_CRYPT_CS,
                                    &algorithms);
if(rc > 0) {
    /* the call succeeded, do sth. with the list of algorithms
       (e.g. list them)... */
    printf("Supported symmetric algorithms:\n");
    for(i = 0; i < rc; i++)
        printf("\t%s\n", algorithms[i]);

    /* ... and free the allocated memory when not needed anymore */
    libssh2_free(session, algorithms);
}
else {
    /* call failed, error handling */
}
~~~

# RETURN VALUE

On success, a number of returned algorithms (i.e a positive number will be
returned). In case of a failure, an error code (a negative number, see below)
is returned. 0 should never be returned.

# ERRORS

*LIBSSH2_ERROR_BAD_USE* - Invalid address of algs.

*LIBSSH2_ERROR_METHOD_NOT_SUPPORTED* - Unknown method type.

*LIBSSH2_ERROR_INVAL* - Internal error (normally should not occur).

*LIBSSH2_ERROR_ALLOC* - Allocation of memory failed.

# AVAILABILITY

Added in 1.4.0
