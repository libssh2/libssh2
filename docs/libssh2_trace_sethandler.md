---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_trace_sethandler
Section: 3
Source: libssh2
See-also:
---

# NAME

libssh2_trace_sethandler - set a trace output handler

# SYNOPSIS

~~~c
#include <libssh2.h>

typedef void (*libssh2_trace_handler_func)(LIBSSH2_SESSION *session,
                                           void *context,
                                           const char *data,
                                           size_t length);

int
libssh2_trace_sethandler(LIBSSH2_SESSION *session,
                         void *context,
                         libssh2_trace_handler_func callback);
~~~

# DESCRIPTION

libssh2_trace_sethandler installs a trace output handler for your application.
By default, when tracing has been switched on via a call to libssh2_trace(),
all output is written to stderr. By calling this method and passing a
function pointer that matches the libssh2_trace_handler_func prototype,
libssh2 will call back as it generates trace output. This can be used to
capture the trace output and put it into a log file or diagnostic window.
This function has no effect unless libssh2 was built to support this option,
and a typical "release build" might not.

**context** can be used to pass arbitrary user defined data back into the callback when invoked.

# AVAILABILITY

Added in libssh2 version 1.2.3
