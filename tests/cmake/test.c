/* Copyright (C) Viktor Szakats
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "libssh2.h"
#include <stdio.h>

int main(int argc, char **argv)
{
    (void)argc;

    puts("libssh2 test:");
    puts(argv[0]);
    puts(libssh2_version(0));
    puts(libssh2_build_options());
    puts("---");

    return 0;
}
