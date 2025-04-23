/* Copyright (C) Viktor Szakats
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "libssh2.h"
#include <stdio.h>

int main(int argc, char **argv)
{
    const char *crypto_str;

    (void)argc;

    switch(libssh2_crypto_engine()) {
    case libssh2_gcrypt:
        crypto_str = "libgcrypt";
        break;
    case libssh2_mbedtls:
        crypto_str = "mbedTLS";
        break;
    case libssh2_openssl:
        crypto_str = "openssl compatible";
        break;
    case libssh2_os400qc3:
        crypto_str = "OS400QC3";
        break;
    case libssh2_wincng:
        crypto_str = "WinCNG";
        break;
    default:
        crypto_str = "(unrecognized)";
    }

    printf("libssh2 test: |%s|%s|%s|\n", argv[0],
                                         libssh2_version(0), crypto_str);

    return 0;
}
