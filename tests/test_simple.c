/* Copyright (C) The Written Word, Inc.
 * Copyright (C) Simon Josefsson
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "libssh2_priv.h"

#include <stdio.h>
#include <stdlib.h>

static int test_ssh2_base64_decode(LIBSSH2_SESSION *session)
{
    char *data;
    size_t datalen;
    const char *src = "Zm5vcmQ=";
    int ret;

    ret = ssh2_base64_decode(session, &data, &datalen, src, strlen(src));
    if(ret)
        return ret;

    if(datalen != 5 || strcmp(data, "fnord")) {
        fprintf(stderr, "ssh2_base64_decode() failed (%d, %.*s)\n",
                (int)datalen, (int)datalen, data);
        return 1;
    }

    free(data);

    return 0;
}

static int test_ssh2_dh_is_valid(void)
{
    struct tbn {
        const char *f; const char *p; int expected;
    };
    static const struct tbn tests[] = {
        {  "-1",  "10", -1 },
        {   "2",  "10", -3 },
        {   "9",  "10", -2 },
        {   "1",  "10", -1 },
        {   "0",  "10", -1 },
        {   "9",  "10", -2 },  /* f=9; p=10 => p-2=8, f > 8 */
        {   "6",  "20", -3 },  /* f=6 (0b110); p=20 => p-2=18, and 6 <= 18 */
        {  "27", "100",  0 },  /* f=27 (0b11011); p=100 => p-2=98, and 27 <= 98 */
        { "240", "242",  0 },  /* f=p-2, f=240 (0b11110000); p = f+2 = 242 */
    };

    size_t i;
    int err = 0;

#ifdef LIBSSH2_MBEDTLS
    mbedtls_mpi f, p;
#elif defined(LIBSSH2_OPENSSL) || defined(LIBSSH2_WOLFSSL)
    BIGNUM *f = BN_new(), *p = BN_new();
#endif

    for(i = 0; i < (sizeof(tests) / sizeof(tests[0])); i++) {
        int got;

#ifdef LIBSSH2_MBEDTLS
        mbedtls_mpi_init(&f);
        mbedtls_mpi_init(&p);
        if(mbedtls_mpi_read_string(&f, 10, tests[i].f) ||
           mbedtls_mpi_read_string(&p, 10, tests[i].p)) {
            fprintf(stderr,
                    "ssh2_dh_is_valid/%lu: mbedtls_mpi_read_string() failed\n",
                    (unsigned long)i);
            err++;
            continue;
        }
        got = ssh2_dh_is_valid(&f, &p);
#elif defined(LIBSSH2_OPENSSL) || defined(LIBSSH2_WOLFSSL)
        if(!BN_dec2bn(&f, tests[i].f) ||
           !BN_dec2bn(&p, tests[i].p)) {
            fprintf(stderr,
                    "ssh2_dh_is_valid/%lu: BN_dec2bn() failed\n",
                    (unsigned long)i);
            err++;
            continue;
        }
        got = ssh2_dh_is_valid(f, p);
#else
        got = tests[i].expected;
#endif
        if(got != tests[i].expected) {
            fprintf(stderr,
                    "ssh2_dh_is_valid/%lu: f=%s p=%s: expected %d got %d\n",
                    (unsigned long)i,
                    tests[i].f, tests[i].p, tests[i].expected, got);
            err++;
        }
    }

#ifdef LIBSSH2_MBEDTLS
    mbedtls_mpi_free(&f);
    mbedtls_mpi_free(&p);
#elif defined(LIBSSH2_OPENSSL) || defined(LIBSSH2_WOLFSSL)
    BN_free(f);
    BN_free(p);
#endif

    return err > 0;
}

int main(int argc, char *argv[])
{
    LIBSSH2_SESSION *session;
    int rc;
    (void)argv;
    (void)argc;

    rc = libssh2_init(LIBSSH2_INIT_NO_CRYPTO);
    if(rc) {
        fprintf(stderr, "libssh2_init() failed: %d\n", rc);
        return 1;
    }

    session = libssh2_session_init();
    if(!session) {
        fprintf(stderr, "libssh2_session_init() failed\n");
        return 1;
    }

    rc = test_ssh2_base64_decode(session);
    rc |= test_ssh2_dh_is_valid();

    libssh2_session_free(session);

    libssh2_exit();

    return rc;
}
