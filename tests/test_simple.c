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
#include <stdlib.h>  /* for atoi() */

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
        {   "1",  "10", -1 },
        {   "0",  "10", -1 },
        {   "9",  "10", -2 }, /* f=9; p=10 => p-2=8, f>8 */
        {   "6",  "20", -3 }, /* f=6 (110); p=20 => p-2=18, 6<=18 */
        {  "27", "100",  0 }, /* f=27 (11011); p=100 => p-2=98, 27<=98 */
        { "240", "242",  0 }, /* f=p-2, f=240 (11110000); p=f+2=242 */
    };

    size_t i;
    int err = 0;

    for(i = 0; i < SSH2_ARRAYSIZE(tests); i++) {
        int got;
#ifdef LIBSSH2_LIBGCRYPT
        int fi = atoi(tests[i].f);
        gcry_mpi_t f = gcry_mpi_set_ui(NULL, fi >= 0 ? fi : -fi);
        gcry_mpi_t p = gcry_mpi_set_ui(NULL, atoi(tests[i].p));
        if(tests[i].f[0] == '-')
            gcry_mpi_neg(f, f);
        got = ssh2_dh_is_valid(f, p);
        gcry_mpi_release(f);
        gcry_mpi_release(p);
#elif defined(LIBSSH2_MBEDTLS)
        mbedtls_mpi f, p;
        mbedtls_mpi_init(&f);
        mbedtls_mpi_init(&p);
        if(mbedtls_mpi_read_string(&f, 10, tests[i].f) ||
           mbedtls_mpi_read_string(&p, 10, tests[i].p))
            got = -9;
        else
            got = ssh2_dh_is_valid(&f, &p);
        mbedtls_mpi_free(&f);
        mbedtls_mpi_free(&p);
#elif defined(LIBSSH2_OPENSSL) || defined(LIBSSH2_WOLFSSL)
        BIGNUM *f = BN_new(), *p = BN_new();
        if(!BN_dec2bn(&f, tests[i].f) ||
           !BN_dec2bn(&p, tests[i].p))
            got = -9;
        else
            got = ssh2_dh_is_valid(f, p);
        BN_free(f);
        BN_free(p);
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

    return err > 0;
}

int main(int argc, char *argv[])
{
    LIBSSH2_SESSION *session;
    int rc;
    (void)argv;
    (void)argc;

    rc = libssh2_init(0);
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
