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

static int test_ssh2_dh_validate(void)
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
        struct tbn t = tests[i];
        int got;
#ifdef LIBSSH2_LIBGCRYPT
        gcry_mpi_t f = gcry_mpi_set_ui(NULL, (unsigned long)abs(atoi(t.f)));
        gcry_mpi_t p = gcry_mpi_set_ui(NULL, (unsigned long)atoi(t.p));
        if(t.f[0] == '-')
            gcry_mpi_neg(f, f);
        got = ssh2_dh_validate(f, p);
        gcry_mpi_release(f);
        gcry_mpi_release(p);
#elif defined(LIBSSH2_MBEDTLS)
        mbedtls_mpi f, p;
        mbedtls_mpi_init(&f);
        mbedtls_mpi_init(&p);
        if(mbedtls_mpi_read_string(&f, 10, t.f) ||
           mbedtls_mpi_read_string(&p, 10, t.p))
            got = -9;
        else
            got = ssh2_dh_validate(&f, &p);
        mbedtls_mpi_free(&f);
        mbedtls_mpi_free(&p);
#elif defined(LIBSSH2_OPENSSL) || \
    (defined(LIBSSH2_WOLFSSL) && LIBWOLFSSL_VERSION_HEX >= 0x05006000)
        BIGNUM *f = BN_new(), *p = BN_new();
        if(!BN_dec2bn(&f, t.f) ||
           !BN_dec2bn(&p, t.p))
            got = -9;
        else
            got = ssh2_dh_validate(f, p);
        BN_free(f);
        BN_free(p);
#else
        got = t.expected;
#endif
        if(got != t.expected) {
            fprintf(stderr,
                    "ssh2_dh_validate/%lu: f=%s p=%s: expected %d got %d\n",
                    (unsigned long)i,
                    t.f, t.p, t.expected, got);
            err++;
        }
    }

    return err > 0;
}

/* Return codes match scp.c (SCP_C_FIELDS_*). */
static int test_ssh2_scp_parse_c_fields(void)
{
    long mode = -1;
    libssh2_int64_t size = -1;
    unsigned char long_line[SSH2_SCP_RESPONSE_BUFLEN];
    size_t prefix_len;
    size_t i;
    int prc;
    int err = 0;

    /* Normal complete line with short name */
    prc = ssh2_scp_parse_c_fields(
        (const unsigned char *)"C0644 123 shortname\n", 20, &mode, &size);
    if(prc || mode != 420L || size != 123) { /* 0644 octal == 420 */
        fprintf(stderr, "scp_parse short: prc=%d mode=%ld size=%lld\n",
                prc, mode, (long long)size);
        err++;
    }

    /* Fields complete without trailing newline (name unfinished) */
    mode = -1;
    size = -1;
    prc = ssh2_scp_parse_c_fields(
        (const unsigned char *)"C0755 42 ", 9, &mode, &size);
    if(prc || mode != 493L || size != 42) { /* 0755 octal == 493 */
        fprintf(stderr, "scp_parse partial-name: prc=%d mode=%ld size=%lld\n",
                prc, mode, (long long)size);
        err++;
    }

    /* Incomplete size digits still growing */
    prc = ssh2_scp_parse_c_fields(
        (const unsigned char *)"C0644 12", 8, &mode, &size);
    if(prc != 1) {
        fprintf(stderr, "scp_parse incomplete size: prc=%d (want 1)\n", prc);
        err++;
    }

    /*
     * Reproduce #1738 shape: fixed buffer full of "Cmode size " + long name
     * without newline. Mode and size must still parse so scp_recv can drain.
     * Avoid snprintf: old MSVC (AppVeyor VS2010) lacks it.
     */
    {
        static const char prefix[] = "C0644 99 ";
        prefix_len = sizeof(prefix) - 1;
        memcpy(long_line, prefix, prefix_len);
    }
    for(i = prefix_len; i < sizeof(long_line); i++)
        long_line[i] = 'a';
    mode = -1;
    size = -1;
    prc = ssh2_scp_parse_c_fields(long_line, sizeof(long_line), &mode, &size);
    if(prc || mode != 420L || size != 99) { /* 0644 octal == 420 */
        fprintf(stderr,
                "scp_parse long-name buffer: prc=%d mode=%ld size=%lld\n",
                prc, mode, (long long)size);
        err++;
    }

    /* Malformed: bad mode */
    prc = ssh2_scp_parse_c_fields(
        (const unsigned char *)"Cxyz 1 name\n", 12, &mode, &size);
    if(prc != -1) {
        fprintf(stderr, "scp_parse bad mode: prc=%d (want -1)\n", prc);
        err++;
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
    rc |= test_ssh2_dh_validate();
    rc |= test_ssh2_scp_parse_c_fields();

    libssh2_session_free(session);

    libssh2_exit();

    return rc;
}
