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
#include <string.h>
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

static int test_knownhost_ipv6_case(LIBSSH2_SESSION *session,
                                    const char *stored,
                                    const char *checked,
                                    int port,
                                    int expected)
{
    static const char key[] = "AAAA";
    const int typemask =
        LIBSSH2_KNOWNHOST_TYPE_PLAIN |
        LIBSSH2_KNOWNHOST_KEYENC_BASE64 |
        LIBSSH2_KNOWNHOST_KEY_SSHRSA;
    LIBSSH2_KNOWNHOSTS *hosts;
    int rc;

    hosts = libssh2_knownhost_init(session);
    if(!hosts) {
        fprintf(stderr, "libssh2_knownhost_init() failed\n");
        return 1;
    }

    rc = libssh2_knownhost_addc(hosts, stored, NULL, key, strlen(key),
                                NULL, 0, typemask, NULL);
    if(rc) {
        fprintf(stderr, "libssh2_knownhost_addc(%s) failed: %d\n",
                stored, rc);
        libssh2_knownhost_free(hosts);
        return 1;
    }

    if(port >= 0)
        rc = libssh2_knownhost_checkp(hosts, checked, port, key,
                                      strlen(key), typemask, NULL);
    else
        rc = libssh2_knownhost_check(hosts, checked, key, strlen(key),
                                     typemask, NULL);

    libssh2_knownhost_free(hosts);

    if(rc != expected) {
        fprintf(stderr,
                "knownhost IPv6: stored=%s checked=%s port=%d "
                "expected=%d got=%d\n",
                stored, checked, port, expected, rc);
        return 1;
    }

    return 0;
}

static int test_knownhost_ipv6(LIBSSH2_SESSION *session)
{
    int err = 0;

    err |= test_knownhost_ipv6_case(
        session,
        "fd5f:4268:2387:97c1:0000:0000:0000:0002",
        "fd5f:4268:2387:97c1::2",
        -1, LIBSSH2_KNOWNHOST_CHECK_MATCH);

    err |= test_knownhost_ipv6_case(
        session,
        "fd5f:4268:2387:97c1::2",
        "fd5f:4268:2387:97c1:0:0:0:2",
        -1, LIBSSH2_KNOWNHOST_CHECK_MATCH);

    err |= test_knownhost_ipv6_case(
        session,
        "0:0:0:0:0:ffff:c000:0201",
        "::ffff:192.0.2.1",
        -1, LIBSSH2_KNOWNHOST_CHECK_MATCH);

    err |= test_knownhost_ipv6_case(
        session,
        "[fd5f:4268:2387:97c1:0000:0000:0000:0002]:2222",
        "fd5f:4268:2387:97c1::2",
        2222, LIBSSH2_KNOWNHOST_CHECK_MATCH);

    err |= test_knownhost_ipv6_case(
        session,
        "[fd5f:4268:2387:97c1:0000:0000:0000:0002]:2222",
        "fd5f:4268:2387:97c1::2",
        22, LIBSSH2_KNOWNHOST_CHECK_NOTFOUND);

    err |= test_knownhost_ipv6_case(
        session,
        "fd5f:4268:2387:97c1::2",
        "fd5f:4268:2387:97c1::3",
        -1, LIBSSH2_KNOWNHOST_CHECK_NOTFOUND);

    err |= test_knownhost_ipv6_case(
        session,
        "fd5f:4268:2387:97c1::2",
        "fd5f:4268:2387:97c1::1::2",
        -1, LIBSSH2_KNOWNHOST_CHECK_NOTFOUND);

    err |= test_knownhost_ipv6_case(
        session,
        "example.com",
        "example.com",
        -1, LIBSSH2_KNOWNHOST_CHECK_MATCH);

    err |= test_knownhost_ipv6_case(
        session,
        "example.com",
        "EXAMPLE.COM",
        -1, LIBSSH2_KNOWNHOST_CHECK_NOTFOUND);

    /* Hexadecimal digits are case-insensitive. */
    err |= test_knownhost_ipv6_case(
        session,
        "2001:0DB8:0000:0000:0000:0000:0000:0001",
        "2001:db8::1",
        -1, LIBSSH2_KNOWNHOST_CHECK_MATCH);

    /* Compression may represent the complete address. */
    err |= test_knownhost_ipv6_case(
        session,
        "0:0:0:0:0:0:0:0",
        "::",
        -1, LIBSSH2_KNOWNHOST_CHECK_MATCH);

    /* Compression at the end must expand to the remaining words. */
    err |= test_knownhost_ipv6_case(
        session,
        "2001:db8:1:2:3:4:0:0",
        "2001:db8:1:2:3:4::",
        -1, LIBSSH2_KNOWNHOST_CHECK_MATCH);

    /* More than eight words is not a valid IPv6 literal. */
    err |= test_knownhost_ipv6_case(
        session,
        "2001:db8::1",
        "1:2:3:4:5:6:7:8:9",
        -1, LIBSSH2_KNOWNHOST_CHECK_NOTFOUND);

    /* An embedded IPv4 address must contain valid octets. */
    err |= test_knownhost_ipv6_case(
        session,
        "::ffff:192.0.2.1",
        "::ffff:192.0.2.256",
        -1, LIBSSH2_KNOWNHOST_CHECK_NOTFOUND);

    /* Embedded IPv4 octets with leading zeros are not valid. */
    err |= test_knownhost_ipv6_case(
        session,
        "::ffff:192.168.001.1",
        "::ffff:192.168.1.1",
        -1, LIBSSH2_KNOWNHOST_CHECK_NOTFOUND);

    /* Identical malformed names retain the historical exact-string match. */
    err |= test_knownhost_ipv6_case(
        session,
        "::ffff:192.168.001.1",
        "::ffff:192.168.001.1",
        -1, LIBSSH2_KNOWNHOST_CHECK_MATCH);

    /*
     * Preserve the historical exact-string behavior even when a plain host
     * containing colons is not a valid IPv6 literal.
     */
    err |= test_knownhost_ipv6_case(
        session,
        "fd5f::1::2",
        "fd5f::1::2",
        -1, LIBSSH2_KNOWNHOST_CHECK_MATCH);

    return err > 0;
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

#ifdef LIBSSH2_WINCNG
static int test_ssh2_wcng_bn_normalize(void)
{
    static const unsigned char fixed_width[] = { 0, 0, 0x80, 0x42 };
    static const unsigned char expected[] = { 0x80, 0x42 };
    ssh2_bn *bn = ssh2_bn_init();
    int rc = 0;

    if(!bn)
        return 1;

    bn->bignum = malloc(sizeof(fixed_width));
    if(!bn->bignum) {
        ssh2_bn_free(bn);
        return 1;
    }
    memcpy(bn->bignum, fixed_width, sizeof(fixed_width));
    bn->length = sizeof(fixed_width);

    ssh2_wcng_bn_normalize(bn);
    if(bn->length != sizeof(expected) ||
       memcmp(bn->bignum, expected, sizeof(expected)) ||
       bn->bignum[sizeof(expected)] || bn->bignum[sizeof(expected) + 1]) {
        fprintf(stderr, "WinCNG bignum normalization failed\n");
        rc = 1;
    }

    ssh2_bn_free(bn);
    return rc;
}
#endif

/* Return codes match scp.c (SCP_C_FIELDS_*). */
static int test_ssh2_scp_parse_c_fields(void)
{
    long mode = -1;
    libssh2_int64_t size = -1;
    char long_line[SSH2_SCP_RESPONSE_BUFLEN];
    int prefix_len;
    int prc;
    int err = 0;

    /* Normal complete line with short name */
    prc = ssh2_scp_parse_c_fields("C0644 123 shortname\n", 20, &mode, &size);
    if(prc || mode != 420L || size != 123) { /* 0644 octal == 420 */
        fprintf(stderr, "scp_parse short: prc=%d mode=%ld size=%lu\n",
                prc, mode, (unsigned long)size);
        err++;
    }

    /* Fields complete without trailing newline (name unfinished) */
    mode = -1;
    size = -1;
    prc = ssh2_scp_parse_c_fields("C0755 42 ", 9, &mode, &size);
    if(prc || mode != 493L || size != 42) { /* 0755 octal == 493 */
        fprintf(stderr, "scp_parse partial-name: prc=%d mode=%ld size=%lu\n",
                prc, mode, (unsigned long)size);
        err++;
    }

    /* Incomplete size digits still growing */
    prc = ssh2_scp_parse_c_fields("C0644 12", 8, &mode, &size);
    if(prc != 1) {
        fprintf(stderr, "scp_parse incomplete size: prc=%d (want 1)\n", prc);
        err++;
    }

    /*
     * Fixed buffer full of "Cmode size " + long name without newline. Mode and
     * size must still parse so scp_recv can drain the unused basename.
     */
    prefix_len = snprintf(long_line, sizeof(long_line), "C0644 99 ");
    if(prefix_len < 0 || (size_t)prefix_len >= sizeof(long_line)) {
        fprintf(stderr, "scp_parse long-name: snprintf failed (%d)\n",
                prefix_len);
        return 1;
    }
    memset(long_line + prefix_len, 'a',
           sizeof(long_line) - (size_t)prefix_len);
    mode = -1;
    size = -1;
    prc = ssh2_scp_parse_c_fields(long_line, sizeof(long_line), &mode, &size);
    if(prc || mode != 420L || size != 99) { /* 0644 octal == 420 */
        fprintf(stderr,
                "scp_parse long-name buffer: prc=%d mode=%ld size=%lu\n",
                prc, mode, (unsigned long)size);
        err++;
    }

    /* Malformed: bad mode */
    prc = ssh2_scp_parse_c_fields("Cxyz 1 name\n", 12, &mode, &size);
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
    rc |= test_knownhost_ipv6(session);
    rc |= test_ssh2_dh_validate();
#ifdef LIBSSH2_WINCNG
    rc |= test_ssh2_wcng_bn_normalize();
#endif
    rc |= test_ssh2_scp_parse_c_fields();

    libssh2_session_free(session);

    libssh2_exit();

    return rc;
}
