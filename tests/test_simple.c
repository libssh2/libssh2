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
static int check_ssh2_wcng_tail(const ssh2_bn *bn, size_t width,
                               const char *name)
{
    size_t i;

    if(bn->length > width)
        return 1;

    /* WinCNG normalization retains the original fixed-width allocation. */
    for(i = bn->length; i < width; i++) {
        if(bn->bignum[i]) {
            fprintf(stderr, "%s has an uncleared tail at %lu\n",
                    name, (unsigned long)i);
            return 1;
        }
    }

    return 0;
}
#endif

static int test_ssh2_bn_from_bin(void)
{
    static const struct {
        unsigned char input[5];
        size_t length;
        size_t leading;
    } tests[] = {
        { { 1 }, 1, 0 },
        { { 0x7f }, 1, 0 },
        { { 0x80 }, 1, 0 },
        { { 0xff, 0x42 }, 2, 0 },
        { { 0, 1 }, 2, 1 },
        { { 0, 0x80 }, 2, 1 },
        { { 0, 0, 0x80, 0x42 }, 4, 2 },
        { { 0, 0, 0, 0, 1 }, 5, 4 },
#ifdef LIBSSH2_WINCNG
        /* WinCNG has historically represented zero as one zero byte. */
        { { 0 }, 1, 0 },
        { { 0, 0, 0, 0, 0 }, 5, 4 },
#endif
    };
    size_t i;
    int rc = 0;

    for(i = 0; i < SSH2_ARRAYSIZE(tests); i++) {
        unsigned char actual[5] = { 0 };
        size_t length = tests[i].length - tests[i].leading;
        ssh2_bn *bn = ssh2_bn_init_from_bin();

#ifndef LIBSSH2_LIBGCRYPT
        if(!bn)
            return 1;
#endif
        if(ssh2_bn_from_bin(bn, tests[i].input, tests[i].length) ||
           (size_t)ssh2_bn_bytes(bn) != length ||
           ssh2_bn_to_bin(bn, actual) ||
           memcmp(actual, tests[i].input + tests[i].leading, length)) {
            fprintf(stderr, "ssh2_bn_from_bin case %lu failed\n",
                    (unsigned long)i);
            rc = 1;
        }
#ifdef LIBSSH2_WINCNG
        else
            rc |= check_ssh2_wcng_tail(bn, tests[i].length,
                                       "ssh2_bn_from_bin");
#endif
        ssh2_bn_free(bn);
    }
    return rc;
}

#ifdef LIBSSH2_WINCNG
/* RFC 3526 group 14, also used by the production key exchange. */
static const unsigned char test_dh_prime[256] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xc9, 0x0f, 0xda, 0xa2, 0x21, 0x68, 0xc2, 0x34,
    0xc4, 0xc6, 0x62, 0x8b, 0x80, 0xdc, 0x1c, 0xd1,
    0x29, 0x02, 0x4e, 0x08, 0x8a, 0x67, 0xcc, 0x74,
    0x02, 0x0b, 0xbe, 0xa6, 0x3b, 0x13, 0x9b, 0x22,
    0x51, 0x4a, 0x08, 0x79, 0x8e, 0x34, 0x04, 0xdd,
    0xef, 0x95, 0x19, 0xb3, 0xcd, 0x3a, 0x43, 0x1b,
    0x30, 0x2b, 0x0a, 0x6d, 0xf2, 0x5f, 0x14, 0x37,
    0x4f, 0xe1, 0x35, 0x6d, 0x6d, 0x51, 0xc2, 0x45,
    0xe4, 0x85, 0xb5, 0x76, 0x62, 0x5e, 0x7e, 0xc6,
    0xf4, 0x4c, 0x42, 0xe9, 0xa6, 0x37, 0xed, 0x6b,
    0x0b, 0xff, 0x5c, 0xb6, 0xf4, 0x06, 0xb7, 0xed,
    0xee, 0x38, 0x6b, 0xfb, 0x5a, 0x89, 0x9f, 0xa5,
    0xae, 0x9f, 0x24, 0x11, 0x7c, 0x4b, 0x1f, 0xe6,
    0x49, 0x28, 0x66, 0x51, 0xec, 0xe4, 0x5b, 0x3d,
    0xc2, 0x00, 0x7c, 0xb8, 0xa1, 0x63, 0xbf, 0x05,
    0x98, 0xda, 0x48, 0x36, 0x1c, 0x55, 0xd3, 0x9a,
    0x69, 0x16, 0x3f, 0xa8, 0xfd, 0x24, 0xcf, 0x5f,
    0x83, 0x65, 0x5d, 0x23, 0xdc, 0xa3, 0xad, 0x96,
    0x1c, 0x62, 0xf3, 0x56, 0x20, 0x85, 0x52, 0xbb,
    0x9e, 0xd5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6d,
    0x67, 0x0c, 0x35, 0x4e, 0x4a, 0xbc, 0x98, 0x04,
    0xf1, 0x74, 0x6c, 0x08, 0xca, 0x18, 0x21, 0x7c,
    0x32, 0x90, 0x5e, 0x46, 0x2e, 0x36, 0xce, 0x3b,
    0xe3, 0x9e, 0x77, 0x2c, 0x18, 0x0e, 0x86, 0x03,
    0x9b, 0x27, 0x83, 0xa2, 0xec, 0x07, 0xa2, 0x8f,
    0xb5, 0xc5, 0x5d, 0xf0, 0x6f, 0x4c, 0x52, 0xc9,
    0xde, 0x2b, 0xcb, 0xf6, 0x95, 0x58, 0x17, 0x18,
    0x39, 0x95, 0x49, 0x7c, 0xea, 0x95, 0x6a, 0xe5,
    0x15, 0xd2, 0x26, 0x18, 0x98, 0xfa, 0x05, 0x10,
    0x15, 0x72, 0x8e, 0x5a, 0x8a, 0xac, 0xaa, 0x68,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

static int check_ssh2_wcng_output(const ssh2_bn *bn,
                                 const unsigned char *raw, size_t width,
                                 const char *name)
{
    unsigned char actual[sizeof(test_dh_prime)];
    size_t offset = 0;

    if(!bn || !width || width > sizeof(actual))
        return 1;

    while(offset + 1 < width && !raw[offset])
        offset++;

    if(ssh2_bn_bytes(bn) != width - offset ||
       ssh2_bn_to_bin(bn, actual) ||
       memcmp(actual, raw + offset, width - offset)) {
        fprintf(stderr, "%s normalization failed (length %lu, expected %lu)\n",
                name, (unsigned long)ssh2_bn_bytes(bn),
                (unsigned long)(width - offset));
        return 1;
    }

    return check_ssh2_wcng_tail(bn, width, name);
}

static int check_ssh2_bn_is_one(const ssh2_bn *bn, size_t width,
                               const char *name)
{
    unsigned char actual = 0;

    if(ssh2_bn_bytes(bn) != 1 || ssh2_bn_to_bin(bn, &actual) || actual != 1) {
        fprintf(stderr, "%s is not canonical one (length %lu)\n",
                name, (unsigned long)ssh2_bn_bytes(bn));
        return 1;
    }

    return check_ssh2_wcng_tail(bn, width, name);
}

static int test_ssh2_dh_fallback_normalization(void)
{
    /* One isolates backend arithmetic; this is not an SSH handshake. */
    static const unsigned char one[] = { 1 };
    const int has_alg_dh_with_kdf = ssh2_wcng.hasAlgDHwithKDF;
    ssh2_dh_ctx dhctx;
    ssh2_bn *pub = ssh2_bn_init();
    ssh2_bn *secret = ssh2_bn_init();
    ssh2_bn *g = ssh2_bn_init_from_bin();
    ssh2_bn *p = ssh2_bn_init_from_bin();
    ssh2_bn *f = ssh2_bn_init_from_bin();
    int rc = 1;

    ssh2_dh_init(&dhctx);

    if(!pub || !secret || !g || !p || !f) {
        fprintf(stderr, "DH fallback bignum allocation failed\n");
        goto out;
    }

    if(ssh2_bn_from_bin(g, one, sizeof(one)) ||
       ssh2_bn_from_bin(p, test_dh_prime, sizeof(test_dh_prime)) ||
       ssh2_bn_from_bin(f, one, sizeof(one))) {
        fprintf(stderr, "DH fallback bignum initialization failed\n");
        goto out;
    }

    ssh2_wcng.hasAlgDHwithKDF = -1;
    if(ssh2_dh_key_pair(&dhctx, pub, g, p, 8, NULL)) {
        fprintf(stderr, "DH fallback key pair failed\n");
        goto out;
    }

    rc = check_ssh2_bn_is_one(pub, sizeof(test_dh_prime),
                             "DH fallback public value");

    if(ssh2_dh_secret(&dhctx, secret, f, p, NULL)) {
        fprintf(stderr, "DH fallback shared secret failed\n");
        rc = 1;
        goto out;
    }

    rc |= check_ssh2_bn_is_one(secret, sizeof(test_dh_prime),
                              "DH fallback shared secret");

out:
    ssh2_wcng.hasAlgDHwithKDF = has_alg_dh_with_kdf;
    ssh2_dh_dtor(&dhctx);
    ssh2_bn_free(pub);
    ssh2_bn_free(secret);
    ssh2_bn_free(g);
    ssh2_bn_free(p);
    ssh2_bn_free(f);
    return rc;
}

static int test_ssh2_dh_native_normalization(void)
{
    struct {
        BCRYPT_DH_KEY_BLOB header;
        unsigned char data[4 * sizeof(test_dh_prime)];
    } blob;
    unsigned char expected[sizeof(test_dh_prime)] = { 0 };
    const int has_alg_dh_with_kdf = ssh2_wcng.hasAlgDHwithKDF;
    ssh2_dh_ctx dhctx;
    ssh2_bn *pub = ssh2_bn_init();
    ssh2_bn *secret = ssh2_bn_init();
    ssh2_bn *g = ssh2_bn_init();
    ssh2_bn *p = ssh2_bn_init_from_bin();
    ssh2_bn *f = ssh2_bn_init();
    ULONG written = 0;
    int rc = 1;
    int public_rc;

    ssh2_dh_init(&dhctx);
    if(!pub || !secret || !g || !p || !f)
        goto out;
    if(!ssh2_wcng.hAlgDH) {
        fprintf(stderr, "Native DH provider unavailable\n");
        rc = 0;
        goto out;
    }
    if(ssh2_bn_set_word(g, 2) || ssh2_bn_set_word(f, 4) ||
       ssh2_bn_from_bin(p, test_dh_prime, sizeof(test_dh_prime)))
        goto out;

    ssh2_wcng.hasAlgDHwithKDF = 1;
    /* Compare a fresh public value with the actual fixed-width CNG export. */
    if(ssh2_dh_key_pair(&dhctx, pub, g, p, sizeof(test_dh_prime), NULL))
        goto out;
    if(!BCRYPT_SUCCESS(BCryptExportKey(dhctx.dh_handle, NULL,
                                      BCRYPT_DH_PUBLIC_BLOB,
                                      (PUCHAR)&blob, sizeof(blob),
                                      &written, 0)) ||
       blob.header.cbKey != sizeof(test_dh_prime) ||
       written != sizeof(blob.header) + 3 * sizeof(test_dh_prime))
        goto out;
    public_rc = check_ssh2_wcng_output(pub,
        blob.data + 2 * sizeof(test_dh_prime), sizeof(test_dh_prime),
        "DH native public value");

    /* Fixed test key: g=2, private exponent=3, public value=8. */
    if(!BCRYPT_SUCCESS(BCryptDestroyKey(dhctx.dh_handle)))
        goto out;
    dhctx.dh_handle = NULL;
    memset(&blob, 0, sizeof(blob));
    blob.header.dwMagic = BCRYPT_DH_PRIVATE_MAGIC;
    blob.header.cbKey = sizeof(test_dh_prime);
    memcpy(blob.data, test_dh_prime, sizeof(test_dh_prime));
    blob.data[2 * sizeof(test_dh_prime) - 1] = 2;
    blob.data[3 * sizeof(test_dh_prime) - 1] = 8;
    blob.data[4 * sizeof(test_dh_prime) - 1] = 3;
    if(!BCRYPT_SUCCESS(BCryptImportKeyPair(ssh2_wcng.hAlgDH, NULL,
                                          BCRYPT_DH_PRIVATE_BLOB,
                                          &dhctx.dh_handle, (PUCHAR)&blob,
                                          sizeof(blob), 0)))
        goto out;
    dhctx.dh_privbn = ssh2_bn_init();
    if(!dhctx.dh_privbn || ssh2_bn_set_word(dhctx.dh_privbn, 3))
        goto out;
    if(ssh2_dh_secret(&dhctx, secret, f, p, NULL))
        goto out;
    if(ssh2_wcng.hasAlgDHwithKDF == -1)
        fprintf(stderr, "Native DH raw KDF unavailable; used fallback\n");
    expected[sizeof(expected) - 1] = 64; /* 4^3 mod p */
    rc = public_rc | check_ssh2_wcng_output(secret, expected, sizeof(expected),
                                           "DH native shared secret");
out:
    if(rc)
        fprintf(stderr, "Native DH normalization test failed\n");
    ssh2_wcng.hasAlgDHwithKDF = has_alg_dh_with_kdf;
    ssh2_dh_dtor(&dhctx);
    ssh2_bn_free(pub);
    ssh2_bn_free(secret);
    ssh2_bn_free(g);
    ssh2_bn_free(p);
    ssh2_bn_free(f);
    return rc;
}

#if LIBSSH2_ECDSA
static int test_ssh2_ecdh_normalization(LIBSSH2_SESSION *session)
{
    /* P-256 generator: local scalar 1. Public test data, not a live key. */
    static const unsigned char generator[64] = {
        0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47,
        0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2,
        0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0,
        0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
        0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b,
        0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16,
        0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce,
        0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5
    };
    /* Peer scalar 379: the shared x coordinate starts with 00. */
    static const unsigned char peer[65] = {
        0x04,
        0x00, 0x55, 0x43, 0x89, 0x4a, 0xf3, 0xd0, 0x0e,
        0xd7, 0xd7, 0x40, 0xab, 0xdb, 0xd7, 0x5c, 0x96,
        0xb0, 0x68, 0x77, 0xb7, 0x87, 0xdb, 0x5f, 0x70,
        0xee, 0xa7, 0x8b, 0x90, 0xa8, 0xd7, 0xc0, 0x0a,
        0xbb, 0x4c, 0x85, 0xa3, 0xd8, 0xea, 0x29, 0xef,
        0xaa, 0xfa, 0x24, 0x40, 0x69, 0x12, 0xdd, 0x84,
        0xd5, 0xb1, 0x4d, 0xc3, 0x2b, 0xf6, 0x56, 0xef,
        0x6c, 0x6b, 0xd5, 0x8a, 0x5d, 0x94, 0x3f, 0x92
    };
    struct {
        BCRYPT_ECCKEY_BLOB header;
        unsigned char data[96];
    } blob;
    ssh2_ecdsa_ctx key;
    ssh2_bn *secret = NULL;
    int rc = 1;

    key.handle = NULL;
    key.curve = SSH2_EC_CURVE_NISTP256;
    memset(&blob, 0, sizeof(blob));
    blob.header.dwMagic = BCRYPT_ECDH_PRIVATE_P256_MAGIC;
    blob.header.cbKey = 32;
    memcpy(blob.data, generator, sizeof(generator));
    blob.data[sizeof(blob.data) - 1] = 1;
    if(!BCRYPT_SUCCESS(BCryptImportKeyPair(ssh2_wcng.hAlgECDH[key.curve], NULL,
                                          BCRYPT_ECCPRIVATE_BLOB,
                                          &key.handle, (PUCHAR)&blob,
                                          sizeof(blob), 0)))
        goto out;
    if(ssh2_ecdh_gen_k(&secret, session, &key, peer, sizeof(peer)))
        goto out;
    rc = check_ssh2_wcng_output(secret, peer + 1, 32, "ECDH shared secret");
out:
    if(rc)
        fprintf(stderr, "ECDH normalization test failed\n");
    ssh2_bn_free(secret);
    if(key.handle)
        BCryptDestroyKey(key.handle);
    return rc;
}
#endif
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
    rc |= test_ssh2_bn_from_bin();
#ifdef LIBSSH2_WINCNG
    rc |= test_ssh2_dh_fallback_normalization();
    rc |= test_ssh2_dh_native_normalization();
#if LIBSSH2_ECDSA
    rc |= test_ssh2_ecdh_normalization(session);
#endif
#endif
    rc |= test_ssh2_scp_parse_c_fields();

    libssh2_session_free(session);

    libssh2_exit();

    return rc;
}
