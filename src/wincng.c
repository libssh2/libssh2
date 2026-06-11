/*
 * Copyright (C) Marc Hoersken <info@marc-hoersken.de>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms,
 * with or without modification, are permitted provided
 * that the following conditions are met:
 *
 *   Redistributions of source code must retain the above
 *   copyright notice, this list of conditions and the
 *   following disclaimer.
 *
 *   Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following
 *   disclaimer in the documentation and/or other materials
 *   provided with the distribution.
 *
 *   Neither the name of the copyright holder nor the names
 *   of any other contributors may be used to endorse or
 *   promote products derived from this software without
 *   specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "libssh2_priv.h"

#ifdef LIBSSH2_WINCNG

/* required for cross-compilation against the w64 mingw-runtime package */
#if defined(_WIN32_WINNT) && _WIN32_WINNT < 0x0600
#undef _WIN32_WINNT
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif

#ifdef _MSC_VER
#pragma comment(lib, "bcrypt.lib")
#if LIBSSH2_RSA || LIBSSH2_DSA
#pragma comment(lib, "crypt32.lib")
#endif
#endif

#include <windows.h>
#if LIBSSH2_RSA || LIBSSH2_DSA
#include <wincrypt.h>  /* for CryptDecodeObjectEx() */
#endif
#include <bcrypt.h>
#include <math.h>

#include <stdlib.h>

#if LIBSSH2_RSA
#define PEM_RSA_HEADER "-----BEGIN RSA PRIVATE KEY-----"
#define PEM_RSA_FOOTER "-----END RSA PRIVATE KEY-----"
#endif
#if LIBSSH2_DSA
#define PEM_DSA_HEADER "-----BEGIN DSA PRIVATE KEY-----"
#define PEM_DSA_FOOTER "-----END DSA PRIVATE KEY-----"
#endif
#if LIBSSH2_ECDSA
/* Define these manually to avoid including <ntstatus.h> and thus
   clashing with <windows.h> symbols. */
#ifndef STATUS_INVALID_SIGNATURE
#define STATUS_INVALID_SIGNATURE ((NTSTATUS)0xC000A000)
#endif
#endif

#ifndef STATUS_NOT_SUPPORTED
#define STATUS_NOT_SUPPORTED ((NTSTATUS)0xC00000BB)
#endif

/*******************************************************************/
/*
 * Windows CNG backend: Missing definitions (for mingw-w64 and MS SDK)
 */

/* BCRYPT_KDF_RAW_SECRET is available from Windows 8.1 and onwards */
#ifndef BCRYPT_KDF_RAW_SECRET /* supported by mingw-w64 9.0+ and VS2017+ */
#define BCRYPT_KDF_RAW_SECRET L"TRUNCATE"
#endif

#ifndef BCRYPT_MESSAGE_BLOCK_LENGTH /* supported by mingw-w64 and VS2017+ */
#define BCRYPT_MESSAGE_BLOCK_LENGTH L"MessageBlockLength"
#endif

#if defined(_MSC_VER) && _MSC_VER < 1700
/* Workaround for warning C4306:
   'type cast' : conversion from 'int' to 'LPCSTR' of greater size */
#undef X509_SEQUENCE_OF_ANY
#undef X509_MULTI_BYTE_UINT
#undef PKCS_RSA_PRIVATE_KEY
#define X509_SEQUENCE_OF_ANY ((LPCSTR)(size_t)34)
#define X509_MULTI_BYTE_UINT ((LPCSTR)(size_t)38)
#define PKCS_RSA_PRIVATE_KEY ((LPCSTR)(size_t)43)
#endif

static void wcng_safe_free(void *buf, size_t len)
{
    if(!buf)
        return;

    if(len > 0)
        ssh2_explicit_zero(buf, len);

    free(buf);
}

/* Copy a big endian set of bits from src to dest.
 * if the size of src is smaller than dest then pad the "left" (MSB)
 * end with zeroes and copy the bits into the "right" (LSB) end. */
static void wcng_memcpy_with_be_padding(unsigned char *dest, ULONG dest_len,
                                        unsigned char *src, ULONG src_len)
{
    if(dest_len > src_len) {
        memset(dest, 0, dest_len - src_len);
    }
    memcpy((dest + dest_len) - src_len, src, src_len);
}

static void wcng_reverse_bytes(IN PUCHAR buffer, IN size_t buffer_len)
{
    if(buffer && buffer_len >= 2) {
        PUCHAR start = buffer;
        PUCHAR end = buffer + buffer_len - 1;
        while(start < end) {
            unsigned char tmp = *end;
            *end = *start;
            *start = tmp;
            start++;
            end--;
        }
    }
}

/*******************************************************************/
/*
 * Windows CNG backend: BigNumber functions
 */

ssh2_bn *ssh2_wcng_bn_init(void)
{
    ssh2_bn *bignum = malloc(sizeof(ssh2_bn));
    if(bignum) {
        bignum->bignum = NULL;
        bignum->length = 0;
    }

    return bignum;
}

static int wcng_bn_resize(ssh2_bn *bn, ULONG length)
{
    unsigned char *bignum;

    if(!bn)
        return -1;

    if(length == bn->length)
        return 0;

    if(bn->bignum && bn->length > 0 && length < bn->length) {
        ssh2_explicit_zero(bn->bignum + length, bn->length - length);
    }

    bignum = realloc(bn->bignum, length);
    if(!bignum)
        return -1;

    bn->bignum = bignum;
    bn->length = length;

    return 0;
}

static int wcng_bn_random(ssh2_bn *rnd, int bits, int top, int bottom)
{
    unsigned char *bignum;
    ULONG length;

    if(!rnd)
        return -1;

    length = (ULONG)(ceil(((double)bits) / 8.0) * sizeof(unsigned char));
    if(wcng_bn_resize(rnd, length))
        return -1;

    bignum = rnd->bignum;

    if(!bignum)
        return -1;

    if(ssh2_random(bignum, length))
        return -1;

    /* calculate significant bits in most significant byte */
    bits %= 8;
    if(bits == 0)
        bits = 8;

    /* fill most significant byte with zero padding */
    bignum[0] &= (unsigned char)((1 << bits) - 1);

    /* set most significant bits in most significant byte */
    if(top == 0)
        bignum[0] |= (unsigned char)(1 << (bits - 1));
    else if(top == 1)
        bignum[0] |= (unsigned char)(3 << (bits - 2));

    /* make odd by setting first bit in least significant byte */
    if(bottom)
        bignum[length - 1] |= 1;

    return 0;
}

static int wcng_bn_mod_exp(ssh2_bn *r, ssh2_bn *a, ssh2_bn *p, ssh2_bn *m)
{
    BCRYPT_KEY_HANDLE hKey;
    BCRYPT_RSAKEY_BLOB *rsakey;
    unsigned char *bignum;
    ULONG keylen, offset, length;
    NTSTATUS ret;

    if(!r || !a || !p || !m)
        return -1;

    offset = sizeof(BCRYPT_RSAKEY_BLOB);
    keylen = offset + p->length + m->length;

    rsakey = malloc(keylen);
    if(!rsakey)
        return -1;

    /* https://learn.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob */
    rsakey->Magic = BCRYPT_RSAPUBLIC_MAGIC;
    rsakey->BitLength = m->length * 8;
    rsakey->cbPublicExp = p->length;
    rsakey->cbModulus = m->length;
    rsakey->cbPrime1 = 0;
    rsakey->cbPrime2 = 0;

    memcpy((unsigned char *)rsakey + offset, p->bignum, p->length);
    offset += p->length;

    memcpy((unsigned char *)rsakey + offset, m->bignum, m->length);
    offset = 0;

    ret = BCryptImportKeyPair(ssh2_wcng.hAlgRSA, NULL, BCRYPT_RSAPUBLIC_BLOB,
                              &hKey, (PUCHAR)rsakey, keylen, 0);
    if(BCRYPT_SUCCESS(ret)) {
        ret = BCryptEncrypt(hKey, a->bignum, a->length, NULL, NULL, 0,
                            NULL, 0, &length, BCRYPT_PAD_NONE);
        if(BCRYPT_SUCCESS(ret)) {
            if(!wcng_bn_resize(r, length)) {
                length = max(a->length, length);
                bignum = malloc(length);
                if(bignum) {
                    wcng_memcpy_with_be_padding(bignum, length,
                                                a->bignum, a->length);

                    ret = BCryptEncrypt(hKey, bignum, length, NULL, NULL, 0,
                                        r->bignum, r->length, &offset,
                                        BCRYPT_PAD_NONE);

                    wcng_safe_free(bignum, length);

                    if(BCRYPT_SUCCESS(ret)) {
                        wcng_bn_resize(r, offset);
                    }
                }
                else
                    ret = (NTSTATUS)STATUS_NO_MEMORY;
            }
            else
                ret = (NTSTATUS)STATUS_NO_MEMORY;
        }

        BCryptDestroyKey(hKey);
    }

    wcng_safe_free(rsakey, keylen);

    return BCRYPT_SUCCESS(ret) ? 0 : -1;
}

int ssh2_wcng_bn_set_word(ssh2_bn *bn, ULONG word)
{
    ULONG offset, number, bits, length;

    if(!bn)
        return -1;

    bits = 0;
    number = word;
    while(number >>= 1)
        bits++;
    bits++;

    length = (ULONG)(ceil(((double)bits) / 8.0) * sizeof(unsigned char));
    if(wcng_bn_resize(bn, length))
        return -1;

    for(offset = 0; offset < length; offset++)
        bn->bignum[offset] = (word >> (offset * 8)) & 0xff;

    return 0;
}

ULONG ssh2_wcng_bn_bits(const ssh2_bn *bn)
{
    unsigned char number;
    ULONG offset, length, bits;

    if(!bn || !bn->bignum || !bn->length)
        return 0;

    offset = 0;
    length = bn->length - 1;
    while(!bn->bignum[offset] && offset < length)
        offset++;

    bits = (length - offset) * 8;
    number = bn->bignum[offset];
    while(number >>= 1)
        bits++;
    bits++;

    return bits;
}

int ssh2_wcng_bn_from_bin(ssh2_bn *bn, ULONG len, const unsigned char *bin)
{
    unsigned char *bignum;
    ULONG offset, length, bits;

    if(!bn || !bin || !len)
        return -1;

    if(wcng_bn_resize(bn, len))
        return -1;

    memcpy(bn->bignum, bin, len);

    bits = ssh2_wcng_bn_bits(bn);
    length = (ULONG)(ceil(((double)bits) / 8.0) * sizeof(unsigned char));

    offset = bn->length - length;
    if(offset > 0) {
        memmove(bn->bignum, bn->bignum + offset, length);

        ssh2_explicit_zero(bn->bignum + length, offset);

        bignum = realloc(bn->bignum, length);
        if(bignum) {
            bn->bignum = bignum;
            bn->length = length;
        }
        else {
            return -1;
        }
    }

    return 0;
}

int ssh2_wcng_bn_to_bin(const ssh2_bn *bn, unsigned char *bin)
{
    if(bin && bn && bn->bignum && bn->length > 0) {
        memcpy(bin, bn->bignum, bn->length);
        return 0;
    }

    return -1;
}

void ssh2_wcng_bn_free(ssh2_bn *bn)
{
    if(bn) {
        if(bn->bignum) {
            wcng_safe_free(bn->bignum, bn->length);
            bn->bignum = NULL;
        }
        bn->length = 0;
        wcng_safe_free(bn, sizeof(ssh2_bn));
    }
}

/*******************************************************************/
/*
 * Windows CNG backend: ECDSA-specific declarations.
 */
#if LIBSSH2_ECDSA

typedef enum {
    WCNG_ECC_KEYTYPE_ECDSA = 0,
    WCNG_ECC_KEYTYPE_ECDH = 1,
} wcng_ecc_keytype;

struct ecdsa_algorithm {
    const char *name;               /* Algorithm name */
    ULONG key_length;               /* Key length, in bits */
    ULONG point_length;             /* Length of each point, in bytes */
    LPCWSTR provider[2];            /* Name of CNG algorithm provider,
                                       indexed by wcng_ecc_keytype */
    ULONG public_import_magic[2];   /* Magic for public key import,
                                       indexed by wcng_ecc_keytype */
    ULONG private_import_magic[2];  /* Magic for private key import,
                                       indexed by wcng_ecc_keytype */
};

/* Supported algorithms, indexed by ssh2_curve_type */
static const struct ecdsa_algorithm wcng_ecdsa_algs[] = {
    {
        "ecdsa-sha2-nistp256",
        256,
        256 / 8,
        { BCRYPT_ECDSA_P256_ALGORITHM, BCRYPT_ECDH_P256_ALGORITHM },
        { BCRYPT_ECDSA_PUBLIC_P256_MAGIC, BCRYPT_ECDH_PUBLIC_P256_MAGIC },
        { BCRYPT_ECDSA_PRIVATE_P256_MAGIC, BCRYPT_ECDH_PRIVATE_P256_MAGIC }
    },
    {
        "ecdsa-sha2-nistp384",
        384,
        384 / 8,
        { BCRYPT_ECDSA_P384_ALGORITHM, BCRYPT_ECDH_P384_ALGORITHM },
        { BCRYPT_ECDSA_PUBLIC_P384_MAGIC, BCRYPT_ECDH_PUBLIC_P384_MAGIC },
        { BCRYPT_ECDSA_PRIVATE_P384_MAGIC, BCRYPT_ECDH_PRIVATE_P384_MAGIC }
    },
    {
        "ecdsa-sha2-nistp521",
        521,
        ((521 + 7) & ~7) / 8,
        { BCRYPT_ECDSA_P521_ALGORITHM, BCRYPT_ECDH_P521_ALGORITHM },
        { BCRYPT_ECDSA_PUBLIC_P521_MAGIC, BCRYPT_ECDH_PUBLIC_P521_MAGIC },
        { BCRYPT_ECDSA_PRIVATE_P521_MAGIC, BCRYPT_ECDH_PRIVATE_P521_MAGIC }
    },
};

/* An encoded point */
struct ecdsa_point {
    ssh2_curve_type curve;

    const unsigned char *x;
    ULONG x_len;

    const unsigned char *y;
    ULONG y_len;
};

#endif

/*******************************************************************/
/*
 * Windows CNG backend: Generic functions
 */

struct wcng_ctx ssh2_wcng;

void ssh2_crypto_init(void)
{
    int ret;

#if LIBSSH2_ECDSA
    unsigned int curve;
#endif

    memset(&ssh2_wcng, 0, sizeof(ssh2_wcng));

    ret = BCryptOpenAlgorithmProvider(&ssh2_wcng.hAlgRNG,
                                      BCRYPT_RNG_ALGORITHM, NULL, 0);
    if(!BCRYPT_SUCCESS(ret)) {
        ssh2_wcng.hAlgRNG = NULL;
    }

#if LIBSSH2_MD5 || LIBSSH2_MD5_PEM
    ret = BCryptOpenAlgorithmProvider(&ssh2_wcng.hAlgHashMD5,
                                      BCRYPT_MD5_ALGORITHM, NULL, 0);
    if(!BCRYPT_SUCCESS(ret)) {
        ssh2_wcng.hAlgHashMD5 = NULL;
    }
#endif
    ret = BCryptOpenAlgorithmProvider(&ssh2_wcng.hAlgHashSHA1,
                                      BCRYPT_SHA1_ALGORITHM, NULL, 0);
    if(!BCRYPT_SUCCESS(ret)) {
        ssh2_wcng.hAlgHashSHA1 = NULL;
    }
    ret = BCryptOpenAlgorithmProvider(&ssh2_wcng.hAlgHashSHA256,
                                      BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if(!BCRYPT_SUCCESS(ret)) {
        ssh2_wcng.hAlgHashSHA256 = NULL;
    }
    ret = BCryptOpenAlgorithmProvider(&ssh2_wcng.hAlgHashSHA384,
                                      BCRYPT_SHA384_ALGORITHM, NULL, 0);
    if(!BCRYPT_SUCCESS(ret)) {
        ssh2_wcng.hAlgHashSHA384 = NULL;
    }
    ret = BCryptOpenAlgorithmProvider(&ssh2_wcng.hAlgHashSHA512,
                                      BCRYPT_SHA512_ALGORITHM, NULL, 0);
    if(!BCRYPT_SUCCESS(ret)) {
        ssh2_wcng.hAlgHashSHA512 = NULL;
    }

#if LIBSSH2_MD5
    ret = BCryptOpenAlgorithmProvider(&ssh2_wcng.hAlgHmacMD5,
                                      BCRYPT_MD5_ALGORITHM, NULL,
                                      BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if(!BCRYPT_SUCCESS(ret)) {
        ssh2_wcng.hAlgHmacMD5 = NULL;
    }
#endif
    ret = BCryptOpenAlgorithmProvider(&ssh2_wcng.hAlgHmacSHA1,
                                      BCRYPT_SHA1_ALGORITHM, NULL,
                                      BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if(!BCRYPT_SUCCESS(ret)) {
        ssh2_wcng.hAlgHmacSHA1 = NULL;
    }
    ret = BCryptOpenAlgorithmProvider(&ssh2_wcng.hAlgHmacSHA256,
                                      BCRYPT_SHA256_ALGORITHM, NULL,
                                      BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if(!BCRYPT_SUCCESS(ret)) {
        ssh2_wcng.hAlgHmacSHA256 = NULL;
    }
    ret = BCryptOpenAlgorithmProvider(&ssh2_wcng.hAlgHmacSHA384,
                                      BCRYPT_SHA384_ALGORITHM, NULL,
                                      BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if(!BCRYPT_SUCCESS(ret)) {
        ssh2_wcng.hAlgHmacSHA384 = NULL;
    }
    ret = BCryptOpenAlgorithmProvider(&ssh2_wcng.hAlgHmacSHA512,
                                      BCRYPT_SHA512_ALGORITHM, NULL,
                                      BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if(!BCRYPT_SUCCESS(ret)) {
        ssh2_wcng.hAlgHmacSHA512 = NULL;
    }

    ret = BCryptOpenAlgorithmProvider(&ssh2_wcng.hAlgRSA,
                                      BCRYPT_RSA_ALGORITHM, NULL, 0);
    if(!BCRYPT_SUCCESS(ret)) {
        ssh2_wcng.hAlgRSA = NULL;
    }
#if LIBSSH2_DSA
    ret = BCryptOpenAlgorithmProvider(&ssh2_wcng.hAlgDSA,
                                      BCRYPT_DSA_ALGORITHM, NULL, 0);
    if(!BCRYPT_SUCCESS(ret)) {
        ssh2_wcng.hAlgDSA = NULL;
    }
#endif

    ret = BCryptOpenAlgorithmProvider(&ssh2_wcng.hAlgAES_CBC,
                                      BCRYPT_AES_ALGORITHM, NULL, 0);
    if(BCRYPT_SUCCESS(ret)) {
        ret = BCryptSetProperty(ssh2_wcng.hAlgAES_CBC,
                                BCRYPT_CHAINING_MODE,
                                (PBYTE)SSH2_UNCONST(BCRYPT_CHAIN_MODE_CBC),
                                sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
        if(!BCRYPT_SUCCESS(ret)) {
            ret = BCryptCloseAlgorithmProvider(ssh2_wcng.hAlgAES_CBC, 0);
            if(BCRYPT_SUCCESS(ret)) {
                ssh2_wcng.hAlgAES_CBC = NULL;
            }
        }
    }

    ret = BCryptOpenAlgorithmProvider(&ssh2_wcng.hAlgAES_ECB,
                                      BCRYPT_AES_ALGORITHM, NULL, 0);
    if(BCRYPT_SUCCESS(ret)) {
        ret = BCryptSetProperty(ssh2_wcng.hAlgAES_ECB,
                                BCRYPT_CHAINING_MODE,
                                (PBYTE)SSH2_UNCONST(BCRYPT_CHAIN_MODE_ECB),
                                sizeof(BCRYPT_CHAIN_MODE_ECB), 0);
        if(!BCRYPT_SUCCESS(ret)) {
            ret = BCryptCloseAlgorithmProvider(ssh2_wcng.hAlgAES_ECB, 0);
            if(BCRYPT_SUCCESS(ret)) {
                ssh2_wcng.hAlgAES_ECB = NULL;
            }
        }
    }
#if LIBSSH2_RC4
    ret = BCryptOpenAlgorithmProvider(&ssh2_wcng.hAlgRC4_NA,
                                      BCRYPT_RC4_ALGORITHM, NULL, 0);
    if(BCRYPT_SUCCESS(ret)) {
        ret = BCryptSetProperty(ssh2_wcng.hAlgRC4_NA,
                                BCRYPT_CHAINING_MODE,
                                (PBYTE)SSH2_UNCONST(BCRYPT_CHAIN_MODE_NA),
                                sizeof(BCRYPT_CHAIN_MODE_NA), 0);
        if(!BCRYPT_SUCCESS(ret)) {
            ret = BCryptCloseAlgorithmProvider(ssh2_wcng.hAlgRC4_NA, 0);
            if(BCRYPT_SUCCESS(ret)) {
                ssh2_wcng.hAlgRC4_NA = NULL;
            }
        }
    }
#endif
#if LIBSSH2_3DES
    ret = BCryptOpenAlgorithmProvider(&ssh2_wcng.hAlg3DES_CBC,
                                      BCRYPT_3DES_ALGORITHM, NULL, 0);
    if(BCRYPT_SUCCESS(ret)) {
        ret = BCryptSetProperty(ssh2_wcng.hAlg3DES_CBC,
                                BCRYPT_CHAINING_MODE,
                                (PBYTE)SSH2_UNCONST(BCRYPT_CHAIN_MODE_CBC),
                                sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
        if(!BCRYPT_SUCCESS(ret)) {
            ret = BCryptCloseAlgorithmProvider(ssh2_wcng.hAlg3DES_CBC, 0);
            if(BCRYPT_SUCCESS(ret)) {
                ssh2_wcng.hAlg3DES_CBC = NULL;
            }
        }
    }
#endif
    ret = BCryptOpenAlgorithmProvider(&ssh2_wcng.hAlgDH,
                                      BCRYPT_DH_ALGORITHM, NULL, 0);
    if(!BCRYPT_SUCCESS(ret)) {
        ssh2_wcng.hAlgDH = NULL;
    }

#if LIBSSH2_ECDSA
    for(curve = 0; curve < SSH2_ARRAYSIZE(wcng_ecdsa_algs); curve++) {
        BCRYPT_ALG_HANDLE alg_handle_ecdsa;
        BCRYPT_ALG_HANDLE alg_handle_ecdh;

        ret = BCryptOpenAlgorithmProvider(
            &alg_handle_ecdsa,
            wcng_ecdsa_algs[curve].provider[WCNG_ECC_KEYTYPE_ECDSA],
            NULL,
            0);
        if(BCRYPT_SUCCESS(ret)) {
            ssh2_wcng.hAlgECDSA[curve] = alg_handle_ecdsa;
        }

        ret = BCryptOpenAlgorithmProvider(
            &alg_handle_ecdh,
            wcng_ecdsa_algs[curve].provider[WCNG_ECC_KEYTYPE_ECDH],
            NULL,
            0);
        if(BCRYPT_SUCCESS(ret)) {
            ssh2_wcng.hAlgECDH[curve] = alg_handle_ecdh;
        }
    }
#endif
}

void ssh2_crypto_exit(void)
{
#if LIBSSH2_ECDSA
    unsigned int curve;
#endif

    if(ssh2_wcng.hAlgRNG)
        (void)BCryptCloseAlgorithmProvider(ssh2_wcng.hAlgRNG, 0);
#if LIBSSH2_MD5 || LIBSSH2_MD5_PEM
    if(ssh2_wcng.hAlgHashMD5)
        (void)BCryptCloseAlgorithmProvider(ssh2_wcng.hAlgHashMD5, 0);
#endif
    if(ssh2_wcng.hAlgHashSHA1)
        (void)BCryptCloseAlgorithmProvider(ssh2_wcng.hAlgHashSHA1, 0);
    if(ssh2_wcng.hAlgHashSHA256)
        (void)BCryptCloseAlgorithmProvider(ssh2_wcng.hAlgHashSHA256, 0);
    if(ssh2_wcng.hAlgHashSHA384)
        (void)BCryptCloseAlgorithmProvider(ssh2_wcng.hAlgHashSHA384, 0);
    if(ssh2_wcng.hAlgHashSHA512)
        (void)BCryptCloseAlgorithmProvider(ssh2_wcng.hAlgHashSHA512, 0);
#if LIBSSH2_MD5
    if(ssh2_wcng.hAlgHmacMD5)
        (void)BCryptCloseAlgorithmProvider(ssh2_wcng.hAlgHmacMD5, 0);
#endif
    if(ssh2_wcng.hAlgHmacSHA1)
        (void)BCryptCloseAlgorithmProvider(ssh2_wcng.hAlgHmacSHA1, 0);
    if(ssh2_wcng.hAlgHmacSHA256)
        (void)BCryptCloseAlgorithmProvider(ssh2_wcng.hAlgHmacSHA256, 0);
    if(ssh2_wcng.hAlgHmacSHA384)
        (void)BCryptCloseAlgorithmProvider(ssh2_wcng.hAlgHmacSHA384, 0);
    if(ssh2_wcng.hAlgHmacSHA512)
        (void)BCryptCloseAlgorithmProvider(ssh2_wcng.hAlgHmacSHA512, 0);
    if(ssh2_wcng.hAlgRSA)
        (void)BCryptCloseAlgorithmProvider(ssh2_wcng.hAlgRSA, 0);
#if LIBSSH2_DSA
    if(ssh2_wcng.hAlgDSA)
        (void)BCryptCloseAlgorithmProvider(ssh2_wcng.hAlgDSA, 0);
#endif
    if(ssh2_wcng.hAlgAES_CBC)
        (void)BCryptCloseAlgorithmProvider(ssh2_wcng.hAlgAES_CBC, 0);
#if LIBSSH2_RC4
    if(ssh2_wcng.hAlgRC4_NA)
        (void)BCryptCloseAlgorithmProvider(ssh2_wcng.hAlgRC4_NA, 0);
#endif
#if LIBSSH2_3DES
    if(ssh2_wcng.hAlg3DES_CBC)
        (void)BCryptCloseAlgorithmProvider(ssh2_wcng.hAlg3DES_CBC, 0);
#endif
    if(ssh2_wcng.hAlgDH)
        (void)BCryptCloseAlgorithmProvider(ssh2_wcng.hAlgDH, 0);

#if LIBSSH2_ECDSA
    for(curve = 0; curve < SSH2_ARRAYSIZE(wcng_ecdsa_algs); curve++) {
        (void)BCryptCloseAlgorithmProvider(ssh2_wcng.hAlgECDSA[curve], 0);
        (void)BCryptCloseAlgorithmProvider(ssh2_wcng.hAlgECDH[curve], 0);
    }
#endif

    memset(&ssh2_wcng, 0, sizeof(ssh2_wcng));
}

int ssh2_random(unsigned char *buf, size_t len)
{
    int ret;

    if(len > ULONG_MAX) {
        return -1;
    }

    ret = BCryptGenRandom(ssh2_wcng.hAlgRNG, buf, (ULONG)len, 0);

    return BCRYPT_SUCCESS(ret) ? 0 : -1;
}

/*******************************************************************/
/*
 * Windows CNG backend: Hash functions
 */

int ssh2_wcng_hash_init(struct wcng_hash_ctx *ctx, BCRYPT_ALG_HANDLE hAlg,
                        ULONG hashlen, unsigned char *key, ULONG keylen)
{
    BCRYPT_HASH_HANDLE hHash;
    unsigned char *pbHashObject;
    ULONG dwHashObject, dwHash, cbData;
    int ret;

    ret = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH,
                            (unsigned char *)&dwHash,
                            sizeof(dwHash),
                            &cbData, 0);
    if(!BCRYPT_SUCCESS(ret) || dwHash != hashlen) {
        return -1;
    }

    ret = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
                            (unsigned char *)&dwHashObject,
                            sizeof(dwHashObject),
                            &cbData, 0);
    if(!BCRYPT_SUCCESS(ret)) {
        return -1;
    }

    pbHashObject = malloc(dwHashObject);
    if(!pbHashObject) {
        return -1;
    }

    ret = BCryptCreateHash(hAlg, &hHash,
                           pbHashObject, dwHashObject,
                           key, keylen, 0);
    if(!BCRYPT_SUCCESS(ret)) {
        wcng_safe_free(pbHashObject, dwHashObject);
        return -1;
    }

    ctx->hHash = hHash;
    ctx->pbHashObject = pbHashObject;
    ctx->dwHashObject = dwHashObject;
    ctx->cbHash = dwHash;

    return 0;
}

int ssh2_wcng_hash_update(struct wcng_hash_ctx *ctx,
                          const void *data, ULONG datalen)
{
    int ret;

    ret = BCryptHashData(ctx->hHash,
                         (PUCHAR)SSH2_UNCONST(data), datalen, 0);

    return BCRYPT_SUCCESS(ret) ? 0 : -1;
}

int ssh2_wcng_hash_final(struct wcng_hash_ctx *ctx, unsigned char *hash)
{
    int ret;

    ret = BCryptFinishHash(ctx->hHash, hash, ctx->cbHash, 0);

    BCryptDestroyHash(ctx->hHash);
    ctx->hHash = NULL;

    wcng_safe_free(ctx->pbHashObject, ctx->dwHashObject);
    ctx->pbHashObject = NULL;
    ctx->dwHashObject = 0;

    return BCRYPT_SUCCESS(ret) ? 0 : -1;
}

int ssh2_wcng_hash(const unsigned char *data, ULONG datalen,
                   BCRYPT_ALG_HANDLE hAlg, unsigned char *hash, ULONG hashlen)
{
    struct wcng_hash_ctx ctx;
    int ret;

    ret = ssh2_wcng_hash_init(&ctx, hAlg, hashlen, NULL, 0);
    if(!ret) {
        ret = ssh2_wcng_hash_update(&ctx, data, datalen);
        ret |= ssh2_wcng_hash_final(&ctx, hash);
    }

    return ret;
}

/*******************************************************************/
/*
 * Windows CNG backend: HMAC functions
 */

int ssh2_hmac_ctx_init(ssh2_hmac_ctx *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    return 1;
}

#if LIBSSH2_MD5
int ssh2_hmac_md5_init(ssh2_hmac_ctx *ctx, void *key, size_t keylen)
{
    int ret = ssh2_wcng_hash_init(ctx, ssh2_wcng.hAlgHmacMD5,
                                  MD5_DIGEST_LENGTH, key, (ULONG)keylen);

    return ret == 0 ? 1 : 0;
}
#endif

int ssh2_hmac_sha1_init(ssh2_hmac_ctx *ctx, void *key, size_t keylen)
{
    int ret = ssh2_wcng_hash_init(ctx, ssh2_wcng.hAlgHmacSHA1,
                                  SHA_DIGEST_LENGTH, key, (ULONG)keylen);

    return ret == 0 ? 1 : 0;
}

int ssh2_hmac_sha256_init(ssh2_hmac_ctx *ctx, void *key, size_t keylen)
{
    int ret = ssh2_wcng_hash_init(ctx, ssh2_wcng.hAlgHmacSHA256,
                                  SHA256_DIGEST_LENGTH, key, (ULONG)keylen);

    return ret == 0 ? 1 : 0;
}

int ssh2_hmac_sha512_init(ssh2_hmac_ctx *ctx, void *key, size_t keylen)
{
    int ret = ssh2_wcng_hash_init(ctx, ssh2_wcng.hAlgHmacSHA512,
                                  SHA512_DIGEST_LENGTH, key, (ULONG)keylen);

    return ret == 0 ? 1 : 0;
}

int ssh2_hmac_update(ssh2_hmac_ctx *ctx, const void *data, size_t datalen)
{
    int ret = ssh2_wcng_hash_update(ctx, data, (ULONG)datalen);

    return ret == 0 ? 1 : 0;
}

int ssh2_hmac_final(ssh2_hmac_ctx *ctx, void *data)
{
    int ret = BCryptFinishHash(ctx->hHash, data, ctx->cbHash, 0);

    return BCRYPT_SUCCESS(ret) ? 1 : 0;
}

void ssh2_hmac_cleanup(ssh2_hmac_ctx *ctx)
{
    BCryptDestroyHash(ctx->hHash);
    ctx->hHash = NULL;

    wcng_safe_free(ctx->pbHashObject, ctx->dwHashObject);
    ctx->pbHashObject = NULL;
    ctx->dwHashObject = 0;
}

/*******************************************************************/
/*
 * Windows CNG backend: Key functions
 */

#if LIBSSH2_RSA || LIBSSH2_DSA
static int wcng_key_sha_verify(struct wcng_key_ctx *ctx,
                               ULONG hashlen,
                               const unsigned char *sig,
                               ULONG sig_len,
                               const unsigned char *m,
                               ULONG m_len,
                               ULONG flags)
{
    BCRYPT_PKCS1_PADDING_INFO paddingInfoPKCS1;
    BCRYPT_ALG_HANDLE hAlgHash;
    void *pPaddingInfo;
    unsigned char *data, *hash;
    ULONG datalen;
    int ret;

    if(hashlen == SHA_DIGEST_LENGTH) {
        hAlgHash = ssh2_wcng.hAlgHashSHA1;
        paddingInfoPKCS1.pszAlgId = BCRYPT_SHA1_ALGORITHM;
    }
    else if(hashlen == SHA256_DIGEST_LENGTH) {
        hAlgHash = ssh2_wcng.hAlgHashSHA256;
        paddingInfoPKCS1.pszAlgId = BCRYPT_SHA256_ALGORITHM;
    }
    else if(hashlen == SHA384_DIGEST_LENGTH) {
        hAlgHash = ssh2_wcng.hAlgHashSHA384;
        paddingInfoPKCS1.pszAlgId = BCRYPT_SHA384_ALGORITHM;
    }
    else if(hashlen == SHA512_DIGEST_LENGTH) {
        hAlgHash = ssh2_wcng.hAlgHashSHA512;
        paddingInfoPKCS1.pszAlgId = BCRYPT_SHA512_ALGORITHM;
    }
    else {
        return -1;
    }

    datalen = m_len;
    data = malloc(datalen);
    if(!data) {
        return -1;
    }

    hash = malloc(hashlen);
    if(!hash) {
        free(data);
        return -1;
    }
    memcpy(data, m, datalen);

    ret = ssh2_wcng_hash(data, datalen, hAlgHash, hash, hashlen);
    wcng_safe_free(data, datalen);

    if(ret) {
        wcng_safe_free(hash, hashlen);
        return -1;
    }

    datalen = sig_len;
    data = malloc(datalen);
    if(!data) {
        wcng_safe_free(hash, hashlen);
        return -1;
    }

    if(flags & BCRYPT_PAD_PKCS1) {
        pPaddingInfo = &paddingInfoPKCS1;
    }
    else
        pPaddingInfo = NULL;

    memcpy(data, sig, datalen);

    ret = BCryptVerifySignature(ctx->hKey, pPaddingInfo,
                                hash, hashlen, data, datalen, flags);

    wcng_safe_free(hash, hashlen);
    wcng_safe_free(data, datalen);

    return BCRYPT_SUCCESS(ret) ? 0 : -1;
}

static int wcng_load_pem(LIBSSH2_SESSION *session,
                         const char *filename,
                         const unsigned char *passphrase,
                         const char *headerbegin,
                         const char *headerend,
                         unsigned char **data,
                         size_t *datalen)
{
    FILE *fp;
    int ret;

    fp = fopen(filename, "rb");
    if(!fp) {
        return -1;
    }

    ret = ssh2_pem_parse(session, headerbegin, headerend,
                         passphrase,
                         fp, data, datalen);

    fclose(fp);

    return ret;
}

static int wcng_load_private(LIBSSH2_SESSION *session,
                             const char *filename,
                             const unsigned char *passphrase,
                             unsigned char **ppbEncoded,
                             size_t *pcbEncoded,
                             int tryLoadRSA, int tryLoadDSA)
{
    unsigned char *data = NULL;
    size_t datalen = 0;
    int ret = -1;

#if LIBSSH2_RSA
    if(ret && tryLoadRSA) {
        ret = wcng_load_pem(session, filename, passphrase,
                            PEM_RSA_HEADER, PEM_RSA_FOOTER,
                            &data, &datalen);
    }
#else
   (void)tryLoadRSA;
#endif

#if LIBSSH2_DSA
    if(ret && tryLoadDSA) {
        ret = wcng_load_pem(session, filename, passphrase,
                            PEM_DSA_HEADER, PEM_DSA_FOOTER,
                            &data, &datalen);
    }
#else
   (void)tryLoadDSA;
#endif

    if(!ret) {
        *ppbEncoded = data;
        *pcbEncoded = datalen;
    }

    return ret;
}

static int wcng_load_private_memory(LIBSSH2_SESSION *session,
                                    const char *privatekeydata,
                                    size_t privatekeydata_len,
                                    const unsigned char *passphrase,
                                    unsigned char **ppbEncoded,
                                    size_t *pcbEncoded,
                                    int tryLoadRSA, int tryLoadDSA)
{
    unsigned char *data = NULL;
    size_t datalen = 0;
    int ret = -1;

#if LIBSSH2_RSA
    if(ret && tryLoadRSA) {
        ret = ssh2_pem_parse_memory(session, PEM_RSA_HEADER, PEM_RSA_FOOTER,
                                    passphrase,
                                    privatekeydata, privatekeydata_len,
                                    &data, &datalen);
    }
#else
   (void)tryLoadRSA;
#endif

#if LIBSSH2_DSA
    if(ret && tryLoadDSA) {
        ret = ssh2_pem_parse_memory(session, PEM_DSA_HEADER, PEM_DSA_FOOTER,
                                    passphrase,
                                    privatekeydata, privatekeydata_len,
                                    &data, &datalen);
    }
#else
    (void)tryLoadDSA;
#endif

    if(!ret) {
        *ppbEncoded = data;
        *pcbEncoded = datalen;
    }

    return ret;
}

static int wcng_asn_decode(unsigned char *pbEncoded, DWORD cbEncoded,
                           LPCSTR lpszStructType,
                           unsigned char **ppbDecoded, DWORD *pcbDecoded)
{
    unsigned char *pbDecoded = NULL;
    DWORD cbDecoded = 0;
    int ret;

    ret = CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                              lpszStructType,
                              pbEncoded, cbEncoded, 0, NULL,
                              NULL, &cbDecoded);
    if(!ret) {
        return -1;
    }

    pbDecoded = malloc(cbDecoded);
    if(!pbDecoded) {
        return -1;
    }

    ret = CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                              lpszStructType,
                              pbEncoded, cbEncoded, 0, NULL,
                              pbDecoded, &cbDecoded);
    if(!ret) {
        wcng_safe_free(pbDecoded, cbDecoded);
        return -1;
    }

    *ppbDecoded = pbDecoded;
    *pcbDecoded = cbDecoded;

    return 0;
}

static int wcng_bn_ltob(unsigned char *pbInput,
                        DWORD cbInput,
                        unsigned char **ppbOutput,
                        DWORD *pcbOutput)
{
    unsigned char *pbOutput;
    DWORD cbOutput, index, offset, length;

    if(cbInput < 1) {
        return 0;
    }

    offset = 0;
    length = cbInput - 1;
    cbOutput = cbInput;
    if(pbInput[length] & (1 << 7)) {
        offset++;
        cbOutput += offset;
    }

    pbOutput = malloc(cbOutput);
    if(!pbOutput) {
        return -1;
    }

    pbOutput[0] = 0;
    for(index = 0; (index + offset) < cbOutput && index < cbInput; index++) {
        pbOutput[index + offset] = pbInput[length - index];
    }

    *ppbOutput = pbOutput;
    *pcbOutput = cbOutput;

    return 0;
}

static int wcng_asn_decode_bn(unsigned char *pbEncoded, DWORD cbEncoded,
                              unsigned char **ppbDecoded, DWORD *pcbDecoded)
{
    unsigned char *pbDecoded = NULL;
    PCRYPT_DATA_BLOB pbInteger;
    DWORD cbDecoded = 0, cbInteger;
    int ret;

    ret = wcng_asn_decode(pbEncoded, cbEncoded, X509_MULTI_BYTE_UINT,
                          (void *)&pbInteger, &cbInteger);
    if(!ret) {
        ret = wcng_bn_ltob(pbInteger->pbData,
                           pbInteger->cbData,
                           &pbDecoded, &cbDecoded);
        if(!ret) {
            *ppbDecoded = pbDecoded;
            *pcbDecoded = cbDecoded;
        }
        wcng_safe_free(pbInteger, cbInteger);
    }

    return ret;
}

static int wcng_asn_decode_bns(unsigned char *pbEncoded,
                               DWORD cbEncoded,
                               unsigned char ***prpbDecoded,
                               DWORD **prcbDecoded,
                               DWORD *pcbCount)
{
    PCRYPT_DER_BLOB pBlob;
    unsigned char **rpbDecoded;
    PCRYPT_SEQUENCE_OF_ANY pbDecoded;
    DWORD cbDecoded, *rcbDecoded, index, length;
    int ret;

    ret = wcng_asn_decode(pbEncoded, cbEncoded, X509_SEQUENCE_OF_ANY,
                          (void *)&pbDecoded, &cbDecoded);
    if(!ret) {
        length = pbDecoded->cValue;

        rpbDecoded = malloc(sizeof(PBYTE) * length);
        if(rpbDecoded) {
            rcbDecoded = malloc(sizeof(DWORD) * length);
            if(rcbDecoded) {
                for(index = 0; index < length; index++) {
                    pBlob = &pbDecoded->rgValue[index];
                    ret = wcng_asn_decode_bn(pBlob->pbData,
                                             pBlob->cbData,
                                             &rpbDecoded[index],
                                             &rcbDecoded[index]);
                    if(ret)
                        break;
                }

                if(!ret) {
                    *prpbDecoded = rpbDecoded;
                    *prcbDecoded = rcbDecoded;
                    *pcbCount = length;
                }
                else {
                    for(length = 0; length < index; length++) {
                        wcng_safe_free(rpbDecoded[length],
                                       rcbDecoded[length]);
                        rpbDecoded[length] = NULL;
                        rcbDecoded[length] = 0;
                    }
                    free(rpbDecoded);
                    free(rcbDecoded);
                }
            }
            else {
                free(rpbDecoded);
                ret = -1;
            }
        }
        else {
            ret = -1;
        }

        wcng_safe_free(pbDecoded, cbDecoded);
    }

    return ret;
}

static ULONG wcng_bn_size(const unsigned char *bignum, ULONG length)
{
    ULONG offset;

    if(!bignum || length == 0)
        return 0;

    length--;

    offset = 0;
    while(!*(bignum + offset) && offset < length)
        offset++;

    length++;

    return length - offset;
}
#endif /* LIBSSH2_RSA || LIBSSH2_DSA */

#if LIBSSH2_RSA
/*******************************************************************/
/*
 * Windows CNG backend: RSA functions
 */

int ssh2_rsa_new(ssh2_rsa_ctx **rsa,
                 const unsigned char *edata, unsigned long elen,
                 const unsigned char *ndata, unsigned long nlen,
                 const unsigned char *ddata, unsigned long dlen,
                 const unsigned char *pdata, unsigned long plen,
                 const unsigned char *qdata, unsigned long qlen,
                 const unsigned char *e1data, unsigned long e1len,
                 const unsigned char *e2data, unsigned long e2len,
                 const unsigned char *coeffdata,
                 unsigned long coefflen)
{
    BCRYPT_KEY_HANDLE hKey;
    BCRYPT_RSAKEY_BLOB *rsakey;
    LPCWSTR lpszBlobType;
    ULONG keylen, offset, mlen, p1len = 0, p2len = 0;
    int ret;

    mlen = max(wcng_bn_size(ndata, nlen),
               wcng_bn_size(ddata, dlen));
    offset = sizeof(BCRYPT_RSAKEY_BLOB);
    keylen = offset + elen + mlen;
    if(ddata && dlen > 0) {
        p1len = max(wcng_bn_size(pdata, plen),
                    wcng_bn_size(e1data, e1len));
        p2len = max(wcng_bn_size(qdata, qlen),
                    wcng_bn_size(e2data, e2len));
        keylen += p1len * 3 + p2len * 2 + mlen;
    }

    rsakey = malloc(keylen);
    if(!rsakey) {
        return -1;
    }

    memset(rsakey, 0, keylen);

    /* https://learn.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob */
    rsakey->BitLength = mlen * 8;
    rsakey->cbPublicExp = elen;
    rsakey->cbModulus = mlen;

    memcpy((unsigned char *)rsakey + offset, edata, elen);
    offset += elen;

    if(nlen < mlen)
        memcpy((unsigned char *)rsakey + offset + mlen - nlen, ndata, nlen);
    else
        memcpy((unsigned char *)rsakey + offset, ndata + nlen - mlen, mlen);

    if(ddata && dlen > 0) {
        offset += mlen;

        if(plen < p1len)
            memcpy((unsigned char *)rsakey + offset + p1len - plen,
                   pdata, plen);
        else
            memcpy((unsigned char *)rsakey + offset,
                   pdata + plen - p1len, p1len);
        offset += p1len;

        if(qlen < p2len)
            memcpy((unsigned char *)rsakey + offset + p2len - qlen,
                   qdata, qlen);
        else
            memcpy((unsigned char *)rsakey + offset,
                   qdata + qlen - p2len, p2len);
        offset += p2len;

        if(e1len < p1len)
            memcpy((unsigned char *)rsakey + offset + p1len - e1len,
                   e1data, e1len);
        else
            memcpy((unsigned char *)rsakey + offset,
                   e1data + e1len - p1len, p1len);
        offset += p1len;

        if(e2len < p2len)
            memcpy((unsigned char *)rsakey + offset + p2len - e2len,
                   e2data, e2len);
        else
            memcpy((unsigned char *)rsakey + offset,
                   e2data + e2len - p2len, p2len);
        offset += p2len;

        if(coefflen < p1len)
            memcpy((unsigned char *)rsakey + offset + p1len - coefflen,
                   coeffdata, coefflen);
        else
            memcpy((unsigned char *)rsakey + offset,
                   coeffdata + coefflen - p1len, p1len);
        offset += p1len;

        if(dlen < mlen)
            memcpy((unsigned char *)rsakey + offset + mlen - dlen,
                   ddata, dlen);
        else
            memcpy((unsigned char *)rsakey + offset,
                   ddata + dlen - mlen, mlen);

        lpszBlobType = BCRYPT_RSAFULLPRIVATE_BLOB;
        rsakey->Magic = BCRYPT_RSAFULLPRIVATE_MAGIC;
        rsakey->cbPrime1 = p1len;
        rsakey->cbPrime2 = p2len;
    }
    else {
        lpszBlobType = BCRYPT_RSAPUBLIC_BLOB;
        rsakey->Magic = BCRYPT_RSAPUBLIC_MAGIC;
        rsakey->cbPrime1 = 0;
        rsakey->cbPrime2 = 0;
    }

    ret = BCryptImportKeyPair(ssh2_wcng.hAlgRSA, NULL, lpszBlobType,
                              &hKey, (PUCHAR)rsakey, keylen, 0);
    if(!BCRYPT_SUCCESS(ret)) {
        wcng_safe_free(rsakey, keylen);
        return -1;
    }

    *rsa = malloc(sizeof(ssh2_rsa_ctx));
    if(!(*rsa)) {
        BCryptDestroyKey(hKey);
        wcng_safe_free(rsakey, keylen);
        return -1;
    }

    (*rsa)->hKey = hKey;
    (*rsa)->pbKeyObject = rsakey;
    (*rsa)->cbKeyObject = keylen;

    return 0;
}

static int wcng_rsa_new_private_parse(ssh2_rsa_ctx **rsa,
                                      LIBSSH2_SESSION *session,
                                      unsigned char *pbEncoded,
                                      size_t cbEncoded)
{
    BCRYPT_KEY_HANDLE hKey;
    unsigned char *pbStructInfo;
    DWORD cbStructInfo;
    int ret;

    (void)session;

    ret = wcng_asn_decode(pbEncoded, (DWORD)cbEncoded, PKCS_RSA_PRIVATE_KEY,
                          &pbStructInfo, &cbStructInfo);

    wcng_safe_free(pbEncoded, cbEncoded);

    if(ret) {
        return -1;
    }

    ret = BCryptImportKeyPair(ssh2_wcng.hAlgRSA, NULL, LEGACY_RSAPRIVATE_BLOB,
                              &hKey, pbStructInfo, cbStructInfo, 0);
    if(!BCRYPT_SUCCESS(ret)) {
        wcng_safe_free(pbStructInfo, cbStructInfo);
        return -1;
    }

    *rsa = malloc(sizeof(ssh2_rsa_ctx));
    if(!(*rsa)) {
        BCryptDestroyKey(hKey);
        wcng_safe_free(pbStructInfo, cbStructInfo);
        return -1;
    }

    (*rsa)->hKey = hKey;
    (*rsa)->pbKeyObject = pbStructInfo;
    (*rsa)->cbKeyObject = cbStructInfo;

    return 0;
}

int ssh2_rsa_new_private(ssh2_rsa_ctx **rsa,
                         LIBSSH2_SESSION *session,
                         const char *filename,
                         const unsigned char *passphrase)
{
    unsigned char *pbEncoded;
    size_t cbEncoded;
    int ret;

    ret = wcng_load_private(session, filename, passphrase,
                            &pbEncoded, &cbEncoded, 1, 0);
    if(ret) {
        return -1;
    }

    return wcng_rsa_new_private_parse(rsa, session, pbEncoded, cbEncoded);
}

int ssh2_rsa_new_private_frommemory(ssh2_rsa_ctx **rsa,
                                    LIBSSH2_SESSION *session,
                                    const char *filedata, size_t filedata_len,
                                    const unsigned char *passphrase)
{
    unsigned char *pbEncoded;
    size_t cbEncoded;
    int ret;

    ret = wcng_load_private_memory(session, filedata, filedata_len,
                                   passphrase, &pbEncoded, &cbEncoded, 1, 0);
    if(ret) {
        return -1;
    }

    return wcng_rsa_new_private_parse(rsa, session, pbEncoded, cbEncoded);
}

#if LIBSSH2_RSA_SHA1
int ssh2_rsa_sha1_verify(ssh2_rsa_ctx *rsactx,
                         const unsigned char *sig, size_t sig_len,
                         const unsigned char *m, size_t m_len)
{
    return wcng_key_sha_verify(rsactx, SHA_DIGEST_LENGTH,
                               sig, (ULONG)sig_len,
                               m, (ULONG)m_len,
                               BCRYPT_PAD_PKCS1);
}
#endif

#if LIBSSH2_RSA_SHA2
int ssh2_rsa_sha2_verify(ssh2_rsa_ctx *rsactx,
                         size_t hash_len,
                         const unsigned char *sig, size_t sig_len,
                         const unsigned char *m, size_t m_len)
{
    return wcng_key_sha_verify(rsactx, (ULONG)hash_len,
                               sig, (ULONG)sig_len,
                               m, (ULONG)m_len,
                               BCRYPT_PAD_PKCS1);
}
#endif

static int wcng_rsa_sha_sign(LIBSSH2_SESSION *session,
                             ssh2_rsa_ctx *rsa,
                             const unsigned char *hash,
                             size_t hash_len,
                             unsigned char **signature,
                             size_t *signature_len)
{
    BCRYPT_PKCS1_PADDING_INFO paddingInfo;
    unsigned char *data, *sig;
    ULONG cbData, datalen, siglen;
    NTSTATUS ret;

    if(hash_len == SHA_DIGEST_LENGTH)
        paddingInfo.pszAlgId = BCRYPT_SHA1_ALGORITHM;
    else if(hash_len == SHA256_DIGEST_LENGTH)
        paddingInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;
    else if(hash_len == SHA384_DIGEST_LENGTH)
        paddingInfo.pszAlgId = BCRYPT_SHA384_ALGORITHM;
    else if(hash_len == SHA512_DIGEST_LENGTH)
        paddingInfo.pszAlgId = BCRYPT_SHA512_ALGORITHM;
    else {
        ssh2_err(session, LIBSSH2_ERROR_PROTO,
                 "Unsupported hash digest length");
        return -1;
    }

    datalen = (ULONG)hash_len;
    data = malloc(datalen);
    if(!data) {
        return -1;
    }
    memcpy(data, hash, datalen);

    ret = BCryptSignHash(rsa->hKey, &paddingInfo,
                         data, datalen, NULL, 0,
                         &cbData, BCRYPT_PAD_PKCS1);
    if(BCRYPT_SUCCESS(ret)) {
        siglen = cbData;
        sig = SSH2_ALLOC(session, siglen);
        if(sig) {
            ret = BCryptSignHash(rsa->hKey, &paddingInfo,
                                 data, datalen, sig, siglen,
                                 &cbData, BCRYPT_PAD_PKCS1);
            if(BCRYPT_SUCCESS(ret)) {
                *signature_len = siglen;
                *signature = sig;
            }
            else {
                SSH2_FREE(session, sig);
            }
        }
        else
            ret = (NTSTATUS)STATUS_NO_MEMORY;
    }

    wcng_safe_free(data, datalen);

    return BCRYPT_SUCCESS(ret) ? 0 : -1;
}

int ssh2_rsa_sha1_sign(LIBSSH2_SESSION *session,
                       ssh2_rsa_ctx *rsactx,
                       const unsigned char *hash, size_t hash_len,
                       unsigned char **signature, size_t *signature_len)
{
    return wcng_rsa_sha_sign(session, rsactx,
                             hash, hash_len,
                             signature, signature_len);
}

int ssh2_rsa_sha2_sign(LIBSSH2_SESSION *session,
                       ssh2_rsa_ctx *rsactx,
                       const unsigned char *hash, size_t hash_len,
                       unsigned char **signature, size_t *signature_len)
{
    return wcng_rsa_sha_sign(session, rsactx,
                             hash, hash_len,
                             signature, signature_len);
}

void ssh2_rsa_free(ssh2_rsa_ctx *rsa)
{
    if(!rsa)
        return;

    BCryptDestroyKey(rsa->hKey);
    rsa->hKey = NULL;

    wcng_safe_free(rsa->pbKeyObject, rsa->cbKeyObject);
    wcng_safe_free(rsa, sizeof(ssh2_rsa_ctx));
}
#endif

/*******************************************************************/
/*
 * Windows CNG backend: DSA functions
 */

#if LIBSSH2_DSA
int ssh2_dsa_new(ssh2_dsa_ctx **dsa,
                 const unsigned char *pdata, unsigned long plen,
                 const unsigned char *qdata, unsigned long qlen,
                 const unsigned char *gdata, unsigned long glen,
                 const unsigned char *ydata, unsigned long ylen,
                 const unsigned char *xdata, unsigned long xlen)
{
    BCRYPT_KEY_HANDLE hKey;
    BCRYPT_DSA_KEY_BLOB *dsakey;
    LPCWSTR lpszBlobType;
    ULONG keylen, offset, length;
    int ret;

    length = max(max(wcng_bn_size(pdata, plen),
                     wcng_bn_size(gdata, glen)),
                 wcng_bn_size(ydata, ylen));
    offset = sizeof(BCRYPT_DSA_KEY_BLOB);
    keylen = offset + length * 3;
    if(xdata && xlen > 0)
        keylen += 20;

    dsakey = malloc(keylen);
    if(!dsakey) {
        return -1;
    }

    memset(dsakey, 0, keylen);

    /* https://learn.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_dsa_key_blob */
    dsakey->cbKey = length;

    memset(dsakey->Count, -1, sizeof(dsakey->Count));
    memset(dsakey->Seed, -1, sizeof(dsakey->Seed));

    if(qlen < 20)
        memcpy(dsakey->q + 20 - qlen, qdata, qlen);
    else
        memcpy(dsakey->q, qdata + qlen - 20, 20);

    if(plen < length)
        memcpy((unsigned char *)dsakey + offset + length - plen,
               pdata, plen);
    else
        memcpy((unsigned char *)dsakey + offset,
               pdata + plen - length, length);
    offset += length;

    if(glen < length)
        memcpy((unsigned char *)dsakey + offset + length - glen,
               gdata, glen);
    else
        memcpy((unsigned char *)dsakey + offset,
               gdata + glen - length, length);
    offset += length;

    if(ylen < length)
        memcpy((unsigned char *)dsakey + offset + length - ylen,
               ydata, ylen);
    else
        memcpy((unsigned char *)dsakey + offset,
               ydata + ylen - length, length);

    if(xdata && xlen > 0) {
        offset += length;

        if(xlen < 20)
            memcpy((unsigned char *)dsakey + offset + 20 - xlen, xdata, xlen);
        else
            memcpy((unsigned char *)dsakey + offset, xdata + xlen - 20, 20);

        lpszBlobType = BCRYPT_DSA_PRIVATE_BLOB;
        dsakey->dwMagic = BCRYPT_DSA_PRIVATE_MAGIC;
    }
    else {
        lpszBlobType = BCRYPT_DSA_PUBLIC_BLOB;
        dsakey->dwMagic = BCRYPT_DSA_PUBLIC_MAGIC;
    }

    ret = BCryptImportKeyPair(ssh2_wcng.hAlgDSA, NULL, lpszBlobType,
                              &hKey, (PUCHAR)dsakey, keylen, 0);
    if(!BCRYPT_SUCCESS(ret)) {
        wcng_safe_free(dsakey, keylen);
        return -1;
    }

    *dsa = malloc(sizeof(ssh2_dsa_ctx));
    if(!(*dsa)) {
        BCryptDestroyKey(hKey);
        wcng_safe_free(dsakey, keylen);
        return -1;
    }

    (*dsa)->hKey = hKey;
    (*dsa)->pbKeyObject = dsakey;
    (*dsa)->cbKeyObject = keylen;

    return 0;
}

static int wcng_dsa_new_private_parse(ssh2_dsa_ctx **dsa,
                                      LIBSSH2_SESSION *session,
                                      unsigned char *pbEncoded,
                                      size_t cbEncoded)
{
    unsigned char **rpbDecoded;
    DWORD *rcbDecoded, index, length;
    int ret;

    (void)session;

    ret = wcng_asn_decode_bns(pbEncoded, (DWORD)cbEncoded,
                              &rpbDecoded, &rcbDecoded, &length);

    wcng_safe_free(pbEncoded, cbEncoded);

    if(ret) {
        return -1;
    }

    if(length == 6) {
        ret = ssh2_dsa_new(dsa,
                           rpbDecoded[1], rcbDecoded[1],
                           rpbDecoded[2], rcbDecoded[2],
                           rpbDecoded[3], rcbDecoded[3],
                           rpbDecoded[4], rcbDecoded[4],
                           rpbDecoded[5], rcbDecoded[5]);
    }
    else {
        ret = -1;
    }

    for(index = 0; index < length; index++) {
        wcng_safe_free(rpbDecoded[index], rcbDecoded[index]);
        rpbDecoded[index] = NULL;
        rcbDecoded[index] = 0;
    }

    free(rpbDecoded);
    free(rcbDecoded);

    return ret;
}

int ssh2_dsa_new_private(ssh2_dsa_ctx **dsa,
                         LIBSSH2_SESSION *session,
                         const char *filename,
                         const unsigned char *passphrase)
{
    unsigned char *pbEncoded;
    size_t cbEncoded;
    int ret;

    ret = wcng_load_private(session, filename, passphrase,
                            &pbEncoded, &cbEncoded, 0, 1);
    if(ret) {
        return -1;
    }

    return wcng_dsa_new_private_parse(dsa, session, pbEncoded, cbEncoded);
}

int ssh2_dsa_new_private_frommemory(ssh2_dsa_ctx **dsa,
                                    LIBSSH2_SESSION *session,
                                    const char *filedata, size_t filedata_len,
                                    const unsigned char *passphrase)
{
    unsigned char *pbEncoded;
    size_t cbEncoded;
    int ret;

    ret = wcng_load_private_memory(session, filedata, filedata_len,
                                   passphrase, &pbEncoded, &cbEncoded, 0, 1);
    if(ret) {
        return -1;
    }

    return wcng_dsa_new_private_parse(dsa, session, pbEncoded, cbEncoded);
}

int ssh2_dsa_sha1_verify(ssh2_dsa_ctx *dsa,
                         const unsigned char *sig_fixed,
                         const unsigned char *m, size_t m_len)
{
    return wcng_key_sha_verify(dsa, SHA_DIGEST_LENGTH, sig_fixed,
                               40, m, (ULONG)m_len, 0);
}

int ssh2_dsa_sha1_sign(ssh2_dsa_ctx *dsa,
                       const unsigned char *hash, size_t hash_len,
                       unsigned char *sig_fixed)
{
    unsigned char *data, *sig;
    ULONG cbData, datalen, siglen;
    NTSTATUS ret;

    datalen = (ULONG)hash_len;
    data = malloc(datalen);
    if(!data) {
        return -1;
    }

    memcpy(data, hash, datalen);

    ret = BCryptSignHash(dsa->hKey, NULL, data, datalen,
                         NULL, 0, &cbData, 0);
    if(BCRYPT_SUCCESS(ret)) {
        siglen = cbData;
        if(siglen == 40) {
            sig = malloc(siglen);
            if(sig) {
                ret = BCryptSignHash(dsa->hKey, NULL, data, datalen,
                                     sig, siglen, &cbData, 0);
                if(BCRYPT_SUCCESS(ret)) {
                    memcpy(sig_fixed, sig, siglen);
                }

                wcng_safe_free(sig, siglen);
            }
            else
                ret = (NTSTATUS)STATUS_NO_MEMORY;
        }
        else
            ret = (NTSTATUS)STATUS_NO_MEMORY;
    }

    wcng_safe_free(data, datalen);

    return BCRYPT_SUCCESS(ret) ? 0 : -1;
}

void ssh2_dsa_free(ssh2_dsa_ctx *dsa)
{
    if(!dsa)
        return;

    BCryptDestroyKey(dsa->hKey);
    dsa->hKey = NULL;

    wcng_safe_free(dsa->pbKeyObject, dsa->cbKeyObject);
    wcng_safe_free(dsa, sizeof(ssh2_dsa_ctx));
}
#endif

/*******************************************************************/
/*
 * Windows CNG backend: ECDSA helper functions
 */

#if LIBSSH2_ECDSA

/*
 * Decode an uncompressed point.
 */
static int wcng_ecdsa_decode_uncompressed_point(
    IN const unsigned char *encoded_point,
    IN size_t encoded_point_len,
    OUT struct ecdsa_point *point)
{
    unsigned int curve;

    if(!point) {
        return LIBSSH2_ERROR_INVAL;
    }

    /* Verify that the point uses uncompressed format */
    if(encoded_point_len == 0 || encoded_point[0] != 4) {
        return LIBSSH2_ERROR_INVAL;
    }

    for(curve = 0; curve < SSH2_ARRAYSIZE(wcng_ecdsa_algs); curve++) {
        if(wcng_ecdsa_algs[curve].point_length ==
           (encoded_point_len - 1) / 2) {

            point->curve = (ssh2_curve_type)curve;

            point->x = encoded_point + 1;
            point->x_len = wcng_ecdsa_algs[curve].point_length;

            point->y = point->x + point->x_len;
            point->y_len = wcng_ecdsa_algs[curve].point_length;

            return LIBSSH2_ERROR_NONE;
        }
    }

    return LIBSSH2_ERROR_INVAL;
}

/*
 * Create a IEEE P-1363 signature from a point.
 *
 * The IEEE P-1363 format is defined as r || s,
 * where r and s are of the same length.
 */
static int wcng_p1363signature_from_point(IN const unsigned char *r,
                                          IN size_t r_len,
                                          IN const unsigned char *s,
                                          IN size_t s_len,
                                          IN ssh2_curve_type curve,
                                          OUT PUCHAR *signature,
                                          OUT size_t *signature_length)
{
    const unsigned char *r_trimmed;
    const unsigned char *s_trimmed;
    size_t r_trimmed_len;
    size_t s_trimmed_len;

    /* Validate parameters */
    if(curve >= SSH2_ARRAYSIZE(wcng_ecdsa_algs)) {
        return LIBSSH2_ERROR_INVAL;
    }

    *signature = NULL;
    *signature_length = (size_t)wcng_ecdsa_algs[curve].point_length * 2;

    /* Trim leading zero, if any */
    r_trimmed = r;
    r_trimmed_len = r_len;
    if(r_len > 0 && r[0] == '\0') {
        r_trimmed++;
        r_trimmed_len--;
    }

    s_trimmed = s;
    s_trimmed_len = s_len;
    if(s_len > 0 && s[0] == '\0') {
        s_trimmed++;
        s_trimmed_len--;
    }

    /* Validate r and s fits into signature */
    if(r_trimmed_len > *signature_length / 2 ||
       s_trimmed_len > *signature_length / 2) {
        return LIBSSH2_ERROR_INVAL;
    }

    /* Concatenate into zero-filled buffer and zero-pad if necessary */
    *signature = calloc(1, *signature_length);
    if(!*signature) {
        return LIBSSH2_ERROR_ALLOC;
    }

    memcpy(*signature + (*signature_length / 2) - r_trimmed_len,
           r_trimmed, r_trimmed_len);
    memcpy(*signature + (*signature_length) - s_trimmed_len,
           s_trimmed, s_trimmed_len);

    return LIBSSH2_ERROR_NONE;
}

/*
 * Create a CNG public key from an ECC point.
 */
static int wcng_publickey_from_point(IN wcng_ecc_keytype keytype,
                                     IN struct ecdsa_point *point,
                                     OUT BCRYPT_KEY_HANDLE *key)
{
    int result = LIBSSH2_ERROR_NONE;
    NTSTATUS status;

    PBCRYPT_ECCKEY_BLOB ecc_blob;
    size_t ecc_blob_len;

    /* Validate parameters */
    if(!key) {
        return LIBSSH2_ERROR_INVAL;
    }

    if(point->x_len != point->y_len) {
        return LIBSSH2_ERROR_INVAL;
    }

    *key = NULL;

    /* Initialize a blob to import */
    ecc_blob_len = sizeof(BCRYPT_ECCKEY_BLOB) + point->x_len + point->y_len;
    ecc_blob = malloc(ecc_blob_len);
    if(!ecc_blob) {
        return LIBSSH2_ERROR_ALLOC;
    }

    ecc_blob->cbKey = point->x_len;
    ecc_blob->dwMagic =
        wcng_ecdsa_algs[point->curve].public_import_magic[keytype];

    /** Copy x, y */
    memcpy((char *)ecc_blob + sizeof(BCRYPT_ECCKEY_BLOB),
           point->x, point->x_len);
    memcpy((char *)ecc_blob + sizeof(BCRYPT_ECCKEY_BLOB) + point->x_len,
           point->y, point->y_len);

    status = BCryptImportKeyPair(
        keytype == WCNG_ECC_KEYTYPE_ECDSA
            ? ssh2_wcng.hAlgECDSA[point->curve]
            : ssh2_wcng.hAlgECDH[point->curve],
        NULL,
        BCRYPT_ECCPUBLIC_BLOB,
        key,
        (PUCHAR)ecc_blob,
        (ULONG)ecc_blob_len,
        0);
    if(!BCRYPT_SUCCESS(status)) {
        result = LIBSSH2_ERROR_PUBLICKEY_PROTOCOL;
        goto cleanup;
    }

    result = LIBSSH2_ERROR_NONE;

cleanup:
    free(ecc_blob);
    return result;
}

/*
 * Create a CNG private key from an ECC point.
 */
static int wcng_privatekey_from_point(IN wcng_ecc_keytype keytype,
                                      IN struct ecdsa_point *q,
                                      IN unsigned char *d,
                                      IN size_t d_len,
                                      OUT BCRYPT_KEY_HANDLE *key)
{
    int result = LIBSSH2_ERROR_NONE;
    NTSTATUS status;

    PBCRYPT_ECCKEY_BLOB ecc_blob;
    size_t ecc_blob_len;

    /* Validate parameters */
    if(!key) {
        return LIBSSH2_ERROR_INVAL;
    }

    if(q->x_len != q->y_len) {
        return LIBSSH2_ERROR_INVAL;
    }

    *key = NULL;

    /* Initialize a blob to import */
    ecc_blob_len =
        sizeof(BCRYPT_ECCPRIVATE_BLOB) + q->x_len + q->y_len + d_len;
    ecc_blob = malloc(ecc_blob_len);
    if(!ecc_blob) {
        return LIBSSH2_ERROR_ALLOC;
    }

    ecc_blob->cbKey = q->x_len;
    ecc_blob->dwMagic =
        wcng_ecdsa_algs[q->curve].private_import_magic[keytype];

    /* Copy x, y, d */
    memcpy((char *)ecc_blob + sizeof(BCRYPT_ECCKEY_BLOB),
           q->x, q->x_len);
    memcpy((char *)ecc_blob + sizeof(BCRYPT_ECCKEY_BLOB) + q->x_len,
           q->y, q->y_len);
    memcpy((char *)ecc_blob + sizeof(BCRYPT_ECCKEY_BLOB) + q->x_len + q->y_len,
           d, d_len);

    status = BCryptImportKeyPair(
        keytype == WCNG_ECC_KEYTYPE_ECDSA
            ? ssh2_wcng.hAlgECDSA[q->curve]
            : ssh2_wcng.hAlgECDH[q->curve],
        NULL,
        BCRYPT_ECCPRIVATE_BLOB,
        key,
        (PUCHAR)ecc_blob,
        (ULONG)ecc_blob_len,
        0);
    if(!BCRYPT_SUCCESS(status)) {
        result = LIBSSH2_ERROR_PUBLICKEY_PROTOCOL;
        goto cleanup;
    }

    result = LIBSSH2_ERROR_NONE;

cleanup:
    free(ecc_blob);
    return result;
}

/*
 * Get the uncompressed point encoding for a CNG key.
 */
static int wcng_uncompressed_point_from_publickey(
    IN LIBSSH2_SESSION *session,
    IN ssh2_curve_type curve,
    IN BCRYPT_KEY_HANDLE key,
    OUT PUCHAR *encoded_point,
    OUT size_t *encoded_point_len)
{
    int result = LIBSSH2_ERROR_NONE;
    NTSTATUS status;

    PBCRYPT_ECCKEY_BLOB ecc_blob = NULL;
    ULONG ecc_blob_len;
    PUCHAR point_x;
    PUCHAR point_y;

    /* Validate parameters */
    if(curve >= SSH2_ARRAYSIZE(wcng_ecdsa_algs)) {
        return LIBSSH2_ERROR_INVAL;
    }

    if(!encoded_point || !encoded_point_len) {
        return LIBSSH2_ERROR_INVAL;
    }

    *encoded_point = NULL;
    *encoded_point_len = 0;

    /*
     * Export point as BCRYPT_ECCKEY_BLOB, a dynamically-sized structure.
     */
    status = BCryptExportKey(key,
        NULL,
        BCRYPT_ECCPUBLIC_BLOB,
        NULL,
        0,
        &ecc_blob_len,
        0);
    if(BCRYPT_SUCCESS(status) && ecc_blob_len > 0) {
        ecc_blob = SSH2_ALLOC(session, ecc_blob_len);
        if(!ecc_blob) {
            result = LIBSSH2_ERROR_ALLOC;
            goto cleanup;
        }

        status = BCryptExportKey(key,
            NULL,
            BCRYPT_ECCPUBLIC_BLOB,
            (PUCHAR)ecc_blob,
            ecc_blob_len,
            &ecc_blob_len,
            0);
    }

    if(!BCRYPT_SUCCESS(status)) {
        result = ssh2_err(session, LIBSSH2_ERROR_PUBLICKEY_PROTOCOL,
                          "Decoding the ECC public key failed");
        goto cleanup;
    }

    point_x = (PUCHAR)ecc_blob + sizeof(BCRYPT_ECCKEY_BLOB);
    point_y = (PUCHAR)ecc_blob + ecc_blob->cbKey + sizeof(BCRYPT_ECCKEY_BLOB);

    /*
     * Create uncompressed point, which needs to look like the following:
     *
     * struct uncompressed_point {
     *     UCHAR tag = 4; // uncompressed
     *     PUCHAR[size] x;
     *     PUCHAR[size] y;
     * }
     */

    *encoded_point_len = (size_t)ecc_blob->cbKey * 2 + 1;
    *encoded_point = SSH2_ALLOC(session, *encoded_point_len);
    if(!*encoded_point) {
        result = LIBSSH2_ERROR_ALLOC;
        goto cleanup;
    }

    **encoded_point = 4; /* Uncompressed tag */
    memcpy((*encoded_point) + 1, point_x, ecc_blob->cbKey);
    memcpy((*encoded_point) + 1 + ecc_blob->cbKey, point_y, ecc_blob->cbKey);

cleanup:
    if(ecc_blob) {
        SSH2_FREE(session, ecc_blob);
    }

    return result;
}

/*******************************************************************/
/*
 * Windows CNG backend: ECDSA functions
 */
void ssh2_ecdsa_free(ssh2_ecdsa_ctx *ctx)
{
    if(!ctx) {
        return;
    }

    (void)BCryptDestroyKey(ctx->handle);
    free(ctx);
}

/*
 * Creates a local private ECDH key based on input curve
 * and returns the public key in uncompressed point encoding.
 */
int ssh2_ecdsa_create_key(IN LIBSSH2_SESSION *session,
                          OUT struct wcng_ecdsa_ctx **privatekey,
                          OUT unsigned char **encoded_publickey,
                          OUT size_t *encoded_publickey_len,
                          IN ssh2_curve_type curve)
{
    int result = LIBSSH2_ERROR_NONE;
    NTSTATUS status;

    BCRYPT_KEY_HANDLE key_handle = NULL;

    /* Validate parameters */
    if(curve >= SSH2_ARRAYSIZE(wcng_ecdsa_algs)) {
        return LIBSSH2_ERROR_INVAL;
    }

    if(!ssh2_wcng.hAlgECDH[curve]) {
        return LIBSSH2_ERROR_INVAL;
    }

    if(!privatekey || !encoded_publickey || !encoded_publickey_len) {
        return LIBSSH2_ERROR_INVAL;
    }

    *privatekey = NULL;
    *encoded_publickey = NULL;
    *encoded_publickey_len = 0;

    /* Create an ECDH key pair using the requested curve */
    status = BCryptGenerateKeyPair(
        ssh2_wcng.hAlgECDH[curve],
        &key_handle,
        wcng_ecdsa_algs[curve].key_length,
        0);
    if(!BCRYPT_SUCCESS(status)) {
        result = ssh2_err(session, LIBSSH2_ERROR_PUBLICKEY_PROTOCOL,
                          "Creating ECC key pair failed");
        goto cleanup;
    }

    status = BCryptFinalizeKeyPair(key_handle, 0);
    if(!BCRYPT_SUCCESS(status)) {
        result = ssh2_err(session, LIBSSH2_ERROR_PUBLICKEY_PROTOCOL,
                          "Creating ECDH key pair failed");
        goto cleanup;
    }

    result = wcng_uncompressed_point_from_publickey(
        session,
        curve,
        key_handle,
        encoded_publickey,
        encoded_publickey_len);
    if(result != LIBSSH2_ERROR_NONE) {
        result = ssh2_err(session, LIBSSH2_ERROR_PUBLICKEY_PROTOCOL,
                          "Exporting ECDH key pair failed");
    }

    *privatekey = malloc(sizeof(struct wcng_ecdsa_ctx));
    if(!*privatekey) {
        result = LIBSSH2_ERROR_ALLOC;
        goto cleanup;
    }

    (*privatekey)->curve = curve;
    (*privatekey)->handle = key_handle;

cleanup:
    if(result != LIBSSH2_ERROR_NONE && key_handle) {
        (void)BCryptDestroyKey(key_handle);
    }

    if(result != LIBSSH2_ERROR_NONE && *privatekey) {
        free(*privatekey);
    }

    return result;
}

/*
 * Creates an ECDSA public key from an uncompressed point.
 */
int ssh2_ecdsa_curve_name_with_octal_new(
    OUT ssh2_ecdsa_ctx **key,
    IN const unsigned char *publickey_encoded,
    IN size_t publickey_encoded_len,
    IN ssh2_curve_type curve)
{
    int result = LIBSSH2_ERROR_NONE;

    BCRYPT_KEY_HANDLE publickey_handle;
    struct ecdsa_point publickey;

    /* Validate parameters */
    if(curve >= SSH2_ARRAYSIZE(wcng_ecdsa_algs)) {
        return LIBSSH2_ERROR_INVAL;
    }

    if(!key) {
        return LIBSSH2_ERROR_INVAL;
    }

    *key = NULL;

    result = wcng_ecdsa_decode_uncompressed_point(
        publickey_encoded,
        publickey_encoded_len,
        &publickey);
    if(result != LIBSSH2_ERROR_NONE) {
        goto cleanup;
    }

    result = wcng_publickey_from_point(
        WCNG_ECC_KEYTYPE_ECDSA,
        &publickey,
        &publickey_handle);
    if(result != LIBSSH2_ERROR_NONE) {
        goto cleanup;
    }

    *key = malloc(sizeof(struct wcng_ecdsa_ctx));
    if(!*key) {
        result = LIBSSH2_ERROR_ALLOC;
        goto cleanup;
    }

    (*key)->handle = publickey_handle;
    (*key)->curve = curve;

cleanup:

    return result;
}

/*
 * Computes the shared secret K given a local private key,
 * remote public key and length
 */
int ssh2_ecdh_gen_k(OUT ssh2_bn **secret,
                    IN ssh2_ecdsa_ctx *privatekey,
                    IN const unsigned char *server_publickey_encoded,
                    IN size_t server_publickey_encoded_len)
{
    int result = LIBSSH2_ERROR_NONE;
    NTSTATUS status;

    BCRYPT_KEY_HANDLE publickey_handle;
    BCRYPT_SECRET_HANDLE agreed_secret_handle = NULL;
    ULONG secret_len;
    struct ecdsa_point server_publickey;

    /* Validate parameters */
    if(!secret) {
        return LIBSSH2_ERROR_INVAL;
    }

    *secret = NULL;

    /* Decode the public key */
    result = wcng_ecdsa_decode_uncompressed_point(
        server_publickey_encoded,
        server_publickey_encoded_len,
        &server_publickey);
    if(result != LIBSSH2_ERROR_NONE) {
        return result;
    }

    result = wcng_publickey_from_point(
        WCNG_ECC_KEYTYPE_ECDH,
        &server_publickey,
        &publickey_handle);
    if(result != LIBSSH2_ERROR_NONE) {
        return result;
    }

    /* Establish the shared secret between ourselves and the peer */
    status = BCryptSecretAgreement(
        privatekey->handle,
        publickey_handle,
        &agreed_secret_handle,
        0);
    if(!BCRYPT_SUCCESS(status)) {
        result = LIBSSH2_ERROR_PUBLICKEY_PROTOCOL;
        goto cleanup;
    }

    /* Compute the size of the buffer that is needed to hold the derived
     * shared secret.
     *
     * NB. The use of BCRYPT_KDF_RAW_SECRET requires Windows 10 or newer.
     * On older versions, the BCryptDeriveKey returns STATUS_NOT_SUPPORTED.
     */
    status = BCryptDeriveKey(
        agreed_secret_handle,
        BCRYPT_KDF_RAW_SECRET,
        NULL,
        NULL,
        0,
        &secret_len,
        0);
    if(!BCRYPT_SUCCESS(status)) {
        result = LIBSSH2_ERROR_PUBLICKEY_PROTOCOL;
        goto cleanup;
    }

    /* Allocate a secret bignum to be ready to receive the derived secret */
    *secret = ssh2_wcng_bn_init();
    if(!*secret) {
        result = LIBSSH2_ERROR_ALLOC;
        goto cleanup;
    }

    if(wcng_bn_resize(*secret, secret_len)) {
        result = LIBSSH2_ERROR_ALLOC;
        goto cleanup;
    }

    /* Populate the secret bignum */
    status = BCryptDeriveKey(
        agreed_secret_handle,
        BCRYPT_KDF_RAW_SECRET,
        NULL,
        (*secret)->bignum,
        secret_len,
        &secret_len,
        0);
    if(!BCRYPT_SUCCESS(status)) {
        result = LIBSSH2_ERROR_PUBLICKEY_PROTOCOL;
        goto cleanup;
    }

    /* BCRYPT_KDF_RAW_SECRET returns the little-endian representation of the
     * raw secret, so we need to swap it to big endian order.
     */

    wcng_reverse_bytes((*secret)->bignum, secret_len);

    result = LIBSSH2_ERROR_NONE;

cleanup:
    if(result != LIBSSH2_ERROR_NONE && *secret) {
        ssh2_wcng_bn_free(*secret);
        *secret = NULL;
    }

    if(result != LIBSSH2_ERROR_NONE && agreed_secret_handle) {
        BCryptDestroySecret(agreed_secret_handle);
    }

    return result;
}

static int wcng_ecdsa_curve_type_from_name(IN const char *name,
                                           OUT ssh2_curve_type *out_curve)
{
    unsigned int curve;

    /* Validate parameters */
    if(!out_curve) {
        return LIBSSH2_ERROR_INVAL;
    }

    for(curve = 0; curve < SSH2_ARRAYSIZE(wcng_ecdsa_algs); curve++) {
        if(!strcmp(name, wcng_ecdsa_algs[curve].name)) {
            *out_curve = (ssh2_curve_type)curve;
            return LIBSSH2_ERROR_NONE;
        }
    }

    return LIBSSH2_ERROR_INVAL;
}

/*
 * Verifies the ECDSA signature of a hashed message
 */
int ssh2_ecdsa_verify(IN ssh2_ecdsa_ctx *key,
                      IN const unsigned char *r, IN size_t r_len,
                      IN const unsigned char *s, IN size_t s_len,
                      IN const unsigned char *m, IN size_t m_len)
{
    int result = LIBSSH2_ERROR_NONE;
    NTSTATUS status;

    PUCHAR signature_p1363 = NULL;
    size_t signature_p1363_len;
    ULONG hash_len;
    PUCHAR hash = NULL;
    BCRYPT_ALG_HANDLE hash_alg;

    /* CNG expects signatures in IEEE P-1363 format. */
    result = wcng_p1363signature_from_point(
        r,
        r_len,
        s,
        s_len,
        ssh2_ecdsa_get_curve_type(key),
        &signature_p1363,
        &signature_p1363_len);
    if(result != LIBSSH2_ERROR_NONE) {
        goto cleanup;
    }

    /* Create hash over m */
    switch(ssh2_ecdsa_get_curve_type(key)) {
    case SSH2_EC_CURVE_NISTP256:
        hash_len = 256 / 8;
        hash_alg = ssh2_wcng.hAlgHashSHA256;
        break;

    case SSH2_EC_CURVE_NISTP384:
        hash_len = 384 / 8;
        hash_alg = ssh2_wcng.hAlgHashSHA384;
        break;

    case SSH2_EC_CURVE_NISTP521:
        hash_len = 512 / 8;
        hash_alg = ssh2_wcng.hAlgHashSHA512;
        break;

    default:
        return LIBSSH2_ERROR_INVAL;
    }

    hash = malloc(hash_len);
    result = ssh2_wcng_hash(m, (ULONG)m_len, hash_alg, hash, hash_len);
    if(result != LIBSSH2_ERROR_NONE) {
        goto cleanup;
    }

    /* Verify signature over hash */
    status = BCryptVerifySignature(
        key->handle,
        NULL,
        hash,
        hash_len,
        signature_p1363,
        (ULONG)signature_p1363_len,
        0);

    if(status == STATUS_INVALID_SIGNATURE) {
        result = LIBSSH2_ERROR_PUBLICKEY_PROTOCOL;
        goto cleanup;
    }
    else if(!BCRYPT_SUCCESS(status)) {
        result = LIBSSH2_ERROR_PUBLICKEY_PROTOCOL;
        goto cleanup;
    }

    result = LIBSSH2_ERROR_NONE;

cleanup:
    if(hash) {
        free(hash);
    }

    if(signature_p1363) {
        free(signature_p1363);
    }

    return result;
}

/*
 * Creates a new private key given a file path and password
 */
int ssh2_ecdsa_new_private(OUT ssh2_ecdsa_ctx **key,
                           IN LIBSSH2_SESSION *session,
                           IN const char *filename,
                           IN const unsigned char *passphrase)
{
    int result;

    FILE *file_handle = NULL;
    unsigned char *data = NULL;
    size_t datalen = 0;

    /* Validate parameters */
    if(!key || !session || !filename) {
        return LIBSSH2_ERROR_INVAL;
    }

    *key = NULL;

    if(passphrase && strlen((const char *)passphrase) > 0) {
        return ssh2_err(session, LIBSSH2_ERROR_INVAL,
                        "Passphrase-protected ECDSA private key "
                        "files are unsupported");
    }

    file_handle = fopen(filename, "rb");
    if(!file_handle) {
        result = ssh2_err(session, LIBSSH2_ERROR_INVAL,
                          "Opening the private key file failed");
        goto cleanup;
    }

    result = ssh2_pem_parse(session,
        OPENSSH_PRIVKEY_HEADER,
        OPENSSH_PRIVKEY_FOOTER,
        passphrase,
        file_handle,
        &data,
        &datalen);
    if(result != LIBSSH2_ERROR_NONE) {
        goto cleanup;
    }

    result = ssh2_ecdsa_new_private_frommemory(key, session,
                                               (const char *)data, datalen,
                                               passphrase);
    if(result != LIBSSH2_ERROR_NONE) {
        goto cleanup;
    }

cleanup:
    if(file_handle) {
        fclose(file_handle);
    }

    if(data) {
        SSH2_FREE(session, data);
    }

    return result;
}

static int wcng_parse_ecdsa_privatekey(OUT struct wcng_ecdsa_ctx **key,
                                       IN unsigned char *privatekey,
                                       IN size_t privatekey_len)
{
    char *keytype = NULL;
    size_t keytype_len;

    unsigned char *ignore;
    size_t ignore_len;

    unsigned char *publickey;
    size_t publickey_len;

    ssh2_curve_type curve_type;
    int result;
    uint32_t check1, check2;
    struct string_buf data_buffer;

    struct ecdsa_point q;
    unsigned char *d;
    size_t d_len;

    BCRYPT_KEY_HANDLE key_handle = NULL;

    *key = NULL;

    data_buffer.data = privatekey;
    data_buffer.dataptr = privatekey;
    data_buffer.len = privatekey_len;

    /* Read the 2 checkints and check that they match */
    result = ssh2_get_u32(&data_buffer, &check1);
    if(result != LIBSSH2_ERROR_NONE) {
        goto cleanup;
    }

    result = ssh2_get_u32(&data_buffer, &check2);
    if(result != LIBSSH2_ERROR_NONE) {
        goto cleanup;
    }

    if(check1 != check2) {
        result = LIBSSH2_ERROR_FILE;
        goto cleanup;
    }

    /* What follows is a key as defined in */
    /* draft-miller-ssh-agent, section-3.2.2 */

    /* Read the key type */
    result = ssh2_get_string(&data_buffer,
                             (unsigned char **)&keytype, &keytype_len);
    if(result != LIBSSH2_ERROR_NONE) {
        goto cleanup;
    }

    result = wcng_ecdsa_curve_type_from_name(keytype, &curve_type);
    if(result < 0) {
        goto cleanup;
    }

    /* Read the curve */
    result = ssh2_get_string(&data_buffer, &ignore, &ignore_len);
    if(result != LIBSSH2_ERROR_NONE) {
        goto cleanup;
    }

    /* Read Q */
    result = ssh2_get_string(&data_buffer, &publickey, &publickey_len);
    if(result != LIBSSH2_ERROR_NONE) {
        goto cleanup;
    }

    result = wcng_ecdsa_decode_uncompressed_point(
        publickey,
        publickey_len,
        &q);
    if(result != LIBSSH2_ERROR_NONE) {
        goto cleanup;
    }

    /* Read d */
    result = ssh2_get_bignum_bytes(&data_buffer, &d, &d_len);
    if(result != LIBSSH2_ERROR_NONE) {
        goto cleanup;
    }

    /* Ignore the rest (comment, etc) */

    /* Use Q and d to create a key handle */
    result = wcng_privatekey_from_point(
        WCNG_ECC_KEYTYPE_ECDSA,
        &q,
        d,
        d_len,
        &key_handle);
    if(result != LIBSSH2_ERROR_NONE) {
        goto cleanup;
    }

    *key = malloc(sizeof(struct wcng_ecdsa_ctx));
    if(!*key) {
        result = LIBSSH2_ERROR_ALLOC;
        goto cleanup;
    }

    (*key)->curve = q.curve;
    (*key)->handle = key_handle;

    result = LIBSSH2_ERROR_NONE;

cleanup:
    if(result != LIBSSH2_ERROR_NONE && key_handle) {
        (void)BCryptDestroyKey(key_handle);
    }

    return result;
}

/*
 * Creates a new private key given a file data and password.
 * ECDSA private key files use the decoding defined in PROTOCOL.key
 * in the OpenSSL source tree.
 */
int ssh2_ecdsa_new_private_frommemory(OUT ssh2_ecdsa_ctx **key,
                                      IN LIBSSH2_SESSION *session,
                                      IN const char *data,
                                      IN size_t data_len,
                                      IN const unsigned char *passphrase)
{
    int result;

    struct string_buf data_buffer;
    uint32_t index;
    uint32_t key_count;
    unsigned char *privatekey;
    size_t privatekey_len;

    /* Validate parameters */
    if(!key || !session || !data) {
        return LIBSSH2_ERROR_INVAL;
    }

    *key = NULL;

    if(passphrase && strlen((const char *)passphrase) > 0) {
        return ssh2_err(session, LIBSSH2_ERROR_INVAL,
                        "Passphrase-protected ECDSA private key "
                        "files are unsupported");
    }

    /* Read OPENSSH_PRIVKEY_AUTH_MAGIC */
    if(data_len < sizeof(OPENSSH_PRIVKEY_AUTH_MAGIC) ||
       memcmp(data, OPENSSH_PRIVKEY_AUTH_MAGIC,
              sizeof(OPENSSH_PRIVKEY_AUTH_MAGIC))) {
        result = -1;
        goto cleanup;
    }

    data_buffer.len = data_len;
    data_buffer.data = (unsigned char *)SSH2_UNCONST(data);
    data_buffer.dataptr = data_buffer.data +
                          sizeof(OPENSSH_PRIVKEY_AUTH_MAGIC);

    /* Read ciphername, should be 'none' as we do not support passphrases */
    result = ssh2_match_string(&data_buffer, "none");
    if(result != LIBSSH2_ERROR_NONE) {
        goto cleanup;
    }

    /* Read kdfname, should be 'none' as we do not support passphrases */
    result = ssh2_match_string(&data_buffer, "none");
    if(result != LIBSSH2_ERROR_NONE) {
        goto cleanup;
    }

    /* Read kdfoptions, should be empty */
    result = ssh2_match_string(&data_buffer, "");
    if(result != LIBSSH2_ERROR_NONE) {
        goto cleanup;
    }

    /* Read number of keys N */
    result = ssh2_get_u32(&data_buffer, &key_count);
    if(result != LIBSSH2_ERROR_NONE) {
        goto cleanup;
    }

    if(key_count == 0) {
        result = LIBSSH2_ERROR_FILE;
        goto cleanup;
    }

    /* Skip all public keys */
    for(index = 0; index < key_count; index++) {
        unsigned char *publickey;
        size_t publickey_len;

        result = ssh2_get_string(&data_buffer, &publickey, &publickey_len);
        if(result != LIBSSH2_ERROR_NONE) {
            goto cleanup;
        }
    }

    /* Read first private key */
    result = ssh2_get_string(&data_buffer, &privatekey, &privatekey_len);
    if(result != LIBSSH2_ERROR_NONE) {
        goto cleanup;
    }

    result = wcng_parse_ecdsa_privatekey(key, privatekey, privatekey_len);

cleanup:
    if(result != LIBSSH2_ERROR_NONE) {
        return ssh2_err(session, result, "The key is malformed");
    }

    return result;
}

/*
 * Computes the ECDSA signature of a previously-hashed message
 */
int ssh2_ecdsa_sign(IN LIBSSH2_SESSION *session,
                    IN struct wcng_ecdsa_ctx *key,
                    IN const unsigned char *hash,
                    IN size_t hash_len,
                    OUT unsigned char **signature,
                    OUT size_t *signature_len)
{
    NTSTATUS status;
    int result = LIBSSH2_ERROR_NONE;

    unsigned char *hash_buffer;

    unsigned char *cng_signature = NULL;
    ULONG cng_signature_len;

    ULONG signature_maxlen;
    unsigned char *signature_ptr;

    *signature = NULL;
    *signature_len = 0;

    /* CNG expects a mutable buffer */
    hash_buffer = malloc(hash_len);
    if(!hash_buffer) {
        result = LIBSSH2_ERROR_ALLOC;
        goto cleanup;
    }

    memcpy(hash_buffer, hash, hash_len);

    status = BCryptSignHash(
        key->handle,
        NULL,
        hash_buffer,
        (ULONG)hash_len,
        NULL,
        0,
        &cng_signature_len,
        0);
    if(!BCRYPT_SUCCESS(status)) {
        result = LIBSSH2_ERROR_PUBLICKEY_PROTOCOL;
        goto cleanup;
    }

    cng_signature = malloc(cng_signature_len);
    if(!cng_signature) {
        result = LIBSSH2_ERROR_ALLOC;
        goto cleanup;
    }

    status = BCryptSignHash(
        key->handle,
        NULL,
        hash_buffer,
        (ULONG)hash_len,
        cng_signature,
        cng_signature_len,
        &cng_signature_len,
        0);
    if(!BCRYPT_SUCCESS(status)) {
        result = LIBSSH2_ERROR_PUBLICKEY_PROTOCOL;
        goto cleanup;
    }

    /*
        cng_signature is in IEEE P-1163 format: r || s.
        Convert to ecdsa_signature_blob: mpint(r) || mpint(s)
    */

    signature_maxlen =
        cng_signature_len / 2 + 5 + /* mpint(r) */
        cng_signature_len / 2 + 5;  /* mpint(s) */

    *signature = SSH2_ALLOC(session, signature_maxlen);
    signature_ptr = *signature;

    if(ssh2_store_bignum_bytes(&signature_ptr,
                               cng_signature,
                               cng_signature_len / 2) &&
       ssh2_store_bignum_bytes(&signature_ptr,
                               cng_signature + (cng_signature_len / 2),
                               cng_signature_len / 2)) {
        *signature_len = signature_ptr - *signature;
    }
    else {
        ssh2_deb((session, LIBSSH2_ERROR_STORE_OVERFLOW, "Too large write."));
        result = LIBSSH2_ERROR_STORE_OVERFLOW;
        goto cleanup;
    }

cleanup:
    if(result != LIBSSH2_ERROR_NONE && *signature) {
        SSH2_FREE(session, *signature);
        *signature = NULL;
        *signature_len = 0;
    }

    if(cng_signature) {
        free(cng_signature);
    }

    if(hash_buffer) {
        free(hash_buffer);
    }

    return result;
}

/*
 * returns key curve type that maps to ssh2_curve_type
 */
ssh2_curve_type ssh2_ecdsa_get_curve_type(IN ssh2_ecdsa_ctx *key)
{
    return key->curve;
}

#endif

/*******************************************************************/
/*
 * Windows CNG backend: Key functions
 */

#if LIBSSH2_RSA || LIBSSH2_DSA
static DWORD wcng_pub_priv_write(unsigned char *key,
                                 DWORD offset,
                                 const unsigned char *bignum,
                                 const DWORD length)
{
    ssh2_htonu32(key + offset, length);
    offset += 4;

    memcpy(key + offset, bignum, length);
    offset += length;

    return offset;
}

static int wcng_pub_priv_keyfile_parse(LIBSSH2_SESSION *session,
                                       unsigned char **method,
                                       size_t *method_len,
                                       unsigned char **pubkeydata,
                                       size_t *pubkeydata_len,
                                       unsigned char *pbEncoded,
                                       size_t cbEncoded)
{
    unsigned char **rpbDecoded = NULL;
    DWORD *rcbDecoded = NULL;
    unsigned char *key = NULL, *mth = NULL;
    DWORD keylen = 0, mthlen = 0;
    DWORD index, offset, length = 0;
    int ret;

    ret = wcng_asn_decode_bns(pbEncoded, (DWORD)cbEncoded,
                              &rpbDecoded, &rcbDecoded, &length);

    wcng_safe_free(pbEncoded, cbEncoded);

    if(ret) {
        return -1;
    }

    if(length == 9) { /* private RSA key */
        mthlen = 7;
        mth = SSH2_ALLOC(session, mthlen);
        if(mth) {
            memcpy(mth, "ssh-rsa", mthlen);
        }
        else {
            ret = -1;
        }

        keylen = 4 + mthlen + 4 + rcbDecoded[2] + 4 + rcbDecoded[1];
        key = SSH2_ALLOC(session, keylen);
        if(key) {
            offset = wcng_pub_priv_write(key, 0, mth, mthlen);

            offset = wcng_pub_priv_write(key, offset,
                                         rpbDecoded[2],
                                         rcbDecoded[2]);

            wcng_pub_priv_write(key, offset,
                                rpbDecoded[1],
                                rcbDecoded[1]);
        }
        else {
            ret = -1;
        }
    }
    else if(length == 6) { /* private DSA key */
        mthlen = 7;
        mth = SSH2_ALLOC(session, mthlen);
        if(mth) {
            memcpy(mth, "ssh-dss", mthlen);
        }
        else {
            ret = -1;
        }

        keylen = 4 + mthlen + 4 + rcbDecoded[1] + 4 + rcbDecoded[2]
                            + 4 + rcbDecoded[3] + 4 + rcbDecoded[4];
        key = SSH2_ALLOC(session, keylen);
        if(key) {
            offset = wcng_pub_priv_write(key, 0, mth, mthlen);

            offset = wcng_pub_priv_write(key, offset,
                                         rpbDecoded[1],
                                         rcbDecoded[1]);

            offset = wcng_pub_priv_write(key, offset,
                                         rpbDecoded[2],
                                         rcbDecoded[2]);

            offset = wcng_pub_priv_write(key, offset,
                                         rpbDecoded[3],
                                         rcbDecoded[3]);

            wcng_pub_priv_write(key, offset,
                                rpbDecoded[4],
                                rcbDecoded[4]);
        }
        else {
            ret = -1;
        }
    }
    else {
        ret = -1;
    }

    for(index = 0; index < length; index++) {
        wcng_safe_free(rpbDecoded[index], rcbDecoded[index]);
        rpbDecoded[index] = NULL;
        rcbDecoded[index] = 0;
    }

    free(rpbDecoded);
    free(rcbDecoded);

    if(ret) {
        if(mth)
            SSH2_FREE(session, mth);
        if(key)
            SSH2_FREE(session, key);
    }
    else {
        *method = mth;
        *method_len = mthlen;
        *pubkeydata = key;
        *pubkeydata_len = keylen;
    }

    return ret;
}

int ssh2_pub_priv_keyfile(LIBSSH2_SESSION *session,
                          unsigned char **method,
                          size_t *method_len,
                          unsigned char **pubkeydata,
                          size_t *pubkeydata_len,
                          const char *privatekey,
                          const char *passphrase)
{
    unsigned char *pbEncoded;
    size_t cbEncoded;
    int ret;

    ret = wcng_load_private(session, privatekey,
                            (const unsigned char *)passphrase,
                            &pbEncoded, &cbEncoded, 1, 1);
    if(ret) {
        return -1;
    }

    return wcng_pub_priv_keyfile_parse(session, method, method_len,
                                       pubkeydata, pubkeydata_len,
                                       pbEncoded, cbEncoded);
}

int ssh2_pub_priv_keyfilememory(LIBSSH2_SESSION *session,
                                unsigned char **method,
                                size_t *method_len,
                                unsigned char **pubkeydata,
                                size_t *pubkeydata_len,
                                const char *privatekeydata,
                                size_t privatekeydata_len,
                                const char *passphrase)
{
    unsigned char *pbEncoded;
    size_t cbEncoded;
    int ret;

    ret = wcng_load_private_memory(session, privatekeydata,
                                   privatekeydata_len,
                                   (const unsigned char *)passphrase,
                                   &pbEncoded, &cbEncoded, 1, 1);
    if(ret) {
        return -1;
    }

    return wcng_pub_priv_keyfile_parse(session, method, method_len,
                                       pubkeydata, pubkeydata_len,
                                       pbEncoded, cbEncoded);
}
#endif /* LIBSSH2_RSA || LIBSSH2_DSA */

int ssh2_sk_pub_keyfilememory(LIBSSH2_SESSION *session,
                              unsigned char **method,
                              size_t *method_len,
                              unsigned char **pubkeydata,
                              size_t *pubkeydata_len,
                              int *algorithm,
                              unsigned char *flags,
                              const char **application,
                              const unsigned char **key_handle,
                              size_t *handle_len,
                              const char *privatekeydata,
                              size_t privatekeydata_len,
                              const char *passphrase)
{
    (void)method;
    (void)method_len;
    (void)pubkeydata;
    (void)pubkeydata_len;
    (void)algorithm;
    (void)flags;
    (void)application;
    (void)key_handle;
    (void)handle_len;
    (void)privatekeydata;
    (void)privatekeydata_len;
    (void)passphrase;

    return ssh2_err(session, LIBSSH2_ERROR_FILE,
                    "Unable to extract public SK key from private key "
                    "file: Method unimplemented in Windows CNG backend");
}

/*******************************************************************/
/*
 * Windows CNG backend: Cipher functions
 */
int ssh2_cipher_init(ssh2_cipher_ctx *h, SSH2_CIPHER_T(algo),
                     unsigned char *iv, unsigned char *secret, int encrypt)
{
    BCRYPT_KEY_HANDLE hKey;
    BCRYPT_KEY_DATA_BLOB_HEADER *header;
    unsigned char *pbKeyObject, *pbIV, *pbCtr, *pbIVCopy;
    ULONG dwKeyObject, dwIV, dwCtrLength, dwBlockLength, cbData, keylen;
    int ret;

    (void)encrypt;

    ret = BCryptGetProperty(*algo.phAlg, BCRYPT_OBJECT_LENGTH,
                            (unsigned char *)&dwKeyObject,
                            sizeof(dwKeyObject),
                            &cbData, 0);
    if(!BCRYPT_SUCCESS(ret)) {
        return -1;
    }

    ret = BCryptGetProperty(*algo.phAlg, BCRYPT_BLOCK_LENGTH,
                            (unsigned char *)&dwBlockLength,
                            sizeof(dwBlockLength),
                            &cbData, 0);
    if(!BCRYPT_SUCCESS(ret)) {
        return -1;
    }

    pbKeyObject = malloc(dwKeyObject);
    if(!pbKeyObject) {
        return -1;
    }

    keylen = (ULONG)sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) + algo.dwKeyLength;
    header = malloc(keylen);
    if(!header) {
        free(pbKeyObject);
        return -1;
    }

    header->dwMagic = BCRYPT_KEY_DATA_BLOB_MAGIC;
    header->dwVersion = BCRYPT_KEY_DATA_BLOB_VERSION1;
    header->cbKeyData = algo.dwKeyLength;

    memcpy((unsigned char *)header + sizeof(BCRYPT_KEY_DATA_BLOB_HEADER),
           secret, algo.dwKeyLength);

    ret = BCryptImportKey(*algo.phAlg, NULL, BCRYPT_KEY_DATA_BLOB, &hKey,
                          pbKeyObject, dwKeyObject,
                          (PUCHAR)header, keylen, 0);

    wcng_safe_free(header, keylen);

    if(!BCRYPT_SUCCESS(ret)) {
        wcng_safe_free(pbKeyObject, dwKeyObject);
        return -1;
    }

    pbIV = NULL;
    pbCtr = NULL;
    dwIV = 0;
    dwCtrLength = 0;

    if(algo.useIV || algo.ctrMode) {
        pbIVCopy = malloc(dwBlockLength);
        if(!pbIVCopy) {
            BCryptDestroyKey(hKey);
            wcng_safe_free(pbKeyObject, dwKeyObject);
            return -1;
        }
        memcpy(pbIVCopy, iv, dwBlockLength);

        if(algo.ctrMode) {
            pbCtr = pbIVCopy;
            dwCtrLength = dwBlockLength;
        }
        else if(algo.useIV) {
            pbIV = pbIVCopy;
            dwIV = dwBlockLength;
        }
    }

    h->hKey = hKey;
    h->pbKeyObject = pbKeyObject;
    h->pbIV = pbIV;
    h->pbCtr = pbCtr;
    h->dwKeyObject = dwKeyObject;
    h->dwIV = dwIV;
    h->dwBlockLength = dwBlockLength;
    h->dwCtrLength = dwCtrLength;

    return 0;
}

/* Increments an AES CTR buffer to prepare it for use with the
   next AES block. */
static void wcng_aes_ctr_increment(unsigned char *ctr, size_t length)
{
    unsigned char *pc;
    unsigned int val, carry;

    pc = ctr + length - 1;
    carry = 1;

    while(pc >= ctr) {
        val = (unsigned int)*pc + carry;
        *pc-- = val & 0xFF;
        carry = val >> 8;
    }
}

int ssh2_cipher_crypt(ssh2_cipher_ctx *ctx, SSH2_CIPHER_T(algo),
                      int encrypt, unsigned char *block, size_t blocksize,
                      int firstlast)
{
    unsigned char *pbOutput, *pbInput;
    ULONG cbOutput, cbInput;
    NTSTATUS ret;

    (void)algo;
    (void)firstlast;

    cbInput = (ULONG)blocksize;

    if(algo.ctrMode) {
        pbInput = ctx->pbCtr;
    }
    else {
        pbInput = block;
    }

    if(encrypt || algo.ctrMode) {
        ret = BCryptEncrypt(ctx->hKey, pbInput, cbInput, NULL,
                            ctx->pbIV, ctx->dwIV, NULL, 0, &cbOutput, 0);
    }
    else {
        ret = BCryptDecrypt(ctx->hKey, pbInput, cbInput, NULL,
                            ctx->pbIV, ctx->dwIV, NULL, 0, &cbOutput, 0);
    }
    if(BCRYPT_SUCCESS(ret)) {
        pbOutput = malloc(cbOutput);
        if(pbOutput) {
            if(encrypt || algo.ctrMode) {
                ret = BCryptEncrypt(ctx->hKey, pbInput, cbInput, NULL,
                                    ctx->pbIV, ctx->dwIV,
                                    pbOutput, cbOutput, &cbOutput, 0);
            }
            else {
                ret = BCryptDecrypt(ctx->hKey, pbInput, cbInput, NULL,
                                    ctx->pbIV, ctx->dwIV,
                                    pbOutput, cbOutput, &cbOutput, 0);
            }
            if(BCRYPT_SUCCESS(ret)) {
                if(algo.ctrMode) {
                    /* NOLINTNEXTLINE(readability-suspicious-call-argument) */
                    ssh2_xor_data(block, block, pbOutput, blocksize);
                    wcng_aes_ctr_increment(ctx->pbCtr, ctx->dwCtrLength);
                }
                else {
                    memcpy(block, pbOutput, cbOutput);
                }
            }

            wcng_safe_free(pbOutput, cbOutput);
        }
        else
            ret = (NTSTATUS)STATUS_NO_MEMORY;
    }

    return BCRYPT_SUCCESS(ret) ? 0 : -1;
}

void ssh2_cipher_dtor(ssh2_cipher_ctx *ctx)
{
    BCryptDestroyKey(ctx->hKey);
    ctx->hKey = NULL;

    wcng_safe_free(ctx->pbKeyObject, ctx->dwKeyObject);
    ctx->pbKeyObject = NULL;
    ctx->dwKeyObject = 0;

    wcng_safe_free(ctx->pbIV, ctx->dwBlockLength);
    ctx->pbIV = NULL;
    ctx->dwBlockLength = 0;

    wcng_safe_free(ctx->pbCtr, ctx->dwCtrLength);
    ctx->pbCtr = NULL;
    ctx->dwCtrLength = 0;
}

/*******************************************************************/
/*
 * Windows CNG backend: Diffie-Hellman support.
 */

void ssh2_dh_init(ssh2_dh_ctx *dhctx)
{
    /* Random from client */
    dhctx->dh_handle = NULL;
    dhctx->dh_params = NULL;
    dhctx->dh_privbn = NULL;
}

void ssh2_dh_dtor(ssh2_dh_ctx *dhctx)
{
    if(dhctx->dh_handle) {
        BCryptDestroyKey(dhctx->dh_handle);
        dhctx->dh_handle = NULL;
    }
    if(dhctx->dh_params) {
        /* Since public dh_params are shared in clear text,
         * we do not need to securely zero them out here */
        free(dhctx->dh_params);
        dhctx->dh_params = NULL;
    }
    if(dhctx->dh_privbn) {
        ssh2_wcng_bn_free(dhctx->dh_privbn);
        dhctx->dh_privbn = NULL;
    }
}

static int wcng_round_down(int number, int multiple)
{
    return (number / multiple) * multiple;
}

/* Generates a Diffie-Hellman key pair using base `g', prime `p' and the given
 * `group_order'. Can use the given big number context `bnctx' if needed.  The
 * private key is stored as opaque in the Diffie-Hellman context `*dhctx' and
 * the public key is returned in `pub'. 0 is returned upon success, else -1. */
int ssh2_wcng_dh_key_pair(ssh2_dh_ctx *dhctx, ssh2_bn *pub, ssh2_bn *g,
                          ssh2_bn *p, int group_order)
{
    const int hasAlgDHwithKDF = ssh2_wcng.hasAlgDHwithKDF;

    if(group_order < 0)
        return -1;

    while(ssh2_wcng.hAlgDH && hasAlgDHwithKDF != -1) {
        BCRYPT_DH_PARAMETER_HEADER *dh_params;
        ULONG dh_params_len;
        int status;
        /* The DH provider requires keys to be multiples of 64 bits. Since
         * group_order can be values like 257, we round down to the nearest
         * multiple of 8 bytes (64 bits / 8) to meet this requirement for key
         * exchange success. */
        ULONG key_length_bytes = max((ULONG)wcng_round_down(group_order, 8),
                                     max(g->length, p->length));
        BCRYPT_DH_KEY_BLOB *dh_key_blob;
        LPCWSTR key_type;

        /* Prepare a key pair; pass the in the bit length of the key,
         * but the key is not ready for consumption until it is finalized. */
        status = BCryptGenerateKeyPair(ssh2_wcng.hAlgDH,
                                       &dhctx->dh_handle,
                                       key_length_bytes * 8, 0);
        if(!BCRYPT_SUCCESS(status)) {
            return -1;
        }

        dh_params_len = (ULONG)sizeof(*dh_params) + 2 * key_length_bytes;
        dh_params = malloc(dh_params_len);
        if(!dh_params) {
            return -1;
        }

        /* Populate DH parameters blob; after the header follows the `p`
         * value and the `g` value. */
        dh_params->cbLength = dh_params_len;
        dh_params->dwMagic = BCRYPT_DH_PARAMETERS_MAGIC;
        dh_params->cbKeyLength = key_length_bytes;
        wcng_memcpy_with_be_padding((unsigned char *)dh_params +
                                    sizeof(*dh_params),
                                    key_length_bytes, p->bignum, p->length);
        wcng_memcpy_with_be_padding((unsigned char *)dh_params +
                                    sizeof(*dh_params) + key_length_bytes,
                                    key_length_bytes, g->bignum, g->length);

        status = BCryptSetProperty(dhctx->dh_handle, BCRYPT_DH_PARAMETERS,
                                   (PUCHAR)dh_params, dh_params_len, 0);
        if(hasAlgDHwithKDF == -1) {
            /* We know that the raw KDF is not supported, so discard this. */
            free(dh_params);
        }
        else {
            /* Pass ownership to dhctx; these parameters are freed when
             * the context is destroyed. We need to keep the parameters more
             * easily available so that we have access to the `g` value when
             * ssh2_wcng_dh_secret() is called later. */
            dhctx->dh_params = dh_params;
        }
        dh_params = NULL;

        if(!BCRYPT_SUCCESS(status)) {
            return -1;
        }

        status = BCryptFinalizeKeyPair(dhctx->dh_handle, 0);
        if(!BCRYPT_SUCCESS(status)) {
            return -1;
        }

        key_length_bytes = 0;
        if(hasAlgDHwithKDF == 1) {
            /* Now we need to extract the public portion of the key so that we
             * set it in the `pub` bignum to satisfy our caller.
             * First measure up the size of the required buffer. */
            key_type = BCRYPT_DH_PUBLIC_BLOB;
        }
        else {
            /* We also need to extract the private portion of the key to
             * set it in the `*dhctx' bignum if the raw KDF is not supported.
             * First measure up the size of the required buffer. */
            key_type = BCRYPT_DH_PRIVATE_BLOB;
        }
        status = BCryptExportKey(dhctx->dh_handle, NULL, key_type,
                                 NULL, 0, &key_length_bytes, 0);
        if(!BCRYPT_SUCCESS(status)) {
            return -1;
        }

        dh_key_blob = malloc(key_length_bytes);
        if(!dh_key_blob) {
            return -1;
        }

        status = BCryptExportKey(dhctx->dh_handle, NULL, key_type,
                                 (PUCHAR)dh_key_blob, key_length_bytes,
                                 &key_length_bytes, 0);
        if(!BCRYPT_SUCCESS(status)) {
            if(hasAlgDHwithKDF == 1) {
                /* We have no private data, because raw KDF is supported */
                free(dh_key_blob);
            }
            else { /* we may have potentially private data, use secure free */
                wcng_safe_free(dh_key_blob, key_length_bytes);
            }
            return -1;
        }

        if(hasAlgDHwithKDF == -1) {
            /* We know that the raw KDF is not supported, so discard this */
            BCryptDestroyKey(dhctx->dh_handle);
            dhctx->dh_handle = NULL;
        }

        /* BCRYPT_DH_PUBLIC_BLOB corresponds to a BCRYPT_DH_KEY_BLOB header
         * followed by the Modulus, Generator and Public data. Those components
         * each have equal size, specified by dh_key_blob->cbKey. */
        if(wcng_bn_resize(pub, dh_key_blob->cbKey)) {
            if(hasAlgDHwithKDF == 1) {
                /* We have no private data, because raw KDF is supported */
                free(dh_key_blob);
            }
            else { /* we may have potentially private data, use secure free */
                wcng_safe_free(dh_key_blob, key_length_bytes);
            }
            return -1;
        }

        /* Copy the public key data into the public bignum data buffer */
        memcpy(pub->bignum, (unsigned char *)dh_key_blob +
                            sizeof(*dh_key_blob) + 2 * dh_key_blob->cbKey,
               dh_key_blob->cbKey);

        if(dh_key_blob->dwMagic == BCRYPT_DH_PRIVATE_MAGIC) {
            /* BCRYPT_DH_PRIVATE_BLOB additionally contains the Private data */
            dhctx->dh_privbn = ssh2_wcng_bn_init();
            if(!dhctx->dh_privbn) {
                wcng_safe_free(dh_key_blob, key_length_bytes);
                return -1;
            }
            if(wcng_bn_resize(dhctx->dh_privbn, dh_key_blob->cbKey)) {
                wcng_safe_free(dh_key_blob, key_length_bytes);
                return -1;
            }

            /* Copy the private key data into the dhctx bignum data buffer */
            memcpy(dhctx->dh_privbn->bignum, (unsigned char *)dh_key_blob +
                                             sizeof(*dh_key_blob) +
                                             3 * dh_key_blob->cbKey,
                   dh_key_blob->cbKey);

            /* Make sure the private key is an odd number, because only
             * odd primes can be used with the RSA-based fallback while
             * DH itself does not seem to care about it being odd or not. */
            if(!(dhctx->dh_privbn->bignum[dhctx->dh_privbn->length - 1] % 2)) {
                wcng_safe_free(dh_key_blob, key_length_bytes);
                /* discard everything first, then try again */
                ssh2_dh_dtor(dhctx);
                ssh2_dh_init(dhctx);
                continue;
            }
        }

        wcng_safe_free(dh_key_blob, key_length_bytes);

        return 0;
    }

    /* Generate x and e */
    dhctx->dh_privbn = ssh2_wcng_bn_init();
    if(!dhctx->dh_privbn)
        return -1;
    if(wcng_bn_random(dhctx->dh_privbn, (group_order * 8) - 1, 0, -1))
        return -1;
    if(wcng_bn_mod_exp(pub, g, dhctx->dh_privbn, p))
        return -1;

    return 0;
}

/* Computes the Diffie-Hellman secret from the previously created context
 * `*dhctx', the public key `f' from the other party and the same prime `p'
 * used at context creation. The result is stored in `secret'.  0 is returned
 * upon success, else -1.  */
int ssh2_wcng_dh_secret(ssh2_dh_ctx *dhctx, ssh2_bn *secret, ssh2_bn *f,
                        ssh2_bn *p)
{
    if(ssh2_wcng.hAlgDH && ssh2_wcng.hasAlgDHwithKDF != -1 &&
       dhctx->dh_handle && dhctx->dh_params && f) {
        BCRYPT_KEY_HANDLE peer_public = NULL;
        BCRYPT_SECRET_HANDLE agreement = NULL;
        ULONG secret_len_bytes = 0;
        NTSTATUS status;
        BCRYPT_DH_KEY_BLOB *public_blob;
        ULONG key_length_bytes = max(f->length, dhctx->dh_params->cbKeyLength);
        ULONG public_blob_len = (ULONG)(sizeof(*public_blob) +
                                        3 * key_length_bytes);

        {
            /* Populate a BCRYPT_DH_KEY_BLOB; after the header follows the
             * Modulus, Generator and Public data. Those components must have
             * equal size in this representation. */
            unsigned char *dest;
            unsigned char *src;

            public_blob = malloc(public_blob_len);
            if(!public_blob) {
                return -1;
            }
            public_blob->dwMagic = BCRYPT_DH_PUBLIC_MAGIC;
            public_blob->cbKey = key_length_bytes;

            dest = (unsigned char *)(public_blob + 1);
            src = (unsigned char *)(dhctx->dh_params + 1);

            /* Modulus (the p-value from the first call) */
            wcng_memcpy_with_be_padding(dest, key_length_bytes,
                                        src, dhctx->dh_params->cbKeyLength);
            /* Generator (the g-value from the first call) */
            wcng_memcpy_with_be_padding(dest + key_length_bytes,
                                        key_length_bytes,
                                        src + dhctx->dh_params->cbKeyLength,
                                        dhctx->dh_params->cbKeyLength);
            /* Public from the peer */
            wcng_memcpy_with_be_padding(dest + 2 * key_length_bytes,
                                        key_length_bytes,
                                        f->bignum, f->length);
        }

        /* Import the peer public key information */
        status = BCryptImportKeyPair(ssh2_wcng.hAlgDH, NULL,
                                     BCRYPT_DH_PUBLIC_BLOB, &peer_public,
                                     (PUCHAR)public_blob, public_blob_len, 0);
        if(!BCRYPT_SUCCESS(status)) {
            goto out;
        }

        /* Set up a handle that we can use to establish the shared secret
         * between ourselves (our saved dh_handle) and the peer. */
        status = BCryptSecretAgreement(dhctx->dh_handle, peer_public,
                                       &agreement, 0);
        if(!BCRYPT_SUCCESS(status)) {
            goto out;
        }

        /* Compute the size of the buffer that is needed to hold the derived
         * shared secret. */
        status = BCryptDeriveKey(agreement, BCRYPT_KDF_RAW_SECRET, NULL, NULL,
                                 0, &secret_len_bytes, 0);
        if(!BCRYPT_SUCCESS(status)) {
            if(status == STATUS_NOT_SUPPORTED) {
                ssh2_wcng.hasAlgDHwithKDF = -1;
            }
            goto out;
        }

        /* Expand the secret bignum to be ready to receive the derived secret
         * */
        if(wcng_bn_resize(secret, secret_len_bytes)) {
            status = (NTSTATUS)STATUS_NO_MEMORY;
            goto out;
        }

        /* Populate the secret bignum */
        status = BCryptDeriveKey(agreement, BCRYPT_KDF_RAW_SECRET, NULL,
                                 secret->bignum, secret_len_bytes,
                                 &secret_len_bytes, 0);
        if(!BCRYPT_SUCCESS(status)) {
            if(status == STATUS_NOT_SUPPORTED) {
                ssh2_wcng.hasAlgDHwithKDF = -1;
            }
            goto out;
        }

        /* Counter to all the other data in the BCrypt APIs, the raw secret is
         * returned to us in host byte order, so we need to swap it to big
         * endian order. */
        wcng_reverse_bytes(secret->bignum, secret->length);

        status = 0;
        ssh2_wcng.hasAlgDHwithKDF = 1;

out:
        if(peer_public) {
            BCryptDestroyKey(peer_public);
        }
        if(agreement) {
            BCryptDestroySecret(agreement);
        }

        free(public_blob);

        if(status == STATUS_NOT_SUPPORTED && ssh2_wcng.hasAlgDHwithKDF == -1) {
            goto fb; /* fallback to RSA-based implementation */
        }
        return BCRYPT_SUCCESS(status) ? 0 : -1;
    }

fb:
    /* Compute the shared secret */
    return wcng_bn_mod_exp(secret, f, dhctx->dh_privbn, p);
}

/*
 * Return supported key hash algo upgrades, see crypto.h
 */
const char *ssh2_supported_key_sign_algs(LIBSSH2_SESSION *session,
                                         unsigned char *key_method,
                                         size_t key_method_len)
{
    (void)session;

#if LIBSSH2_RSA_SHA2
    if(key_method_len == 7 &&
       !memcmp(key_method, "ssh-rsa", key_method_len)) {
        return "rsa-sha2-512,rsa-sha2-256"
#if LIBSSH2_RSA_SHA1
            ",ssh-rsa"
#endif
            ;
    }
#else
    (void)key_method;
    (void)key_method_len;
#endif

    return NULL;
}

#endif /* LIBSSH2_WINCNG */
