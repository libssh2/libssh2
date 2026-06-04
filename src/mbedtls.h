#ifndef LIBSSH2_MBEDTLS_H
#define LIBSSH2_MBEDTLS_H
/* Copyright (C) Art <https://github.com/wildart>
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

#define SSH2_CRYPTO_ENGINE libssh2_mbedtls

#include <mbedtls/version.h>
#include <mbedtls/platform.h>
#include <mbedtls/md.h>
#include <mbedtls/rsa.h>
#include <mbedtls/bignum.h>
#include <mbedtls/cipher.h>
#ifdef MBEDTLS_ECDH_C
# include <mbedtls/ecdh.h>
#endif
#ifdef MBEDTLS_ECDSA_C
# include <mbedtls/ecdsa.h>
#endif
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/pk.h>
#include <mbedtls/error.h>

/* Define which features are supported. */
#define LIBSSH2_MD5             1

#define LIBSSH2_HMAC_RIPEMD     1
#define LIBSSH2_HMAC_SHA256     1
#define LIBSSH2_HMAC_SHA512     1

#define LIBSSH2_AES_CBC         1
#define LIBSSH2_AES_CTR         1
#define LIBSSH2_AES_GCM         0
#ifdef MBEDTLS_CIPHER_BLOWFISH_CBC
# define LIBSSH2_BLOWFISH       1
#else
# define LIBSSH2_BLOWFISH       0
#endif
#ifdef MBEDTLS_CIPHER_ARC4_128
# define LIBSSH2_RC4            1
#else
# define LIBSSH2_RC4            0
#endif
#define LIBSSH2_CAST            0
#define LIBSSH2_3DES            1

#define LIBSSH2_RSA             1
#define LIBSSH2_RSA_SHA1        1
#define LIBSSH2_RSA_SHA2        1
#define LIBSSH2_DSA             0
#ifdef MBEDTLS_ECDSA_C
# define LIBSSH2_ECDSA          1
#else
# define LIBSSH2_ECDSA          0
#endif
#define LIBSSH2_ED25519         0
#define LIBSSH2_MLKEM           0

#include "crypto_config.h"

#if LIBSSH2_MD5 || LIBSSH2_MD5_PEM
#define MD5_DIGEST_LENGTH      16
#endif
#define SHA_DIGEST_LENGTH      20
#define SHA256_DIGEST_LENGTH   32
#define SHA384_DIGEST_LENGTH   48
#define SHA512_DIGEST_LENGTH   64

/*******************************************************************/
/*
 * mbedTLS backend: Generic functions
 */

#define ssh2_crypto_init() ssh2_mbed_crypto_init()
#define ssh2_crypto_exit() ssh2_mbed_crypto_exit()

void ssh2_mbed_crypto_init(void);
void ssh2_mbed_crypto_exit(void);

int ssh2_random(unsigned char *buf, size_t len);

#define ssh2_prepare_iovec(vec, len)  /* Empty. */

/*******************************************************************/
/*
 * mbedTLS backend: HMAC functions
 */

#define ssh2_hmac_ctx mbedtls_md_context_t

/*******************************************************************/
/*
 * mbedTLS backend: SHA1 functions
 */

#define ssh2_sha1_ctx mbedtls_md_context_t

#define ssh2_sha1_init(pctx) \
    ssh2_mbed_hash_init(pctx, MBEDTLS_MD_SHA1, NULL, 0)
#define ssh2_sha1_update(ctx, data, datalen) \
    (mbedtls_md_update(&(ctx), (const unsigned char *)(data), datalen) == 0)
#define ssh2_sha1_final(ctx, hash) \
    ssh2_mbed_hash_final(&(ctx), hash)
#define ssh2_sha1(data, datalen, hash) \
    ssh2_mbed_hash(data, datalen, MBEDTLS_MD_SHA1, hash)

/*******************************************************************/
/*
 * mbedTLS backend: SHA256 functions
 */

#define ssh2_sha256_ctx mbedtls_md_context_t

#define ssh2_sha256_init(pctx) \
    ssh2_mbed_hash_init(pctx, MBEDTLS_MD_SHA256, NULL, 0)
#define ssh2_sha256_update(ctx, data, datalen) \
    (mbedtls_md_update(&(ctx), (const unsigned char *)(data), datalen) == 0)
#define ssh2_sha256_final(ctx, hash) \
    ssh2_mbed_hash_final(&(ctx), hash)
#define ssh2_sha256(data, datalen, hash) \
    ssh2_mbed_hash(data, datalen, MBEDTLS_MD_SHA256, hash)

/*******************************************************************/
/*
 * mbedTLS backend: SHA384 functions
 */

#define ssh2_sha384_ctx mbedtls_md_context_t

#define ssh2_sha384_init(pctx) \
    ssh2_mbed_hash_init(pctx, MBEDTLS_MD_SHA384, NULL, 0)
#define ssh2_sha384_update(ctx, data, datalen) \
    (mbedtls_md_update(&(ctx), (const unsigned char *)(data), datalen) == 0)
#define ssh2_sha384_final(ctx, hash) \
    ssh2_mbed_hash_final(&(ctx), hash)
#define ssh2_sha384(data, datalen, hash) \
    ssh2_mbed_hash(data, datalen, MBEDTLS_MD_SHA384, hash)

/*******************************************************************/
/*
 * mbedTLS backend: SHA512 functions
 */

#define ssh2_sha512_ctx mbedtls_md_context_t

#define ssh2_sha512_init(pctx) \
    ssh2_mbed_hash_init(pctx, MBEDTLS_MD_SHA512, NULL, 0)
#define ssh2_sha512_update(ctx, data, datalen) \
    (mbedtls_md_update(&(ctx), (const unsigned char *)(data), datalen) == 0)
#define ssh2_sha512_final(ctx, hash) \
    ssh2_mbed_hash_final(&(ctx), hash)
#define ssh2_sha512(data, datalen, hash) \
    ssh2_mbed_hash(data, datalen, MBEDTLS_MD_SHA512, hash)

/*******************************************************************/
/*
 * mbedTLS backend: MD5 functions
 */

#if LIBSSH2_MD5 || LIBSSH2_MD5_PEM
#define ssh2_md5_ctx mbedtls_md_context_t

#define ssh2_md5_init(pctx) \
    ssh2_mbed_hash_init(pctx, MBEDTLS_MD_MD5, NULL, 0)
#define ssh2_md5_update(ctx, data, datalen) \
    (mbedtls_md_update(&(ctx), (const unsigned char *)(data), datalen) == 0)
#define ssh2_md5_final(ctx, hash) \
    ssh2_mbed_hash_final(&(ctx), hash)
#endif

int ssh2_mbed_hash_init(mbedtls_md_context_t *ctx,
                        mbedtls_md_type_t mdtype,
                        const unsigned char *key, size_t keylen);
int ssh2_mbed_hash_final(mbedtls_md_context_t *ctx, unsigned char *hash);
int ssh2_mbed_hash(const unsigned char *data, size_t datalen,
                   mbedtls_md_type_t mdtype, unsigned char *hash);

/*******************************************************************/
/*
 * mbedTLS backend: RSA functions
 */

#define ssh2_rsa_ctx mbedtls_rsa_context

/*******************************************************************/
/*
 * mbedTLS backend: ECDSA structures
 */

#if LIBSSH2_ECDSA

#define EC_MAX_POINT_LEN ((528 * 2 / 8) + 1)

typedef enum {
#ifdef MBEDTLS_ECP_DP_SECP256R1_ENABLED
    SSH2_EC_CURVE_NISTP256 = MBEDTLS_ECP_DP_SECP256R1,
#else
    SSH2_EC_CURVE_NISTP256 = MBEDTLS_ECP_DP_NONE,
#endif
#ifdef MBEDTLS_ECP_DP_SECP384R1_ENABLED
    SSH2_EC_CURVE_NISTP384 = MBEDTLS_ECP_DP_SECP384R1,
#else
    SSH2_EC_CURVE_NISTP384 = MBEDTLS_ECP_DP_NONE,
#endif
#ifdef MBEDTLS_ECP_DP_SECP521R1_ENABLED
    SSH2_EC_CURVE_NISTP521 = MBEDTLS_ECP_DP_SECP521R1
#else
    SSH2_EC_CURVE_NISTP521 = MBEDTLS_ECP_DP_NONE,
#endif
} ssh2_curve_type;

#define ssh2_ec_key mbedtls_ecp_keypair
#else
#define ssh2_ec_key void
#endif /* LIBSSH2_ECDSA */

/*******************************************************************/
/*
 * mbedTLS backend: ECDSA functions
 */

#if LIBSSH2_ECDSA
#define ssh2_ecdsa_ctx mbedtls_ecdsa_context
#endif

/*******************************************************************/
/*
 * mbedTLS backend: Cipher Context structure
 */

#define ssh2_cipher_ctx        mbedtls_cipher_context_t

#define SSH2_CIPHER_T(algo)    mbedtls_cipher_type_t algo

#define ssh2_cipher_aes256ctr  MBEDTLS_CIPHER_AES_256_CTR
#define ssh2_cipher_aes192ctr  MBEDTLS_CIPHER_AES_192_CTR
#define ssh2_cipher_aes128ctr  MBEDTLS_CIPHER_AES_128_CTR
#define ssh2_cipher_aes256     MBEDTLS_CIPHER_AES_256_CBC
#define ssh2_cipher_aes192     MBEDTLS_CIPHER_AES_192_CBC
#define ssh2_cipher_aes128     MBEDTLS_CIPHER_AES_128_CBC
#ifdef MBEDTLS_CIPHER_BLOWFISH_CBC
#define ssh2_cipher_blowfish   MBEDTLS_CIPHER_BLOWFISH_CBC
#endif
#ifdef MBEDTLS_CIPHER_ARC4_128
#define ssh2_cipher_arcfour    MBEDTLS_CIPHER_ARC4_128
#endif
#define ssh2_cipher_3des       MBEDTLS_CIPHER_DES_EDE3_CBC
#define ssh2_cipher_chacha20   MBEDTLS_CIPHER_CHACHA20_POLY1305

/*******************************************************************/
/*
 * mbedTLS backend: Cipher functions
 */
#define ssh2_cipher_dtor(ctx)  mbedtls_cipher_free(ctx)

/*******************************************************************/
/*
 * mbedTLS backend: BigNumber Support
 */

#define ssh2_bn_ctx                    int /* not used */
#define ssh2_bn_ctx_new()              0 /* not used */
#define ssh2_bn_ctx_free(bnctx)        ((void)0) /* not used */

#define ssh2_bn                        mbedtls_mpi
#define ssh2_bn_init()                 ssh2_mbed_bn_init()
#define ssh2_bn_init_from_bin()        ssh2_mbed_bn_init()
#define ssh2_bn_set_word(bn, word)     mbedtls_mpi_lset(bn, word)
#define ssh2_bn_from_bin(bn, len, bin) mbedtls_mpi_read_binary(bn, bin, len)
#define ssh2_bn_to_bin(bn, bin) \
    mbedtls_mpi_write_binary(bn, bin, mbedtls_mpi_size(bn))
#define ssh2_bn_bytes(bn)              mbedtls_mpi_size(bn)
#define ssh2_bn_bits(bn)               mbedtls_mpi_bitlen(bn)
#define ssh2_bn_free(bn)               ssh2_mbed_bn_free(bn)

ssh2_bn *ssh2_mbed_bn_init(void);
void ssh2_mbed_bn_free(ssh2_bn *bn);

/*******************************************************************/
/*
 * mbedTLS backend: Diffie-Hellman support.
 */

/* Default generate and safe prime sizes for
   diffie-hellman-group-exchange-sha1 */
#define SSH2_DH_GEX_MINGROUP     2048
#define SSH2_DH_GEX_OPTGROUP     4096
#define SSH2_DH_GEX_MAXGROUP     8192

#define SSH2_DH_MAX_MODULUS_BITS 16384

#define ssh2_dh_ctx mbedtls_mpi *
#define ssh2_dh_key_pair(dhctx, public, g, p, group_order, bnctx) \
    ssh2_mbed_dh_key_pair(dhctx, public, g, p, group_order)
#define ssh2_dh_secret(dhctx, secret, f, p, bnctx) \
    ssh2_mbed_dh_secret(dhctx, secret, f, p)

int ssh2_mbed_dh_key_pair(ssh2_dh_ctx *dhctx, ssh2_bn *public, ssh2_bn *g,
                          ssh2_bn *p, int group_order);
int ssh2_mbed_dh_secret(ssh2_dh_ctx *dhctx, ssh2_bn *secret, ssh2_bn *f,
                        ssh2_bn *p);

#endif /* LIBSSH2_MBEDTLS_H */
