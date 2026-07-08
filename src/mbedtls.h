#ifndef LIBSSH2_MBEDTLS_H
#define LIBSSH2_MBEDTLS_H
/* Copyright (C) Art <https://github.com/wildart>
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

#define SSH2_CRYPTO_ENGINE libssh2_mbedtls
#define SSH2_CRYPTO_ENGINE_NAME "mbedTLS"

#include <mbedtls/version.h>
#include <mbedtls/platform.h>
#include <psa/crypto_config.h>
#include <psa/crypto.h>
#if MBEDTLS_VERSION_NUMBER < 0x04000000
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
#endif
#include <mbedtls/pk.h>
#include <mbedtls/error.h>

#if MBEDTLS_VERSION_NUMBER < 0x03010000
#  error "mbedTLS 3.1.0 or greater required"
#endif
#if MBEDTLS_VERSION_NUMBER < 0x04000000 && !defined(MBEDTLS_CTR_DRBG_C)
#  error "MBEDTLS_CTR_DRBG_C is required for mbedTLS 3.x."
#endif

/* Define which features are supported. */
#if defined(PSA_WANT_ALG_MD5) && PSA_WANT_ALG_MD5
#define LIBSSH2_MD5 1
#else
#define LIBSSH2_MD5 0
#endif

#if defined(PSA_WANT_ALG_RIPEMD160) && PSA_WANT_ALG_RIPEMD160
#define LIBSSH2_HMAC_RIPEMD 1
#else
#define LIBSSH2_HMAC_RIPEMD 0
#endif
#define LIBSSH2_HMAC_SHA256 1
#define LIBSSH2_HMAC_SHA512 1

#define LIBSSH2_AES_CBC 1
#define LIBSSH2_AES_CTR 1
#define LIBSSH2_AES_GCM 0
#ifdef MBEDTLS_CIPHER_BLOWFISH_CBC
# define LIBSSH2_BLOWFISH 1
#else
# define LIBSSH2_BLOWFISH 0
#endif
#ifdef MBEDTLS_CIPHER_ARC4_128
# define LIBSSH2_RC4 1
#else
# define LIBSSH2_RC4 0
#endif
#define LIBSSH2_CAST 0
#define LIBSSH2_3DES 1

#define LIBSSH2_RSA 1
#define LIBSSH2_RSA_SHA1 1
#define LIBSSH2_RSA_SHA2 1
#define LIBSSH2_DSA 0
#ifdef MBEDTLS_ECDSA_C
# define LIBSSH2_ECDSA 1
#else
# define LIBSSH2_ECDSA 0
#endif
#define LIBSSH2_ED25519 0
#define LIBSSH2_MLKEM 0

#include "crypto_config.h"

/*******************************************************************/
/*
 * mbedTLS backend: HMAC functions
 */

struct mbed_hash_ctx {
    psa_mac_operation_t mac;
    psa_key_id_t key_id;
};

#define ssh2_hmac_ctx struct mbed_hash_ctx

#define ssh2_hmac_update(ctx, d, l) \
    (psa_mac_update(&((ctx)->mac), (const uint8_t *)(d), l) == PSA_SUCCESS)

#if LIBSSH2_HMAC_RIPEMD
#define SSH2_RIPEMD160_HMAC PSA_ALG_RIPEMD160
#endif

/*******************************************************************/
/*
 * mbedTLS backend: hash functions
 */

#define ssh2_hash_ctx   psa_hash_operation_t
#define ssh2_hash_alg   psa_algorithm_t
#define ssh2_hash_update(ctx, d, l) \
    (psa_hash_update(ctx, (const uint8_t *)(d), l) == PSA_SUCCESS)

#define SSH2_SHA1_ALG   PSA_ALG_SHA_1
#define SSH2_SHA256_ALG PSA_ALG_SHA_256
#define SSH2_SHA384_ALG PSA_ALG_SHA_384
#define SSH2_SHA512_ALG PSA_ALG_SHA_512
#if LIBSSH2_MD5 || LIBSSH2_MD5_PEM
#define SSH2_MD5_ALG    PSA_ALG_MD5
#endif

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

#define ssh2_ecdsa_ctx mbedtls_ecdsa_context
#define ssh2_ec_key mbedtls_ecp_keypair
#endif /* LIBSSH2_ECDSA */

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
#define ssh2_bn_set_word(bn, word)     mbedtls_mpi_lset(bn, word)
#define ssh2_bn_from_bin(bn, len, bin) mbedtls_mpi_read_binary(bn, bin, len)
#define ssh2_bn_to_bin(bn, bin) \
    mbedtls_mpi_write_binary(bn, bin, mbedtls_mpi_size(bn))
#define ssh2_bn_bytes(bn)              mbedtls_mpi_size(bn)
#define ssh2_bn_bits(bn)               mbedtls_mpi_bitlen(bn)

/*******************************************************************/
/*
 * mbedTLS backend: Diffie-Hellman support.
 */

#define ssh2_dh_ctx                    mbedtls_mpi *

/* Default generate and safe prime sizes for
   diffie-hellman-group-exchange-sha1 */
#define SSH2_DH_GEX_MINGROUP     2048
#define SSH2_DH_GEX_OPTGROUP     4096
#define SSH2_DH_GEX_MAXGROUP     8192

#define SSH2_DH_MAX_MODULUS_BITS 16384

#endif /* LIBSSH2_MBEDTLS_H */
