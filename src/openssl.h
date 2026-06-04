#ifndef LIBSSH2_OPENSSL_H
#define LIBSSH2_OPENSSL_H
/* Copyright (C) Simon Josefsson
 * Copyright (C) The Written Word, Inc.
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

#define SSH2_CRYPTO_ENGINE libssh2_openssl

/* disable deprecated warnings in OpenSSL 3 */
#define OPENSSL_SUPPRESS_DEPRECATED

#ifdef LIBSSH2_WOLFSSL

#include <wolfssl/options.h>
#include <wolfssl/openssl/ecdh.h>

#if defined(NO_DSA) || defined(HAVE_FIPS)
#define OPENSSL_NO_DSA
#endif

#if defined(NO_MD5) || defined(HAVE_FIPS)
#define OPENSSL_NO_MD5
#endif

#if !defined(WOLFSSL_RIPEMD) || defined(HAVE_FIPS)
#define OPENSSL_NO_RIPEMD
#endif

#if defined(NO_RC4) || defined(HAVE_FIPS)
#define OPENSSL_NO_RC4
#endif

#ifdef NO_DES3
#define OPENSSL_NO_DES
#endif

/* wolfSSL does not support Blowfish or CAST. */
#define OPENSSL_NO_BF
#define OPENSSL_NO_CAST

#include <wolfssl/openssl/opensslconf.h>
#include <wolfssl/openssl/sha.h>
#include <wolfssl/openssl/rsa.h>
#ifndef OPENSSL_NO_DSA
#include <wolfssl/openssl/dsa.h>
#endif
#ifndef OPENSSL_NO_MD5
#include <wolfssl/openssl/md5.h>
#endif
#include <wolfssl/openssl/err.h>
#include <wolfssl/openssl/evp.h>
#include <wolfssl/openssl/hmac.h>
#include <wolfssl/openssl/bn.h>
#include <wolfssl/openssl/pem.h>
#include <wolfssl/openssl/rand.h>

#else /* !LIBSSH2_WOLFSSL */

#include <openssl/opensslconf.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#ifndef OPENSSL_NO_DSA
#include <openssl/dsa.h>
#endif
#ifndef OPENSSL_NO_MD5
#include <openssl/md5.h>
#endif
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#define USE_OPENSSL_3 1
#include <openssl/core_names.h>
#endif

#endif /* LIBSSH2_WOLFSSL */

#if !defined(LIBRESSL_VERSION_NUMBER) || defined(LIBSSH2_WOLFSSL) || \
    (defined(LIBRESSL_VERSION_NUMBER) && \
    LIBRESSL_VERSION_NUMBER >= 0x3050000fL)
/* For wolfSSL, whether the structs are truly opaque or not, it is best to not
 * rely on their internal data members being exposed publicly. */
# define HAVE_OPAQUE_STRUCTS 1
#endif

#ifdef OPENSSL_NO_RSA
# define LIBSSH2_RSA 0
# define LIBSSH2_RSA_SHA1 0
# define LIBSSH2_RSA_SHA2 0
#else
# define LIBSSH2_RSA 1
# define LIBSSH2_RSA_SHA1 1
# define LIBSSH2_RSA_SHA2 1
#endif

#ifdef OPENSSL_NO_DSA
# define LIBSSH2_DSA 0
#else
# define LIBSSH2_DSA 1
#endif

#if (!defined(OPENSSL_NO_ECDSA) && !defined(OPENSSL_NO_EC)) || \
    (defined(LIBSSH2_WOLFSSL) && defined(HAVE_ECC))
# define LIBSSH2_ECDSA 1
#else
# define LIBSSH2_ECDSA 0
#endif

#if (!defined(LIBSSH2_WOLFSSL) && \
    !defined(LIBRESSL_VERSION_NUMBER)) || \
    (defined(LIBRESSL_VERSION_NUMBER) && \
    LIBRESSL_VERSION_NUMBER >= 0x3070000fL)
# define LIBSSH2_ED25519 1
#else
# define LIBSSH2_ED25519 0
#endif

#if OPENSSL_VERSION_NUMBER >= 0x30500000L && \
    !defined(LIBRESSL_VERSION_NUMBER)
# define LIBSSH2_MLKEM 1
#else
# define LIBSSH2_MLKEM 0
#endif

#ifdef OPENSSL_NO_MD5
# define LIBSSH2_MD5 0
#else
# define LIBSSH2_MD5 1
#endif

#if defined(OPENSSL_NO_RIPEMD) || defined(OPENSSL_NO_RMD160)
# define LIBSSH2_HMAC_RIPEMD 0
#else
# define LIBSSH2_HMAC_RIPEMD 1
#endif

#define LIBSSH2_HMAC_SHA256 1
#define LIBSSH2_HMAC_SHA512 1

#if (!defined(OPENSSL_NO_AES) && !defined(LIBSSH2_WOLFSSL)) || \
    (defined(LIBSSH2_WOLFSSL) && defined(WOLFSSL_AES_COUNTER))
# define LIBSSH2_AES_CTR 1
# define LIBSSH2_AES_CBC 1
#else
# define LIBSSH2_AES_CTR 0
# define LIBSSH2_AES_CBC 0
#endif

/* wolfSSL v5.4.0 is required due to possibly this bug:
   https://github.com/wolfSSL/wolfssl/pull/5205
   Before this release, all libssh2 tests crash with AES-GCM enabled */
#if !defined(OPENSSL_NO_AES) || \
    (defined(LIBSSH2_WOLFSSL) && LIBWOLFSSL_VERSION_HEX >= 0x05004000 && \
    defined(HAVE_AESGCM) && defined(WOLFSSL_AESGCM_STREAM))
# define LIBSSH2_AES_GCM 1
#else
# define LIBSSH2_AES_GCM 0
#endif

#ifdef OPENSSL_NO_BF
# define LIBSSH2_BLOWFISH 0
#else
# define LIBSSH2_BLOWFISH 1
#endif

#ifdef OPENSSL_NO_RC4
# define LIBSSH2_RC4 0
#else
# define LIBSSH2_RC4 1
#endif

#ifdef OPENSSL_NO_CAST
# define LIBSSH2_CAST 0
#else
# define LIBSSH2_CAST 1
#endif

#ifdef OPENSSL_NO_DES
# define LIBSSH2_3DES 0
#else
# define LIBSSH2_3DES 1
#endif

#include "crypto_config.h"

#define EC_MAX_POINT_LEN ((528 * 2 / 8) + 1)

#define ssh2_prepare_iovec(vec, len)  /* Empty. */

#ifdef HAVE_OPAQUE_STRUCTS
#define ssh2_sha1_ctx EVP_MD_CTX *
#else
#define ssh2_sha1_ctx EVP_MD_CTX
#endif

/* returns 0 in case of failure */
int ssh2_ossl_sha1_init(ssh2_sha1_ctx *ctx);
int ssh2_ossl_sha1_update(ssh2_sha1_ctx *ctx, const void *data, size_t len);
int ssh2_ossl_sha1_final(ssh2_sha1_ctx *ctx, unsigned char *out);
int ssh2_ossl_sha1(const unsigned char *message, size_t len,
                   unsigned char *out);
#define ssh2_sha1_init(x)                ssh2_ossl_sha1_init(x)
#define ssh2_sha1_update(ctx, data, len) \
    ssh2_ossl_sha1_update(&(ctx), data, len)
#define ssh2_sha1_final(ctx, out)        ssh2_ossl_sha1_final(&(ctx), out)
#define ssh2_sha1(x, y, z)               ssh2_ossl_sha1(x, y, z)

#ifdef HAVE_OPAQUE_STRUCTS
#define ssh2_sha256_ctx EVP_MD_CTX *
#else
#define ssh2_sha256_ctx EVP_MD_CTX
#endif

/* returns 0 in case of failure */
int ssh2_ossl_sha256_init(ssh2_sha256_ctx *ctx);
int ssh2_ossl_sha256_update(ssh2_sha256_ctx *ctx, const void *data,
                            size_t len);
int ssh2_ossl_sha256_final(ssh2_sha256_ctx *ctx, unsigned char *out);
int ssh2_ossl_sha256(const unsigned char *message, size_t len,
                     unsigned char *out);
#define ssh2_sha256_init(x) ssh2_ossl_sha256_init(x)
#define ssh2_sha256_update(ctx, data, len) \
    ssh2_ossl_sha256_update(&(ctx), data, len)
#define ssh2_sha256_final(ctx, out) ssh2_ossl_sha256_final(&(ctx), out)
#define ssh2_sha256(x, y, z)        ssh2_ossl_sha256(x, y, z)

#ifdef HAVE_OPAQUE_STRUCTS
#define ssh2_sha384_ctx EVP_MD_CTX *
#else
#define ssh2_sha384_ctx EVP_MD_CTX
#endif

/* returns 0 in case of failure */
int ssh2_ossl_sha384_init(ssh2_sha384_ctx *ctx);
int ssh2_ossl_sha384_update(ssh2_sha384_ctx *ctx, const void *data,
                            size_t len);
int ssh2_ossl_sha384_final(ssh2_sha384_ctx *ctx, unsigned char *out);
int ssh2_ossl_sha384(const unsigned char *message, size_t len,
                     unsigned char *out);
#define ssh2_sha384_init(x) ssh2_ossl_sha384_init(x)
#define ssh2_sha384_update(ctx, data, len) \
    ssh2_ossl_sha384_update(&(ctx), data, len)
#define ssh2_sha384_final(ctx, out) ssh2_ossl_sha384_final(&(ctx), out)
#define ssh2_sha384(x, y, z)        ssh2_ossl_sha384(x, y, z)

#ifdef HAVE_OPAQUE_STRUCTS
#define ssh2_sha512_ctx EVP_MD_CTX *
#else
#define ssh2_sha512_ctx EVP_MD_CTX
#endif

/* returns 0 in case of failure */
int ssh2_ossl_sha512_init(ssh2_sha512_ctx *ctx);
int ssh2_ossl_sha512_update(ssh2_sha512_ctx *ctx, const void *data,
                            size_t len);
int ssh2_ossl_sha512_final(ssh2_sha512_ctx *ctx, unsigned char *out);
int ssh2_ossl_sha512(const unsigned char *message, size_t len,
                     unsigned char *out);
#define ssh2_sha512_init(x) ssh2_ossl_sha512_init(x)
#define ssh2_sha512_update(ctx, data, len) \
    ssh2_ossl_sha512_update(&(ctx), data, len)
#define ssh2_sha512_final(ctx, out) ssh2_ossl_sha512_final(&(ctx), out)
#define ssh2_sha512(x, y, z)        ssh2_ossl_sha512(x, y, z)

#if LIBSSH2_MD5 || LIBSSH2_MD5_PEM
#ifdef HAVE_OPAQUE_STRUCTS
#define ssh2_md5_ctx EVP_MD_CTX *
#else
#define ssh2_md5_ctx EVP_MD_CTX
#endif

/* returns 0 in case of failure */
int ssh2_ossl_md5_init(ssh2_md5_ctx *ctx);
int ssh2_ossl_md5_update(ssh2_md5_ctx *ctx, const void *data, size_t len);
int ssh2_ossl_md5_final(ssh2_md5_ctx *ctx, unsigned char *out);
#define ssh2_md5_init(x)                ssh2_ossl_md5_init(x)
#define ssh2_md5_update(ctx, data, len) ssh2_ossl_md5_update(&(ctx), data, len)
#define ssh2_md5_final(ctx, out)        ssh2_ossl_md5_final(&(ctx), out)
#endif /* LIBSSH2_MD5 || LIBSSH2_MD5_PEM */

#ifdef USE_OPENSSL_3
#define ssh2_hmac_ctx EVP_MAC_CTX *
#elif defined(HAVE_OPAQUE_STRUCTS)
#define ssh2_hmac_ctx HMAC_CTX *
#else /* !HAVE_OPAQUE_STRUCTS */
#define ssh2_hmac_ctx HMAC_CTX
#endif /* USE_OPENSSL_3 */

#define ssh2_crypto_exit()

#if LIBSSH2_RSA

#ifdef USE_OPENSSL_3
#define ssh2_rsa_ctx          EVP_PKEY
#define ssh2_rsa_free(rsactx) EVP_PKEY_free(rsactx)
#else
#define ssh2_rsa_ctx          RSA
#define ssh2_rsa_free(rsactx) RSA_free(rsactx)
#endif

#endif /* LIBSSH2_RSA */

#if LIBSSH2_DSA

#ifdef USE_OPENSSL_3
#define ssh2_dsa_ctx          EVP_PKEY
#define ssh2_dsa_free(rsactx) EVP_PKEY_free(rsactx)
#else
#define ssh2_dsa_ctx          DSA
#define ssh2_dsa_free(dsactx) DSA_free(dsactx)
#endif

#endif /* LIBSSH2_DSA */

#if LIBSSH2_ECDSA

#ifdef USE_OPENSSL_3
#define ssh2_ecdsa_ctx            EVP_PKEY
#define ssh2_ecdsa_free(ecdsactx) EVP_PKEY_free(ecdsactx)
#define ssh2_ec_key               EVP_PKEY
#else
#define ssh2_ecdsa_ctx            EC_KEY
#define ssh2_ecdsa_free(ecdsactx) EC_KEY_free(ecdsactx)
#define ssh2_ec_key               EC_KEY
#endif

typedef enum {
    SSH2_EC_CURVE_NISTP256 = NID_X9_62_prime256v1,
    SSH2_EC_CURVE_NISTP384 = NID_secp384r1,
    SSH2_EC_CURVE_NISTP521 = NID_secp521r1
} ssh2_curve_type;
#else /* !LIBSSH2_ECDSA */
#define ssh2_ec_key void
#endif /* LIBSSH2_ECDSA */

#if LIBSSH2_ED25519
#define ssh2_ed25519_ctx       EVP_PKEY
#define ssh2_ed25519_free(ctx) EVP_PKEY_free(ctx)
#endif /* LIBSSH2_ED25519 */

#define SSH2_CIPHER_T(name) const EVP_CIPHER *(*(name))(void)
#ifdef HAVE_OPAQUE_STRUCTS
#define ssh2_cipher_ctx EVP_CIPHER_CTX *
#else
#define ssh2_cipher_ctx EVP_CIPHER_CTX
#endif

#define ssh2_cipher_aes256gcm EVP_aes_256_gcm
#define ssh2_cipher_aes128gcm EVP_aes_128_gcm

#define ssh2_cipher_aes256    EVP_aes_256_cbc
#define ssh2_cipher_aes192    EVP_aes_192_cbc
#define ssh2_cipher_aes128    EVP_aes_128_cbc
#define ssh2_cipher_aes128ctr EVP_aes_128_ctr
#define ssh2_cipher_aes192ctr EVP_aes_192_ctr
#define ssh2_cipher_aes256ctr EVP_aes_256_ctr
#define ssh2_cipher_blowfish  EVP_bf_cbc
#define ssh2_cipher_arcfour   EVP_rc4
#define ssh2_cipher_cast5     EVP_cast5_cbc
#define ssh2_cipher_3des      EVP_des_ede3_cbc
#define ssh2_cipher_chacha20  NULL

#ifdef HAVE_OPAQUE_STRUCTS
#define ssh2_cipher_dtor(ctx) EVP_CIPHER_CTX_free(*(ctx))
#else
#define ssh2_cipher_dtor(ctx) EVP_CIPHER_CTX_cleanup(ctx)
#endif

#define ssh2_bn                   BIGNUM
#define ssh2_bn_ctx               BN_CTX
#define ssh2_bn_ctx_new()         BN_CTX_new()
#define ssh2_bn_ctx_free(bnctx)   BN_CTX_free(bnctx)
#define ssh2_bn_init()            BN_new()
#define ssh2_bn_init_from_bin()   ssh2_bn_init()
#define ssh2_bn_set_word(bn, val) !BN_set_word(bn, val)
int ssh2_bn_from_bin(ssh2_bn *bn, size_t len, const unsigned char *val);
#define ssh2_bn_to_bin(bn, val)   (BN_bn2bin(bn, val) <= 0)
#define ssh2_bn_bytes(bn)         BN_num_bytes(bn)
#define ssh2_bn_bits(bn)          BN_num_bits(bn)
#define ssh2_bn_free(bn)          BN_clear_free(bn)

/* Default generate and safe prime sizes for
   diffie-hellman-group-exchange-sha1 */
#define SSH2_DH_GEX_MINGROUP     2048
#define SSH2_DH_GEX_OPTGROUP     4096
#define SSH2_DH_GEX_MAXGROUP     8192

#define SSH2_DH_MAX_MODULUS_BITS 16384

#define ssh2_dh_ctx BIGNUM *
#define ssh2_dh_init(dhctx) ssh2_ossl_dh_init(dhctx)
#define ssh2_dh_key_pair(dhctx, public, g, p, group_order, bnctx) \
    ssh2_ossl_dh_key_pair(dhctx, public, g, p, group_order, bnctx)
#define ssh2_dh_secret(dhctx, secret, f, p, bnctx) \
    ssh2_ossl_dh_secret(dhctx, secret, f, p, bnctx)
#define ssh2_dh_dtor(dhctx) ssh2_ossl_dh_dtor(dhctx)
void ssh2_ossl_dh_init(ssh2_dh_ctx *dhctx);
int ssh2_ossl_dh_key_pair(ssh2_dh_ctx *dhctx, ssh2_bn *public,
                          ssh2_bn *g, ssh2_bn *p,
                          int group_order,
                          ssh2_bn_ctx *bnctx);
int ssh2_ossl_dh_secret(ssh2_dh_ctx *dhctx, ssh2_bn *secret,
                        ssh2_bn *f, ssh2_bn *p,
                        ssh2_bn_ctx *bnctx);
void ssh2_ossl_dh_dtor(ssh2_dh_ctx *dhctx);

const EVP_CIPHER *ssh2_EVP_aes_128_ctr(void);
const EVP_CIPHER *ssh2_EVP_aes_192_ctr(void);
const EVP_CIPHER *ssh2_EVP_aes_256_ctr(void);

#endif /* LIBSSH2_OPENSSL_H */
