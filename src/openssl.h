/* Copyright (C) 2006, 2007 The Written Word, Inc.  All rights reserved.
 * Author: Simon Josefsson
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
 */

#include <openssl/opensslconf.h>
#include <openssl/sha.h>
#ifndef OPENSSL_NO_MD5
#include <openssl/md5.h>
#endif
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#ifdef OPENSSL_NO_RSA
# define LIBSSH2_RSA 0
#else
# define LIBSSH2_RSA 1
#endif

#ifdef OPENSSL_NO_DSA
# define LIBSSH2_DSA 0
#else
# define LIBSSH2_DSA 1
#endif

#ifdef OPENSSL_NO_MD5
# define LIBSSH2_MD5 0
#else
# define LIBSSH2_MD5 1
#endif

#ifdef OPENSSL_NO_RIPEMD
# define LIBSSH2_HMAC_RIPEMD 0
#else
# define LIBSSH2_HMAC_RIPEMD 1
#endif

#if OPENSSL_VERSION_NUMBER >= 0x00907000L && !defined(OPENSSL_NO_AES)
# define LIBSSH2_AES 1
#else
# define LIBSSH2_AES 0
#endif

#ifdef OPENSSL_NO_BLOWFISH
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

#define libssh2_random(buf, len)        \
  RAND_bytes ((buf), (len))

#define libssh2_sha1_ctx SHA_CTX
#define libssh2_sha1_init(ctx) SHA1_Init(ctx)
#define libssh2_sha1_update(ctx, data, len) SHA1_Update(&(ctx), data, len)
#define libssh2_sha1_final(ctx, out) SHA1_Final(out, &(ctx))
#define libssh2_sha1(message, len, out) SHA1(message, len, out)

#define libssh2_md5_ctx MD5_CTX
#define libssh2_md5_init(ctx) MD5_Init(ctx)
#define libssh2_md5_update(ctx, data, len) MD5_Update(&(ctx), data, len)
#define libssh2_md5_final(ctx, out) MD5_Final(out, &(ctx))
#define libssh2_md5(message, len, out) MD5(message, len, out)

#define libssh2_hmac_ctx HMAC_CTX
#define libssh2_hmac_sha1_init(ctx, key, keylen) \
  HMAC_Init(ctx, key, keylen, EVP_sha1())
#define libssh2_hmac_md5_init(ctx, key, keylen) \
  HMAC_Init(ctx, key, keylen, EVP_md5())
#define libssh2_hmac_ripemd160_init(ctx, key, keylen) \
  HMAC_Init(ctx, key, keylen, EVP_ripemd160())
#define libssh2_hmac_update(ctx, data, datalen) \
  HMAC_Update(&(ctx), data, datalen)
#define libssh2_hmac_final(ctx, data) HMAC_Final(&(ctx), data, NULL)
#define libssh2_hmac_cleanup(ctx) HMAC_cleanup(ctx)

#define libssh2_crypto_init()

#define libssh2_rsa_ctx RSA

int _libssh2_rsa_new(libssh2_rsa_ctx **rsa,
             const unsigned char *edata,
             unsigned long elen,
             const unsigned char *ndata,
             unsigned long nlen,
             const unsigned char *ddata,
             unsigned long dlen,
             const unsigned char *pdata,
             unsigned long plen,
             const unsigned char *qdata,
             unsigned long qlen,
             const unsigned char *e1data,
             unsigned long e1len,
             const unsigned char *e2data,
             unsigned long e2len,
             const unsigned char *coeffdata,
             unsigned long coefflen);
int _libssh2_rsa_new_private (libssh2_rsa_ctx **rsa,
                  LIBSSH2_SESSION *session,
                  FILE *fp,
                  unsigned const char *passphrase);
int _libssh2_rsa_sha1_verify(libssh2_rsa_ctx *rsa,
                 const unsigned char *sig,
                 unsigned long sig_len,
                 const unsigned char *m,
                 unsigned long m_len);
int _libssh2_rsa_sha1_sign(LIBSSH2_SESSION *session,
               libssh2_rsa_ctx *rsactx,
               const unsigned char *hash,
               unsigned long hash_len,
               unsigned char **signature,
               unsigned long *signature_len);

#define _libssh2_rsa_free(rsactx) RSA_free(rsactx)

#define libssh2_dsa_ctx DSA

int _libssh2_dsa_new(libssh2_dsa_ctx **dsa,
             const unsigned char *pdata,
             unsigned long plen,
             const unsigned char *qdata,
             unsigned long qlen,
             const unsigned char *gdata,
             unsigned long glen,
             const unsigned char *ydata,
             unsigned long ylen,
             const unsigned char *x,
             unsigned long x_len);
int _libssh2_dsa_new_private (libssh2_dsa_ctx **dsa,
                  LIBSSH2_SESSION *session,
                  FILE *fp,
                  unsigned const char *passphrase);
int _libssh2_dsa_sha1_verify(libssh2_dsa_ctx *dsactx,
                 const unsigned char *sig,
                 const unsigned char *m,
                 unsigned long m_len);
int _libssh2_dsa_sha1_sign(libssh2_dsa_ctx *dsactx,
               const unsigned char *hash,
               unsigned long hash_len,
               unsigned char *sig);

#define _libssh2_dsa_free(dsactx) DSA_free(dsactx)

#define _libssh2_cipher_type(name) const EVP_CIPHER *(*name)(void)
#define _libssh2_cipher_ctx EVP_CIPHER_CTX

#define _libssh2_cipher_aes256 EVP_aes_256_cbc
#define _libssh2_cipher_aes192 EVP_aes_192_cbc
#define _libssh2_cipher_aes128 EVP_aes_128_cbc
#define _libssh2_cipher_blowfish EVP_bf_cbc
#define _libssh2_cipher_arcfour EVP_rc4
#define _libssh2_cipher_cast5 EVP_cast5_cbc
#define _libssh2_cipher_3des EVP_des_ede3_cbc

int _libssh2_cipher_init (_libssh2_cipher_ctx *h,
              _libssh2_cipher_type(algo),
              unsigned char *iv,
              unsigned char *secret,
              int encrypt);

int _libssh2_cipher_crypt(_libssh2_cipher_ctx *ctx,
              _libssh2_cipher_type(algo),
              int encrypt,
              unsigned char *block);

#define _libssh2_cipher_dtor(ctx) EVP_CIPHER_CTX_cleanup(ctx)

#define _libssh2_bn BIGNUM
#define _libssh2_bn_ctx BN_CTX
#define _libssh2_bn_ctx_new() BN_CTX_new()
#define _libssh2_bn_ctx_free(bnctx) BN_CTX_free(bnctx)
#define _libssh2_bn_init() BN_new()
#define _libssh2_bn_rand(bn, bits, top, bottom) BN_rand(bn, bits, top, bottom)
#define _libssh2_bn_mod_exp(r, a, p, m, ctx) BN_mod_exp(r, a, p, m, ctx)
#define _libssh2_bn_set_word(bn, val) BN_set_word(bn, val)
#define _libssh2_bn_from_bin(bn, len, val) BN_bin2bn(val, len, bn)
#define _libssh2_bn_to_bin(bn, val) BN_bn2bin(bn, val)
#define _libssh2_bn_bytes(bn) BN_num_bytes(bn)
#define _libssh2_bn_bits(bn) BN_num_bits(bn)
#define _libssh2_bn_free(bn) BN_clear_free(bn)
