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

#include <gcrypt.h>

#define LIBSSH2_MD5 1

#define LIBSSH2_HMAC_RIPEMD 1

#define LIBSSH2_AES 1
#define LIBSSH2_BLOWFISH 1
#define LIBSSH2_RC4 1
#define LIBSSH2_CAST 1
#define LIBSSH2_3DES 1

#define LIBSSH2_RSA 1
#define LIBSSH2_DSA 1

#define MD5_DIGEST_LENGTH 16
#define SHA_DIGEST_LENGTH 20

#define libssh2_random(buf, len)				\
  (gcry_randomize ((buf), (len), GCRY_STRONG_RANDOM), 1)

#define libssh2_sha1_ctx gcry_md_hd_t
#define libssh2_sha1_init(ctx) gcry_md_open (ctx,  GCRY_MD_SHA1, 0);
#define libssh2_sha1_update(ctx, data, len) gcry_md_write (ctx, data, len)
#define libssh2_sha1_final(ctx, out) \
  memcpy (out, gcry_md_read (ctx, 0), 20), gcry_md_close (ctx)
#define libssh2_sha1(message, len, out) \
  gcry_md_hash_buffer (GCRY_MD_SHA1, out, message, len)

#define libssh2_md5_ctx gcry_md_hd_t
#define libssh2_md5_init(ctx) gcry_md_open (ctx,  GCRY_MD_MD5, 0);
#define libssh2_md5_update(ctx, data, len) gcry_md_write (ctx, data, len)
#define libssh2_md5_final(ctx, out) \
  memcpy (out, gcry_md_read (ctx, 0), 20), gcry_md_close (ctx)
#define libssh2_md5(message, len, out) \
  gcry_md_hash_buffer (GCRY_MD_MD5, out, message, len)

#define libssh2_hmac_ctx gcry_md_hd_t
#define libssh2_hmac_sha1_init(ctx, key, keylen) \
  gcry_md_open (ctx, GCRY_MD_SHA1, GCRY_MD_FLAG_HMAC), \
    gcry_md_setkey (*ctx, key, keylen)
#define libssh2_hmac_md5_init(ctx, key, keylen) \
  gcry_md_open (ctx, GCRY_MD_MD5, GCRY_MD_FLAG_HMAC), \
    gcry_md_setkey (*ctx, key, keylen)
#define libssh2_hmac_ripemd160_init(ctx, key, keylen) \
  gcry_md_open (ctx, GCRY_MD_RMD160, GCRY_MD_FLAG_HMAC), \
    gcry_md_setkey (*ctx, key, keylen)
#define libssh2_hmac_update(ctx, data, datalen) \
  gcry_md_write (ctx, data, datalen)
#define libssh2_hmac_final(ctx, data) \
  memcpy (data, gcry_md_read (ctx, 0), \
	  gcry_md_get_algo_dlen (gcry_md_get_algo (ctx)))
#define libssh2_hmac_cleanup(ctx) gcry_md_close (*ctx);

#define libssh2_crypto_init() gcry_control (GCRYCTL_DISABLE_SECMEM)

#define libssh2_rsa_ctx struct gcry_sexp

int _libssh2_rsa_new(libssh2_rsa_ctx **rsa,
		     const unsigned char *edata,
		     unsigned long elen,
		     const unsigned char *ndata,
		     unsigned long nlen);
int _libssh2_rsa_sha1_verify(libssh2_rsa_ctx *rsa,
			     const unsigned char *sig,
			     unsigned long sig_len,
			     const unsigned char *m,
			     unsigned long m_len);

#define _libssh2_rsa_free(rsactx)  gcry_sexp_release (rsactx)

#define libssh2_dsa_ctx struct gcry_sexp

int _libssh2_dsa_new(libssh2_dsa_ctx **dsa,
		     const unsigned char *pdata,
		     unsigned long plen,
		     const unsigned char *qdata,
		     unsigned long qlen,
		     const unsigned char *gdata,
		     unsigned long glen,
		     const unsigned char *ydata,
		     unsigned long ylen);
int _libssh2_dsa_sha1_verify(libssh2_dsa_ctx *dsa,
			     const unsigned char *sig,
			     unsigned long sig_len,
			     const unsigned char *m,
			     unsigned long m_len);

#define _libssh2_dsa_free(dsactx)  gcry_sexp_release (dsactx)

#define _libssh2_cipher_type(name) int name
#define _libssh2_cipher_ctx gcry_cipher_hd_t

#define _libssh2_cipher_aes256 GCRY_CIPHER_AES256
#define _libssh2_cipher_aes192 GCRY_CIPHER_AES192
#define _libssh2_cipher_aes128 GCRY_CIPHER_AES128
#define _libssh2_cipher_blowfish GCRY_CIPHER_BLOWFISH
#define _libssh2_cipher_arcfour GCRY_CIPHER_ARCFOUR
#define _libssh2_cipher_cast5 GCRY_CIPHER_CAST5
#define _libssh2_cipher_3des GCRY_CIPHER_3DES

int _libssh2_cipher_init (_libssh2_cipher_ctx *h,
			  _libssh2_cipher_type(algo),
			  unsigned char *iv,
			  unsigned char *secret,
			  int encrypt);

int _libssh2_cipher_crypt(_libssh2_cipher_ctx *ctx,
			  _libssh2_cipher_type(algo),
			  int encrypt,
			  unsigned char *block);

#define _libssh2_cipher_dtor(ctx) gcry_cipher_close(*(ctx))
