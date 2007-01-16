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
