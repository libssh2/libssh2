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

#include <openssl/sha.h>
#ifndef OPENSSL_NO_MD5
#include <openssl/md5.h>
#endif
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/bn.h>
#include <openssl/pem.h>

#ifndef OPENSSL_NO_MD5
# define LIBSSH2_MD5 0
#else
# define LIBSSH2_MD5 1
#endif

#define libssh2_random(buf, len)		\
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

#define libssh2_crypto_init() 1

#define libssh2_rsa_ctx RSA

void _libssh2_rsa_new(libssh2_rsa_ctx **rsa,
		      const unsigned char *edata,
		      unsigned long elen,
		      const unsigned char *ndata,
		      unsigned long nlen);
int _libssh2_rsa_sha1_verify(libssh2_rsa_ctx *rsa,
			     const unsigned char *sig,
			     unsigned long sig_len,
			     const unsigned char *m,
			     unsigned long m_len);

#define _libssh2_rsa_free(rsactx) RSA_free(rsactx)
