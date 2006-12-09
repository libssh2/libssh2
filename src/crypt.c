/* Copyright (c) 2004-2006, Sara Golemon <sarag@libssh2.org>
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
 */

#include "libssh2_priv.h"
#include <openssl/evp.h>

#ifdef LIBSSH2_CRYPT_NONE
/* {{{ libssh2_crypt_none_crypt
 * Minimalist cipher: VERY secure *wink*
 */
static int libssh2_crypt_none_crypt(LIBSSH2_SESSION *session, unsigned char *buf, void **abstract)
{
	/* Do nothing to the data! */
	return 0;
}
/* }}} */

static LIBSSH2_CRYPT_METHOD libssh2_crypt_method_none = {
	"none",
	8, /* blocksize (SSH2 defines minimum blocksize as 8) */
	0, /* iv_len */
	0, /* secret_len */
	0, /* flags */
	NULL,
	libssh2_crypt_none_crypt,
	NULL
};
#endif

#define MAKE_INIT(name, cipher)						\
	static int name (LIBSSH2_SESSION *session,			\
			 unsigned char *iv, int *free_iv,		\
			 unsigned char *secret, int *free_secret,	\
			 int encrypt, void **abstract)			\
  {									\
	EVP_CIPHER_CTX *ctx = LIBSSH2_ALLOC(session, sizeof(EVP_CIPHER_CTX)); \
	if (!ctx) {							\
		return -1;						\
	}								\
	EVP_CIPHER_CTX_init(ctx);                                       \
	EVP_CipherInit(ctx, cipher, secret, iv, encrypt);               \
	*abstract = ctx;                                                \
	*free_iv = 1;							\
	*free_secret = 1;                                               \
	return 0;                                                       \
  }

MAKE_INIT(aes256_init, EVP_aes_256_cbc())
MAKE_INIT(aes192_init, EVP_aes_192_cbc())
MAKE_INIT(aes128_init, EVP_aes_128_cbc())
MAKE_INIT(blowfish_init, EVP_bf_cbc())
MAKE_INIT(arcfour_init, EVP_rc4())
MAKE_INIT(cast128_init, EVP_cast5_cbc())
MAKE_INIT(des3_init, EVP_des_ede3_cbc())

int crypt(LIBSSH2_SESSION *session, unsigned char *block, void **abstract)
{
	EVP_CIPHER_CTX *ctx = *(EVP_CIPHER_CTX **)abstract;
	int blocksize = ctx->cipher->block_size;
	unsigned char buf[EVP_MAX_BLOCK_LENGTH];
	int ret;

	if (blocksize == 1) {
		/* Hack for arcfour. */
		blocksize = 8;
	}
	ret = EVP_Cipher(ctx, buf, block, blocksize);
	if (ret == 1) {
		memcpy(block, buf, blocksize);
	}
	return ret == 1 ? 0 : 1;
}

int dtor(LIBSSH2_SESSION *session, void **abstract)
{
  EVP_CIPHER_CTX **ctx = (EVP_CIPHER_CTX **)abstract;
  if (ctx && *ctx) {
	EVP_CIPHER_CTX_cleanup(*ctx);
	LIBSSH2_FREE(session, *ctx);
	*abstract = NULL;
  }
  return 0;
}

static LIBSSH2_CRYPT_METHOD libssh2_crypt_method_3des_cbc = {
	"3des-cbc",
	8, /* blocksize */
	8, /* initial value length */
	24, /* secret length */
	0, /* flags */
	&des3_init,
	&crypt,
	&dtor
};

#if OPENSSL_VERSION_NUMBER >= 0x00907000L && !defined(OPENSSL_NO_AES)
static LIBSSH2_CRYPT_METHOD libssh2_crypt_method_aes128_cbc = {
	"aes128-cbc",
	16, /* blocksize */
	16, /* initial value length */
	16, /* secret length -- 16*8 == 128bit */
	0, /* flags */
	&aes128_init,
	&crypt,
	&dtor
};

static LIBSSH2_CRYPT_METHOD libssh2_crypt_method_aes192_cbc = {
	"aes192-cbc",
	16, /* blocksize */
	16, /* initial value length */
	24, /* secret length -- 24*8 == 192bit */
	0, /* flags */
	&aes192_init,
	&crypt,
	&dtor
};

static LIBSSH2_CRYPT_METHOD libssh2_crypt_method_aes256_cbc = {
	"aes256-cbc",
	16, /* blocksize */
	16, /* initial value length */
	32, /* secret length -- 32*8 == 256bit */
	0, /* flags */
	&aes256_init,
	&crypt,
	&dtor
};

/* rijndael-cbc@lysator.liu.se == aes256-cbc */
static LIBSSH2_CRYPT_METHOD libssh2_crypt_method_rijndael_cbc_lysator_liu_se = {
	"rijndael-cbc@lysator.liu.se",
	16, /* blocksize */
	16, /* initial value length */
	32, /* secret length -- 32*8 == 256bit */
	0, /* flags */
	&aes256_init,
	&crypt,
	&dtor
};
#endif /* OPENSSL_VERSION_NUMBER >= 0x00907000L && !defined(OPENSSL_NO_AES)*/

#ifndef OPENSSL_NO_BLOWFISH
static LIBSSH2_CRYPT_METHOD libssh2_crypt_method_blowfish_cbc = {
	"blowfish-cbc",
	8, /* blocksize */
	8, /* initial value length */
	16, /* secret length */
	0, /* flags */
	&blowfish_init,
	&crypt,
	&dtor
};
#endif /* ! OPENSSL_NO_BLOWFISH */

#ifndef OPENSSL_NO_CAST
static LIBSSH2_CRYPT_METHOD libssh2_crypt_method_cast128_cbc = {
	"cast128-cbc",
	8, /* blocksize */
	8, /* initial value length */
	16, /* secret length */
	0, /* flags */
	&cast128_init,
	&crypt,
	&dtor
};
#endif /* ! OPENSSL_NO_CAST */

#ifndef OPENSSL_NO_RC4
static LIBSSH2_CRYPT_METHOD libssh2_crypt_method_arcfour = {
	"arcfour",
	8, /* blocksize */
	8, /* initial value length */
	16, /* secret length */
	0, /* flags */
	&arcfour_init,
	&crypt,
	&dtor
};
#endif /* ! OPENSSL_NO_RC4 */

static LIBSSH2_CRYPT_METHOD *_libssh2_crypt_methods[] = {
#if OPENSSL_VERSION_NUMBER >= 0x00907000L && !defined(OPENSSL_NO_AES)
	&libssh2_crypt_method_aes256_cbc,
	&libssh2_crypt_method_rijndael_cbc_lysator_liu_se, /* == aes256-cbc */
	&libssh2_crypt_method_aes192_cbc,
	&libssh2_crypt_method_aes128_cbc,
#endif /* OPENSSL_VERSION_NUMBER >= 0x00907000L && !defined(OPENSSL_NO_AES) */
#ifndef OPENSSL_NO_BLOWFISH
	&libssh2_crypt_method_blowfish_cbc,
#endif /* ! OPENSSL_NO_BLOWFISH */
#ifndef OPENSSL_NO_RC4
	&libssh2_crypt_method_arcfour,
#endif /* ! OPENSSL_NO_RC4 */
#ifndef OPENSSL_NO_CAST
	&libssh2_crypt_method_cast128_cbc,
#endif /* ! OPENSSL_NO_CAST */
#ifndef OPENSSL_NO_DES
	&libssh2_crypt_method_3des_cbc,
#endif /* ! OPENSSL_NO_DES */
#ifdef LIBSSH2_CRYPT_NONE
 	&libssh2_crypt_method_none,
#endif
	NULL
};

/* Expose to kex.c */
LIBSSH2_CRYPT_METHOD **libssh2_crypt_methods(void) {
	return _libssh2_crypt_methods;
}
