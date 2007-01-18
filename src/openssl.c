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

#include "openssl.h"

int _libssh2_rsa_new(libssh2_rsa_ctx **rsa,
		     const unsigned char *edata,
		     unsigned long elen,
		     const unsigned char *ndata,
		     unsigned long nlen)
{
	*rsa = RSA_new();
	(*rsa)->e = BN_new();
	BN_bin2bn(edata, elen, (*rsa)->e);
	(*rsa)->n = BN_new();
	BN_bin2bn(ndata, nlen, (*rsa)->n);
	return 0;
}

int _libssh2_rsa_sha1_verify(libssh2_rsa_ctx *rsactx,
			     const unsigned char *sig,
			     unsigned long sig_len,
			     const unsigned char *m,
			     unsigned long m_len)
{
	unsigned char hash[SHA_DIGEST_LENGTH];
	int ret;

	SHA1(m, m_len, hash);
	ret = RSA_verify(NID_sha1, hash, SHA_DIGEST_LENGTH,
			 (unsigned char *)sig, sig_len, rsactx);
	return (ret == 1) ? 0 : -1;
}

int _libssh2_dsa_new(libssh2_dsa_ctx **dsactx,
		     const unsigned char *p,
		     unsigned long p_len,
		     const unsigned char *q,
		     unsigned long q_len,
		     const unsigned char *g,
		     unsigned long g_len,
		     const unsigned char *y,
		     unsigned long y_len)
{
	*dsactx = DSA_new();
	(*dsactx)->p = BN_new();
	BN_bin2bn(p, p_len, (*dsactx)->p);
	(*dsactx)->q = BN_new();
	BN_bin2bn(q, q_len, (*dsactx)->q);
	(*dsactx)->g = BN_new();
	BN_bin2bn(g, g_len, (*dsactx)->g);
	(*dsactx)->pub_key = BN_new();
	BN_bin2bn(y, y_len, (*dsactx)->pub_key);
	return 0;
}

int _libssh2_dsa_sha1_verify(libssh2_dsa_ctx *dsactx,
			     const unsigned char *sig,
			     unsigned long sig_len,
			     const unsigned char *m,
			     unsigned long m_len)
{
	unsigned char hash[SHA_DIGEST_LENGTH];
	DSA_SIG dsasig;
	int ret;

	dsasig.r = BN_new();
	BN_bin2bn(sig, 20, dsasig.r);
	dsasig.s = BN_new();
	BN_bin2bn(sig + 20, 20, dsasig.s);

	libssh2_sha1(m, m_len, hash);
	ret = DSA_do_verify(hash, SHA_DIGEST_LENGTH, &dsasig, dsactx);

	return (ret == 1) ? 0 : -1;
}

int _libssh2_cipher_init (_libssh2_cipher_ctx *h,
			  _libssh2_cipher_type(algo),
			  unsigned char *iv,
			  unsigned char *secret,
			  int encrypt)
{
	EVP_CIPHER_CTX_init(h);
	EVP_CipherInit(h, algo(), secret, iv, encrypt);
	return 0;
}

int _libssh2_cipher_crypt(_libssh2_cipher_ctx *ctx,
			  _libssh2_cipher_type(algo),
			  int encrypt,
			  unsigned char *block)
{
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
