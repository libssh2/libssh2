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

#include "libgcrypt.h"

int _libssh2_rsa_new(libssh2_rsa_ctx **rsa,
		     const unsigned char *edata,
		     unsigned long elen,
		     const unsigned char *ndata,
		     unsigned long nlen)
{
	int rc;

	rc = gcry_sexp_build (rsa, NULL, "(public-key(rsa(n%b)(e%b)))",
			      nlen, ndata, elen, edata);
	if (rc)
	{
		*rsa = NULL;
		return -1;
	}

	return 0;
}

int _libssh2_rsa_sha1_verify(libssh2_rsa_ctx *rsa,
			     const unsigned char *sig,
			     unsigned long sig_len,
			     const unsigned char *m,
			     unsigned long m_len)
{
	unsigned char hash[SHA_DIGEST_LENGTH];
	int ret;
	gcry_sexp_t s_sig, s_hash;
	int rc = -1;

	libssh2_sha1(m, m_len, hash);

	rc = gcry_sexp_build (&s_hash, NULL,
			      "(data (flags pkcs1) (hash sha1 %b))",
			      SHA_DIGEST_LENGTH, hash);
	if (rc != 0)
	{
		return -1;
	}

	rc = gcry_sexp_build (&s_sig, NULL, "(sig-val(rsa(s %b)))",
			      sig_len, sig);
	if (rc != 0)
	{
		gcry_sexp_release (s_hash);
		return -1;
	}

	rc = gcry_pk_verify (s_sig, s_hash, rsa);
	gcry_sexp_release (s_sig);
	gcry_sexp_release (s_hash);

	return (rc == 0) ? 0 : -1;
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
  int rc;

  rc = gcry_sexp_build (dsactx, NULL, "(public-key(dsa(p%b)(q%b)(g%b)(y%b)))",
			p_len, p, q_len, q, g_len, g, y_len, y);
  if (rc)
    {
      *dsactx = NULL;
      return -1;
    }

  return 0;
}


int _libssh2_dsa_sha1_verify(libssh2_dsa_ctx *dsactx,
			     const unsigned char *sig,
			     unsigned long sig_len,
			     const unsigned char *m,
			     unsigned long m_len)
{
  unsigned char hash[SHA_DIGEST_LENGTH+1];
  int ret;
  gcry_sexp_t s_sig, s_hash;
  int rc = -1;

  libssh2_sha1(m, m_len, hash+1);
  hash[0] = 0;

  rc = gcry_sexp_build (&s_hash, NULL, "(data(flags raw)(value %b))",
			SHA_DIGEST_LENGTH+1, hash);
  if (rc != 0)
    {
      return -1;
    }

  rc = gcry_sexp_build (&s_sig, NULL, "(sig-val(dsa(r %b)(s %b)))",
			20, sig, 20, sig + 20);
  if (rc != 0)
    {
      gcry_sexp_release (s_hash);
      return -1;
    }

  rc = gcry_pk_verify (s_sig, s_hash, dsactx);
  gcry_sexp_release (s_sig);
  gcry_sexp_release (s_hash);

  return (rc == 0) ? 0 : -1;
}
