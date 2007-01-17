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
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

/* Needed for struct iovec on some platforms */
#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif

#if LIBSSH2_RSA
/* ***********
   * ssh-rsa *
   *********** */

static int libssh2_hostkey_method_ssh_rsa_dtor(LIBSSH2_SESSION *session, void **abstract);

/* {{{ libssh2_hostkey_method_ssh_rsa_init
 * Initialize the server hostkey working area with e/n pair
 */
static int
libssh2_hostkey_method_ssh_rsa_init(LIBSSH2_SESSION *session,
				    unsigned char *hostkey_data,
				    unsigned long hostkey_data_len,
				    void **abstract)
{
	libssh2_rsa_ctx *rsactx;
	unsigned char *s, *e, *n;
	unsigned long len, e_len, n_len;

	(void)hostkey_data_len;

	if (*abstract) {
		libssh2_hostkey_method_ssh_rsa_dtor(session, abstract);
		*abstract = NULL;
	}

	s = hostkey_data;
	len = libssh2_ntohu32(s);
	s += 4;

	if (len != 7 || strncmp((char *)s, "ssh-rsa", 7) != 0) {
		return -1;
	}
	s += 7;

	e_len = libssh2_ntohu32(s);
	s += 4;

	e = s;										s += e_len;
	n_len = libssh2_ntohu32(s);					s += 4;
	n = s;										s += n_len;

	_libssh2_rsa_new (&rsactx, e, e_len, n, n_len);

	*abstract = rsactx;

	return 0;
}
/* }}} */

/* {{{ libssh2_hostkey_method_ssh_rsa_passphrase_cb
 * TODO: Optionally call a passphrase callback specified by the calling program
 */
static int
libssh2_hostkey_method_ssh_rsadsa_passphrase_cb(char *buf, int size,
						int rwflag, char *passphrase)
{
	int passphrase_len = strlen(passphrase);
	(void)rwflag;

	if (passphrase_len > (size - 1)) {
		passphrase_len = size - 1;
	}
	memcpy(buf, passphrase, passphrase_len);
	buf[passphrase_len] = '\0';

    return passphrase_len;
}
/* }}} */

/* {{{ libssh2_hostkey_method_ssh_rsa_initPEM
 * Load a Private Key from a PEM file
 */
static int libssh2_hostkey_method_ssh_rsa_initPEM(LIBSSH2_SESSION *session,
						  const char *privkeyfile, unsigned const char *passphrase, void **abstract)
{
	RSA *rsactx;
	FILE *fp;

	if (*abstract) {
		libssh2_hostkey_method_ssh_rsa_dtor(session, abstract);
		*abstract = NULL;
	}

	fp = fopen((char *)privkeyfile, "r");
	if (!fp) {
		return -1;
	}

	if (!EVP_get_cipherbyname("des")) {
		/* If this cipher isn't loaded it's a pretty good indication that none are.
		 * I have *NO DOUBT* that there's a better way to deal with this ($#&%#$(%$#(
		 * Someone buy me an OpenSSL manual and I'll read up on it.
		 */
		OpenSSL_add_all_ciphers();
	}
	rsactx = PEM_read_RSAPrivateKey(fp, NULL, (void*)libssh2_hostkey_method_ssh_rsadsa_passphrase_cb, (void*)passphrase);
	if (!rsactx) {
		fclose(fp);
		return -1;
	}
	fclose(fp);

	*abstract = rsactx;

	return 0;
}
/* }}} */

/* {{{ libssh2_hostkey_method_ssh_rsa_sign
 * Verify signature created by remote
 */
static int libssh2_hostkey_method_ssh_rsa_sig_verify(LIBSSH2_SESSION *session,
						     const unsigned char *sig,
						     unsigned long sig_len,
						     const unsigned char *m,
						     unsigned long m_len,
						     void **abstract)
{
	libssh2_rsa_ctx *rsactx = (libssh2_rsa_ctx*)(*abstract);
	(void)session;

	/* Skip past keyname_len(4) + keyname(7){"ssh-rsa"} + signature_len(4) */
	sig += 15; sig_len -= 15;
	return _libssh2_rsa_sha1_verify (rsactx, sig, sig_len, m, m_len);
}
/* }}} */

/* {{{ libssh2_hostkey_method_ssh_rsa_sign
 * Sign data to send to remote
 */
static int libssh2_hostkey_method_ssh_rsa_sign(LIBSSH2_SESSION *session, unsigned char **signature, unsigned long *signature_len,
																		 const unsigned char *buf, unsigned long buf_len, void **abstract)
{
	RSA *rsactx = (RSA*)(*abstract);
	int ret;
	unsigned char hash[SHA_DIGEST_LENGTH];
	libssh2_sha1_ctx ctx;
	unsigned char *sig;
	unsigned int sig_len;

	sig_len = RSA_size(rsactx);
	sig = LIBSSH2_ALLOC(session, sig_len);

	if (!sig) {
		return -1;
	}

	libssh2_sha1_init(&ctx);
	libssh2_sha1_update(ctx, buf, buf_len);
	libssh2_sha1_final(ctx, hash);

	ret = RSA_sign(NID_sha1, hash, SHA_DIGEST_LENGTH, sig,
		       &sig_len, rsactx);
	if (!ret) {
		LIBSSH2_FREE(session, sig);
		return -1;
	}

	*signature = sig;
	*signature_len = sig_len;

	return 0;
}
/* }}} */

/* {{{ libssh2_hostkey_method_ssh_rsa_signv
 * Construct a signature from an array of vectors
 */
static int libssh2_hostkey_method_ssh_rsa_signv(LIBSSH2_SESSION *session, unsigned char **signature, unsigned long *signature_len,
																		  unsigned long veccount, const struct iovec datavec[], void **abstract)
{
	RSA *rsactx = (RSA*)(*abstract);
	int ret;
	unsigned int i;
	unsigned char hash[SHA_DIGEST_LENGTH];
	libssh2_sha1_ctx ctx;
	unsigned char *sig;
	unsigned int sig_len;

	sig_len = RSA_size(rsactx);
	sig = LIBSSH2_ALLOC(session, sig_len);

	if (!sig) {
		return -1;
	}

	libssh2_sha1_init(&ctx);
	for(i = 0; i < veccount; i++) {
		libssh2_sha1_update(ctx, datavec[i].iov_base, datavec[i].iov_len);
	}
	libssh2_sha1_final(ctx, hash);

	ret = RSA_sign(NID_sha1, hash, SHA_DIGEST_LENGTH, sig, &sig_len, rsactx);

	if (!ret) {
		LIBSSH2_FREE(session, sig);
		return -1;
	}

	*signature = sig;
	*signature_len = sig_len;

	return 0;
}
/* }}} */

/* {{{ libssh2_hostkey_method_ssh_rsa_dtor
 * Shutdown the hostkey
 */
static int libssh2_hostkey_method_ssh_rsa_dtor(LIBSSH2_SESSION *session,
					       void **abstract)
{
	libssh2_rsa_ctx *rsactx = (libssh2_rsa_ctx*)(*abstract);
	(void)session;

	_libssh2_rsa_free(rsactx);

	*abstract = NULL;

	return 0;
}
/* }}} */

static LIBSSH2_HOSTKEY_METHOD libssh2_hostkey_method_ssh_rsa = {
	"ssh-rsa",
	MD5_DIGEST_LENGTH,
	libssh2_hostkey_method_ssh_rsa_init,
	libssh2_hostkey_method_ssh_rsa_initPEM,
	libssh2_hostkey_method_ssh_rsa_sig_verify,
	libssh2_hostkey_method_ssh_rsa_sign,
	libssh2_hostkey_method_ssh_rsa_signv,
	NULL, /* encrypt */
	libssh2_hostkey_method_ssh_rsa_dtor,
};
#endif /* LIBSSH2_RSA */

#if LIBSSH2_DSA
/* ***********
   * ssh-dss *
   *********** */

static int libssh2_hostkey_method_ssh_dss_dtor(LIBSSH2_SESSION *session, void **abstract);

/* {{{ libssh2_hostkey_method_ssh_dss_init
 * Initialize the server hostkey working area with p/q/g/y set
 */
static int
libssh2_hostkey_method_ssh_dss_init(LIBSSH2_SESSION *session,
				    unsigned char *hostkey_data,
				    unsigned long hostkey_data_len,
				    void **abstract)
{
	DSA *dsactx;
	unsigned char *p, *q, *g, *y, *s;
	unsigned long p_len, q_len, g_len, y_len, len;
	(void)hostkey_data_len;

	if (*abstract) {
		libssh2_hostkey_method_ssh_dss_dtor(session, abstract);
		*abstract = NULL;
	}

	s = hostkey_data;
	len = libssh2_ntohu32(s);					s += 4;
	if (len != 7 || strncmp((char *)s, "ssh-dss", 7) != 0) {
		return -1;
	}											s += 7;

	p_len = libssh2_ntohu32(s);					s += 4;
	p = s;										s += p_len;
	q_len = libssh2_ntohu32(s);					s += 4;
	q = s;										s += q_len;
	g_len = libssh2_ntohu32(s);					s += 4;
	g = s;										s += g_len;
	y_len = libssh2_ntohu32(s);					s += 4;
	y = s;										s += y_len;

	dsactx = DSA_new();
	dsactx->p = BN_new();
	BN_bin2bn(p, p_len, dsactx->p);
	dsactx->q = BN_new();
	BN_bin2bn(q, q_len, dsactx->q);
	dsactx->g = BN_new();
	BN_bin2bn(g, g_len, dsactx->g);
	dsactx->pub_key = BN_new();
	BN_bin2bn(y, y_len, dsactx->pub_key);

	*abstract = dsactx;

	return 0;
}
/* }}} */

/* {{{ libssh2_hostkey_method_ssh_dss_initPEM
 * Load a Private Key from a PEM file
 */
static int libssh2_hostkey_method_ssh_dss_initPEM(LIBSSH2_SESSION *session,
						  const char *privkeyfile,
						  unsigned const char *passphrase,
						  void **abstract)
{
	DSA *dsactx;
	FILE *fp;

	if (*abstract) {
		libssh2_hostkey_method_ssh_dss_dtor(session, abstract);
		*abstract = NULL;
	}

	fp = fopen(privkeyfile, "r");
	if (!fp) {
		return -1;
	}

	if (!EVP_get_cipherbyname("des")) {
		/* If this cipher isn't loaded it's a pretty good indication that none are.
		 * I have *NO DOUBT* that there's a better way to deal with this ($#&%#$(%$#(
		 * Someone buy me an OpenSSL manual and I'll read up on it.
		 */
		OpenSSL_add_all_ciphers();
	}
	dsactx = PEM_read_DSAPrivateKey(fp, NULL, (void*)libssh2_hostkey_method_ssh_rsadsa_passphrase_cb, (void*)passphrase);
	if (!dsactx) {
		fclose(fp);
		return -1;
	}
	fclose(fp);

	*abstract = dsactx;

	return 0;
}
/* }}} */

/* {{{ libssh2_hostkey_method_ssh_dss_sign
 * Verify signature created by remote
 */
static int libssh2_hostkey_method_ssh_dss_sig_verify(LIBSSH2_SESSION *session, const unsigned char *sig, unsigned long sig_len,
																			   const unsigned char *m, unsigned long m_len, void **abstract)
{
	DSA *dsactx = (DSA*)(*abstract);
	unsigned char hash[SHA_DIGEST_LENGTH];
	DSA_SIG dsasig;
	int ret;

	/* Skip past keyname_len(4) + keyname(7){"ssh-dss"} + signature_len(4) */
	sig += 15; sig_len -= 15;
	if (sig_len != 40) {
		libssh2_error(session, LIBSSH2_ERROR_PROTO, "Invalid DSS signature length", 0);
		return -1;
	}
	dsasig.r = BN_new();
	BN_bin2bn(sig, 20, dsasig.r);
	dsasig.s = BN_new();
	BN_bin2bn(sig + 20, 20, dsasig.s);

	libssh2_sha1(m, m_len, hash);
	ret = DSA_do_verify(hash, SHA_DIGEST_LENGTH, &dsasig, dsactx);

	return (ret == 1) ? 0 : -1;
}
/* }}} */

/* {{{ libssh2_hostkey_method_ssh_dss_sign
 * Sign data to send to remote
 */
static int libssh2_hostkey_method_ssh_dss_sign(LIBSSH2_SESSION *session, unsigned char **signature, unsigned long *signature_len,
																		 const unsigned char *buf, unsigned long buf_len, void **abstract)
{
	DSA *dsactx = (DSA*)(*abstract);
	DSA_SIG *sig;
	unsigned char hash[SHA_DIGEST_LENGTH];
	libssh2_sha1_ctx ctx;

	*signature = LIBSSH2_ALLOC(session, 2 * SHA_DIGEST_LENGTH);
	*signature_len = 2 * SHA_DIGEST_LENGTH;

	if (!(*signature)) {
		return -1;
	}

	libssh2_sha1_init(&ctx);
	libssh2_sha1_update(ctx, buf, buf_len);
	libssh2_sha1_final(ctx, hash);

	sig = DSA_do_sign(hash, SHA_DIGEST_LENGTH, dsactx);
	if (!sig) {
		LIBSSH2_FREE(session, *signature);
		return -1;
	}

	BN_bn2bin(sig->r, *signature);
	BN_bn2bin(sig->s, *signature + SHA_DIGEST_LENGTH);

	DSA_SIG_free(sig);

	return 0;
}
/* }}} */

/* {{{ libssh2_hostkey_method_ssh_dss_signv
 * Construct a signature from an array of vectors
 */
static int libssh2_hostkey_method_ssh_dss_signv(LIBSSH2_SESSION *session, unsigned char **signature, unsigned long *signature_len,
																		  unsigned long veccount, const struct iovec datavec[], void **abstract)
{
	DSA *dsactx = (DSA*)(*abstract);
	DSA_SIG *sig;
	unsigned char hash[SHA_DIGEST_LENGTH];
	libssh2_sha1_ctx ctx;
	int r_len, s_len, rs_pad;
	unsigned int i;

	*signature = LIBSSH2_ALLOC(session, 2 * SHA_DIGEST_LENGTH);
	*signature_len = 2 * SHA_DIGEST_LENGTH;
	memset(*signature, 0, 2 * SHA_DIGEST_LENGTH);

	if (!(*signature)) {
		return -1;
	}

	libssh2_sha1_init(&ctx);
	for(i = 0; i < veccount; i++) {
		libssh2_sha1_update(ctx, datavec[i].iov_base, datavec[i].iov_len);
	}
	libssh2_sha1_final(ctx, &hash);

	sig = DSA_do_sign(hash, SHA_DIGEST_LENGTH, dsactx);
	if (!sig) {
		LIBSSH2_FREE(session, *signature);
		return -1;
	}

	r_len = BN_num_bytes(sig->r);
	s_len = BN_num_bytes(sig->s);
	rs_pad = (2 * SHA_DIGEST_LENGTH) - (r_len + s_len);
	if (rs_pad < 0) {
		DSA_SIG_free(sig);
		LIBSSH2_FREE(session, *signature);
		return -1;
	}

	BN_bn2bin(sig->r, *signature + rs_pad);
	BN_bn2bin(sig->s, *signature + rs_pad + r_len);

	DSA_SIG_free(sig);

	return 0;
}
/* }}} */

/* {{{ libssh2_hostkey_method_ssh_dss_dtor
 * Shutdown the hostkey method
 */
static int libssh2_hostkey_method_ssh_dss_dtor(LIBSSH2_SESSION *session,
					       void **abstract)
{
	DSA *dsactx = (DSA*)(*abstract);
	(void)session;

	DSA_free(dsactx);

	*abstract = NULL;

	return 0;
}
/* }}} */

static LIBSSH2_HOSTKEY_METHOD libssh2_hostkey_method_ssh_dss = {
	"ssh-dss",
	MD5_DIGEST_LENGTH,
	libssh2_hostkey_method_ssh_dss_init,
	libssh2_hostkey_method_ssh_dss_initPEM,
	libssh2_hostkey_method_ssh_dss_sig_verify,
	libssh2_hostkey_method_ssh_dss_sign,
	libssh2_hostkey_method_ssh_dss_signv,
	NULL, /* encrypt */
	libssh2_hostkey_method_ssh_dss_dtor,
};
#endif /* LIBSSH2_DSA */

static LIBSSH2_HOSTKEY_METHOD *_libssh2_hostkey_methods[] = {
#if LIBSSH2_RSA
	&libssh2_hostkey_method_ssh_rsa,
#endif /* LIBSSH2_RSA */
#if LIBSSH2_DSA
	&libssh2_hostkey_method_ssh_dss,
#endif /* LIBSSH2_DSA */
	NULL
};

LIBSSH2_HOSTKEY_METHOD **libssh2_hostkey_methods(void)
{
	return _libssh2_hostkey_methods;
}

/* {{{ libssh2_hostkey_hash
 * Returns hash signature
 * Returned buffer should NOT be freed
 * Length of buffer is determined by hash type
 * i.e. MD5 == 16, SHA1 == 20
 */
LIBSSH2_API const char *libssh2_hostkey_hash(LIBSSH2_SESSION *session, int hash_type)
{
	switch (hash_type) {
#if LIBSSH2_MD5
		case LIBSSH2_HOSTKEY_HASH_MD5:
			return (char *)session->server_hostkey_md5;
			break;
#endif /* LIBSSH2_MD5 */
		case LIBSSH2_HOSTKEY_HASH_SHA1:
			return (char *)session->server_hostkey_sha1;
			break;
		default:
			return NULL;
	}
}
/* }}} */


