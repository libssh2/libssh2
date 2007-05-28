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
                    const unsigned char *hostkey_data,
                    unsigned long hostkey_data_len,
                    void **abstract)
{
    libssh2_rsa_ctx *rsactx;
    const unsigned char *s, *e, *n;
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

    e = s;                                      s += e_len;
    n_len = libssh2_ntohu32(s);                 s += 4;
    n = s;                                      s += n_len;

    if (_libssh2_rsa_new (&rsactx, e, e_len, n, n_len, NULL, 0,
                  NULL, 0, NULL, 0, NULL, 0, NULL, 0, NULL, 0))
      return -1;

    *abstract = rsactx;

    return 0;
}
/* }}} */

/* {{{ libssh2_hostkey_method_ssh_rsa_initPEM
 * Load a Private Key from a PEM file
 */
static int libssh2_hostkey_method_ssh_rsa_initPEM(LIBSSH2_SESSION *session,
                          const char *privkeyfile, unsigned const char *passphrase, void **abstract)
{
    libssh2_rsa_ctx *rsactx;
    FILE *fp;
    int ret;

    if (*abstract) {
        libssh2_hostkey_method_ssh_rsa_dtor(session, abstract);
        *abstract = NULL;
    }

    fp = fopen(privkeyfile, "r");
    if (!fp) {
        return -1;
    }

    ret = _libssh2_rsa_new_private (&rsactx, session, fp, passphrase);
    fclose(fp);
    if (ret) {
        return -1;
    }

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

/* {{{ libssh2_hostkey_method_ssh_rsa_signv
 * Construct a signature from an array of vectors
 */
static int libssh2_hostkey_method_ssh_rsa_signv(LIBSSH2_SESSION *session, unsigned char **signature, unsigned long *signature_len,
                                                                          unsigned long veccount, const struct iovec datavec[], void **abstract)
{
    libssh2_rsa_ctx *rsactx = (libssh2_rsa_ctx*)(*abstract);
    int ret;
    unsigned int i;
    unsigned char hash[SHA_DIGEST_LENGTH];
    libssh2_sha1_ctx ctx;

    libssh2_sha1_init(&ctx);
    for(i = 0; i < veccount; i++) {
        libssh2_sha1_update(ctx, datavec[i].iov_base, datavec[i].iov_len);
    }
    libssh2_sha1_final(ctx, hash);

    ret = _libssh2_rsa_sha1_sign(session, rsactx, hash, SHA_DIGEST_LENGTH,
                     signature, signature_len);
    if (ret) {
        return -1;
    }

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

static const LIBSSH2_HOSTKEY_METHOD libssh2_hostkey_method_ssh_rsa = {
    "ssh-rsa",
    MD5_DIGEST_LENGTH,
    libssh2_hostkey_method_ssh_rsa_init,
    libssh2_hostkey_method_ssh_rsa_initPEM,
    libssh2_hostkey_method_ssh_rsa_sig_verify,
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
                    const unsigned char *hostkey_data,
                    unsigned long hostkey_data_len,
                    void **abstract)
{
    libssh2_dsa_ctx *dsactx;
    const unsigned char *p, *q, *g, *y, *s;
    unsigned long p_len, q_len, g_len, y_len, len;
    (void)hostkey_data_len;

    if (*abstract) {
        libssh2_hostkey_method_ssh_dss_dtor(session, abstract);
        *abstract = NULL;
    }

    s = hostkey_data;
    len = libssh2_ntohu32(s);                   s += 4;
    if (len != 7 || strncmp((char *)s, "ssh-dss", 7) != 0) {
        return -1;
    }                                           s += 7;

    p_len = libssh2_ntohu32(s);                 s += 4;
    p = s;                                      s += p_len;
    q_len = libssh2_ntohu32(s);                 s += 4;
    q = s;                                      s += q_len;
    g_len = libssh2_ntohu32(s);                 s += 4;
    g = s;                                      s += g_len;
    y_len = libssh2_ntohu32(s);                 s += 4;
    y = s;                                      s += y_len;

    _libssh2_dsa_new(&dsactx, p, p_len, q, q_len, g, g_len,
             y, y_len, NULL, 0);

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
    libssh2_dsa_ctx *dsactx;
    FILE *fp;
    int ret;

    if (*abstract) {
        libssh2_hostkey_method_ssh_dss_dtor(session, abstract);
        *abstract = NULL;
    }

    fp = fopen(privkeyfile, "r");
    if (!fp) {
        return -1;
    }

    ret = _libssh2_dsa_new_private (&dsactx, session, fp, passphrase);
    fclose(fp);
    if (ret) {
        return -1;
    }

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
    libssh2_dsa_ctx *dsactx = (libssh2_dsa_ctx*)(*abstract);

    /* Skip past keyname_len(4) + keyname(7){"ssh-dss"} + signature_len(4) */
    sig += 15; sig_len -= 15;
    if (sig_len != 40) {
        libssh2_error(session, LIBSSH2_ERROR_PROTO, "Invalid DSS signature length", 0);
        return -1;
    }
    return _libssh2_dsa_sha1_verify(dsactx, sig, m, m_len);
}
/* }}} */

/* {{{ libssh2_hostkey_method_ssh_dss_signv
 * Construct a signature from an array of vectors
 */
static int libssh2_hostkey_method_ssh_dss_signv(LIBSSH2_SESSION *session, unsigned char **signature, unsigned long *signature_len,
                                                                          unsigned long veccount, const struct iovec datavec[], void **abstract)
{
    libssh2_dsa_ctx *dsactx = (libssh2_dsa_ctx*)(*abstract);
    unsigned char hash[SHA_DIGEST_LENGTH];
    libssh2_sha1_ctx ctx;
    unsigned int i;

    *signature = LIBSSH2_ALLOC(session, 2 * SHA_DIGEST_LENGTH);
    if (!*signature) {
        return -1;
    }

    *signature_len = 2 * SHA_DIGEST_LENGTH;
    memset(*signature, 0, 2 * SHA_DIGEST_LENGTH);

    libssh2_sha1_init(&ctx);
    for(i = 0; i < veccount; i++) {
        libssh2_sha1_update(ctx, datavec[i].iov_base, datavec[i].iov_len);
    }
    libssh2_sha1_final(ctx, hash);

    if (_libssh2_dsa_sha1_sign(dsactx, hash, SHA_DIGEST_LENGTH,
                   *signature))
    {
        LIBSSH2_FREE(session, *signature);
        return -1;
    }

    return 0;
}
/* }}} */

/* {{{ libssh2_hostkey_method_ssh_dss_dtor
 * Shutdown the hostkey method
 */
static int libssh2_hostkey_method_ssh_dss_dtor(LIBSSH2_SESSION *session,
                           void **abstract)
{
    libssh2_dsa_ctx *dsactx = (libssh2_dsa_ctx*)(*abstract);
    (void)session;

    _libssh2_dsa_free(dsactx);

    *abstract = NULL;

    return 0;
}
/* }}} */

static const LIBSSH2_HOSTKEY_METHOD libssh2_hostkey_method_ssh_dss = {
    "ssh-dss",
    MD5_DIGEST_LENGTH,
    libssh2_hostkey_method_ssh_dss_init,
    libssh2_hostkey_method_ssh_dss_initPEM,
    libssh2_hostkey_method_ssh_dss_sig_verify,
    libssh2_hostkey_method_ssh_dss_signv,
    NULL, /* encrypt */
    libssh2_hostkey_method_ssh_dss_dtor,
};
#endif /* LIBSSH2_DSA */

static const LIBSSH2_HOSTKEY_METHOD *_libssh2_hostkey_methods[] = {
#if LIBSSH2_RSA
    &libssh2_hostkey_method_ssh_rsa,
#endif /* LIBSSH2_RSA */
#if LIBSSH2_DSA
    &libssh2_hostkey_method_ssh_dss,
#endif /* LIBSSH2_DSA */
    NULL
};

const LIBSSH2_HOSTKEY_METHOD **libssh2_hostkey_methods(void)
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


