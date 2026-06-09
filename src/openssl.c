/* Copyright (C) Simon Josefsson
 * Copyright (C) The Written Word, Inc.
 * Copyright (C) Sara Golemon <sarag@libssh2.org>
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

#include "libssh2_priv.h"

#if defined(LIBSSH2_OPENSSL) || defined(LIBSSH2_WOLFSSL)

#include <stdlib.h>
#include <assert.h>

int ssh2_hmac_ctx_init(ssh2_hmac_ctx *ctx)
{
#ifdef USE_OPENSSL_3
    *ctx = NULL;
    return 1;
#elif defined(HAVE_OPAQUE_STRUCTS)
    *ctx = HMAC_CTX_new();
    return *ctx ? 1 : 0;
#else
    HMAC_CTX_init(ctx);
    return 1;
#endif
}

#ifdef USE_OPENSSL_3
static int ossl_hmac_init(ssh2_hmac_ctx *ctx,
                     void *key, size_t keylen,
                     const char *digest_name)
{
    EVP_MAC *mac;
    OSSL_PARAM params[3];

    mac = EVP_MAC_fetch(NULL, OSSL_MAC_NAME_HMAC, NULL);
    if(!mac)
        return 0;

    *ctx = EVP_MAC_CTX_new(mac);
    EVP_MAC_free(mac);
    if(!*ctx)
        return 0;

    params[0] = OSSL_PARAM_construct_octet_string(
        OSSL_MAC_PARAM_KEY, (void *)key, keylen);
    params[1] = OSSL_PARAM_construct_utf8_string(
        OSSL_MAC_PARAM_DIGEST, (char *)SSH2_UNCONST(digest_name), 0);
    params[2] = OSSL_PARAM_construct_end();

    return EVP_MAC_init(*ctx, NULL, 0, params);
}
#endif

#if LIBSSH2_MD5
int ssh2_hmac_md5_init(ssh2_hmac_ctx *ctx, void *key, size_t keylen)
{
#ifdef USE_OPENSSL_3
    return ossl_hmac_init(ctx, key, keylen, OSSL_DIGEST_NAME_MD5);
#elif defined(HAVE_OPAQUE_STRUCTS)
    return HMAC_Init_ex(*ctx, key, (int)keylen, EVP_md5(), NULL);
#else
    return HMAC_Init_ex(ctx, key, (int)keylen, EVP_md5(), NULL);
#endif
}
#endif

#if LIBSSH2_HMAC_RIPEMD
int ssh2_hmac_ripemd160_init(ssh2_hmac_ctx *ctx, void *key, size_t keylen)
{
#ifdef USE_OPENSSL_3
    return ossl_hmac_init(ctx, key, keylen, OSSL_DIGEST_NAME_RIPEMD160);
#elif defined(HAVE_OPAQUE_STRUCTS)
    return HMAC_Init_ex(*ctx, key, (int)keylen, EVP_ripemd160(), NULL);
#else
    return HMAC_Init_ex(ctx, key, (int)keylen, EVP_ripemd160(), NULL);
#endif
}
#endif

int ssh2_hmac_sha1_init(ssh2_hmac_ctx *ctx, void *key, size_t keylen)
{
#ifdef USE_OPENSSL_3
    return ossl_hmac_init(ctx, key, keylen, OSSL_DIGEST_NAME_SHA1);
#elif defined(HAVE_OPAQUE_STRUCTS)
    return HMAC_Init_ex(*ctx, key, (int)keylen, EVP_sha1(), NULL);
#else
    return HMAC_Init_ex(ctx, key, (int)keylen, EVP_sha1(), NULL);
#endif
}

int ssh2_hmac_sha256_init(ssh2_hmac_ctx *ctx, void *key, size_t keylen)
{
#ifdef USE_OPENSSL_3
    return ossl_hmac_init(ctx, key, keylen, OSSL_DIGEST_NAME_SHA2_256);
#elif defined(HAVE_OPAQUE_STRUCTS)
    return HMAC_Init_ex(*ctx, key, (int)keylen, EVP_sha256(), NULL);
#else
    return HMAC_Init_ex(ctx, key, (int)keylen, EVP_sha256(), NULL);
#endif
}

int ssh2_hmac_sha512_init(ssh2_hmac_ctx *ctx, void *key, size_t keylen)
{
#ifdef USE_OPENSSL_3
    return ossl_hmac_init(ctx, key, keylen, OSSL_DIGEST_NAME_SHA2_512);
#elif defined(HAVE_OPAQUE_STRUCTS)
    return HMAC_Init_ex(*ctx, key, (int)keylen, EVP_sha512(), NULL);
#else
    return HMAC_Init_ex(ctx, key, (int)keylen, EVP_sha512(), NULL);
#endif
}

int ssh2_hmac_update(ssh2_hmac_ctx *ctx, const void *data, size_t datalen)
{
#ifdef USE_OPENSSL_3
    return EVP_MAC_update(*ctx, data, datalen);
#elif defined(HAVE_OPAQUE_STRUCTS)
/* FIXME: upstream bug as of v5.7.0: datalen is int instead of size_t */
#ifdef LIBSSH2_WOLFSSL
    return HMAC_Update(*ctx, data, (int)datalen);
#else /* !LIBSSH2_WOLFSSL */
    return HMAC_Update(*ctx, data, datalen);
#endif /* LIBSSH2_WOLFSSL */
#else
    return HMAC_Update(ctx, data, datalen);
#endif
}

int ssh2_hmac_final(ssh2_hmac_ctx *ctx, void *data)
{
#ifdef USE_OPENSSL_3
    return EVP_MAC_final(*ctx, data, NULL, MAX_MACSIZE);
#elif defined(HAVE_OPAQUE_STRUCTS)
    return HMAC_Final(*ctx, data, NULL);
#else
    return HMAC_Final(ctx, data, NULL);
#endif
}

void ssh2_hmac_cleanup(ssh2_hmac_ctx *ctx)
{
#ifdef USE_OPENSSL_3
    EVP_MAC_CTX_free(*ctx);
#elif defined(HAVE_OPAQUE_STRUCTS)
    HMAC_CTX_free(*ctx);
#else
    HMAC_cleanup(ctx);
#endif
}

static int ossl_key_from_openssh_blob(LIBSSH2_SESSION *session,
                                      void **key_ctx,
                                      const char *key_type,
                                      unsigned char **method,
                                      size_t *method_len,
                                      unsigned char **pubkeydata,
                                      size_t *pubkeydata_len,
                                      const char *privatekeydata,
                                      size_t privatekeydata_len,
                                      const unsigned char *passphrase);

static int ossl_key_sk_from_openssh_blob(LIBSSH2_SESSION *session,
                                         void **key_ctx,
                                         const char *key_type,
                                         unsigned char **method,
                                         size_t *method_len,
                                         unsigned char **pubkeydata,
                                         size_t *pubkeydata_len,
                                         int *algorithm,
                                         unsigned char *flags,
                                         const char **application,
                                         const unsigned char **key_handle,
                                         size_t *handle_len,
                                         const char *privatekeydata,
                                         size_t privatekeydata_len,
                                         const unsigned char *passphrase);

#if LIBSSH2_RSA || LIBSSH2_DSA || LIBSSH2_ECDSA
static unsigned char *ossl_write_bn(unsigned char *buf, const BIGNUM *bn,
                                    int bn_bytes)
{
    unsigned char *p = buf;

    /* Left space for bn size which is written below. */
    p += 4;

    *p = 0;
    BN_bn2bin(bn, p + 1);

    if(!(*(p + 1) & 0x80))
        memmove(p, p + 1, --bn_bytes);

    ssh2_htonu32(p - 4, bn_bytes);  /* Post write bn size. */

    return p + bn_bytes;
}
#endif

#ifdef USE_OPENSSL_3
static SSH2_INLINE void ossl_swap_bytes(unsigned char *buf, unsigned long len)
{
#if !defined(WORDS_BIGENDIAN) || !WORDS_BIGENDIAN
    unsigned long i, j;
    unsigned char temp;
    for(i = 0, j = len - 1; i < j; i++, j--) {
        temp = buf[i];
        buf[i] = buf[j];
        buf[j] = temp;
    }
#endif
}
#endif

int ssh2_random(unsigned char *buf, size_t len)
{
    if(len > INT_MAX)
        return -1;

    return RAND_bytes(buf, (int)len) == 1 ? 0 : -1;
}

#if LIBSSH2_RSA
int ssh2_rsa_new(ssh2_rsa_ctx **rsa,
                 const unsigned char *edata, unsigned long elen,
                 const unsigned char *ndata, unsigned long nlen,
                 const unsigned char *ddata, unsigned long dlen,
                 const unsigned char *pdata, unsigned long plen,
                 const unsigned char *qdata, unsigned long qlen,
                 const unsigned char *e1data, unsigned long e1len,
                 const unsigned char *e2data, unsigned long e2len,
                 const unsigned char *coeffdata, unsigned long coefflen)
{
#ifdef USE_OPENSSL_3
    int ret = 0;
    EVP_PKEY_CTX *ctx;
    OSSL_PARAM params[4];
    int param_num = 0;
    unsigned char *nbuf = NULL;
    unsigned char *ebuf = NULL;
    unsigned char *dbuf = NULL;

    (void)pdata;
    (void)plen;
    (void)qdata;
    (void)qlen;
    (void)e1data;
    (void)e1len;
    (void)e2data;
    (void)e2len;
    (void)coeffdata;
    (void)coefflen;

    if(ndata && nlen > 0) {
        nbuf = OPENSSL_malloc(nlen);

        if(nbuf) {
            memcpy(nbuf, ndata, nlen);
            ossl_swap_bytes(nbuf, nlen);
            params[param_num++] =
                OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_N, nbuf, nlen);
        }
    }

    if(edata && elen > 0) {
        ebuf = OPENSSL_malloc(elen);
        if(ebuf) {
            memcpy(ebuf, edata, elen);
            ossl_swap_bytes(ebuf, elen);
            params[param_num++] =
                OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_E, ebuf, elen);
        }
    }

    if(ddata && dlen > 0) {
        dbuf = OPENSSL_malloc(dlen);
        if(dbuf) {
            memcpy(dbuf, ddata, dlen);
            ossl_swap_bytes(dbuf, dlen);
            params[param_num++] =
                OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_D, dbuf, dlen);
        }
    }

    params[param_num] = OSSL_PARAM_construct_end();

    *rsa = NULL;
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);

    if(EVP_PKEY_fromdata_init(ctx) > 0)
        ret = EVP_PKEY_fromdata(ctx, rsa, EVP_PKEY_KEYPAIR, params);

    if(nbuf)
        OPENSSL_clear_free(nbuf, nlen);
    if(ebuf)
        OPENSSL_clear_free(ebuf, elen);
    if(dbuf)
        OPENSSL_clear_free(dbuf, dlen);

    EVP_PKEY_CTX_free(ctx);

    return (ret == 1) ? 0 : -1;
#else
    BIGNUM *e;
    BIGNUM *n;
    BIGNUM *d = 0;
    BIGNUM *p = 0;
    BIGNUM *q = 0;
    BIGNUM *dmp1 = 0;
    BIGNUM *dmq1 = 0;
    BIGNUM *iqmp = 0;

    e = BN_new();
    BN_bin2bn(edata, (int)elen, e);

    n = BN_new();
    BN_bin2bn(ndata, (int)nlen, n);

    if(ddata) {
        d = BN_new();
        BN_bin2bn(ddata, (int)dlen, d);

        p = BN_new();
        BN_bin2bn(pdata, (int)plen, p);

        q = BN_new();
        BN_bin2bn(qdata, (int)qlen, q);

        dmp1 = BN_new();
        BN_bin2bn(e1data, (int)e1len, dmp1);

        dmq1 = BN_new();
        BN_bin2bn(e2data, (int)e2len, dmq1);

        iqmp = BN_new();
        BN_bin2bn(coeffdata, (int)coefflen, iqmp);
    }

    *rsa = RSA_new();
#ifdef HAVE_OPAQUE_STRUCTS
    RSA_set0_key(*rsa, n, e, d);
#else
    (*rsa)->e = e;
    (*rsa)->n = n;
    (*rsa)->d = d;
#endif

#ifdef HAVE_OPAQUE_STRUCTS
    RSA_set0_factors(*rsa, p, q);
#else
    (*rsa)->p = p;
    (*rsa)->q = q;
#endif

#ifdef HAVE_OPAQUE_STRUCTS
    RSA_set0_crt_params(*rsa, dmp1, dmq1, iqmp);
#else
    (*rsa)->dmp1 = dmp1;
    (*rsa)->dmq1 = dmq1;
    (*rsa)->iqmp = iqmp;
#endif
    return 0;

#endif /* USE_OPENSSL_3 */
}

int ssh2_rsa_sha2_verify(ssh2_rsa_ctx *rsactx, size_t hash_len,
                         const unsigned char *sig, size_t sig_len,
                         const unsigned char *m, size_t m_len)
{
#ifdef USE_OPENSSL_3
    EVP_PKEY_CTX *ctx = NULL;
    const EVP_MD *md = NULL;
#endif

    int ret;
    int nid_type;
    unsigned char *hash = malloc(hash_len);
    if(!hash)
        return -1;

    if(hash_len == SHA_DIGEST_LENGTH) {
        nid_type = NID_sha1;
        ret = ssh2_ossl_sha1(m, m_len, hash);
    }
    else if(hash_len == SHA256_DIGEST_LENGTH) {
        nid_type = NID_sha256;
        ret = ssh2_ossl_sha256(m, m_len, hash);
    }
    else if(hash_len == SHA512_DIGEST_LENGTH) {
        nid_type = NID_sha512;
        ret = ssh2_ossl_sha512(m, m_len, hash);
    }
    else {
        nid_type = 0;
        ret = -1; /* unsupported digest */
    }

    if(ret) {
        free(hash);
        return -1; /* failure */
    }

#ifdef USE_OPENSSL_3
    ctx = EVP_PKEY_CTX_new(rsactx, NULL);

    if(nid_type == NID_sha1)
        md = EVP_sha1();
    else if(nid_type == NID_sha256)
        md = EVP_sha256();
    else if(nid_type == NID_sha512)
        md = EVP_sha512();

    if(ctx && md) {
        if(EVP_PKEY_verify_init(ctx) > 0 &&
           EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) > 0 &&
           EVP_PKEY_CTX_set_signature_md(ctx, md) > 0) {
            ret = EVP_PKEY_verify(ctx, sig, sig_len, hash, hash_len);
        }
    }

    if(ctx)
        EVP_PKEY_CTX_free(ctx);

#else

    ret = RSA_verify(nid_type, hash, (unsigned int)hash_len,
                     (const unsigned char *)sig,
                     (unsigned int)sig_len, rsactx);
#endif

    free(hash);

    return (ret == 1) ? 0 : -1;
}

#if LIBSSH2_RSA_SHA1
int ssh2_rsa_sha1_verify(ssh2_rsa_ctx *rsactx,
                         const unsigned char *sig, size_t sig_len,
                         const unsigned char *m, size_t m_len)
{
    return ssh2_rsa_sha2_verify(rsactx, SHA_DIGEST_LENGTH, sig, sig_len, m,
                                m_len);
}
#endif
#endif /* LIBSSH_RSA */

#if LIBSSH2_DSA
int ssh2_dsa_new(ssh2_dsa_ctx **dsactx,
                 const unsigned char *p, unsigned long p_len,
                 const unsigned char *q, unsigned long q_len,
                 const unsigned char *g, unsigned long g_len,
                 const unsigned char *y, unsigned long y_len,
                 const unsigned char *x, unsigned long x_len)
{
#ifdef USE_OPENSSL_3
    int ret = 0;
    EVP_PKEY_CTX *ctx = NULL;
    OSSL_PARAM params[6];
    int param_num = 0;
    unsigned char *p_buf = NULL;
    unsigned char *q_buf = NULL;
    unsigned char *g_buf = NULL;
    unsigned char *y_buf = NULL;
    unsigned char *x_buf = NULL;

    if(p && p_len > 0) {
        p_buf = OPENSSL_malloc(p_len);

        if(p_buf) {
            memcpy(p_buf, p, p_len);
            ossl_swap_bytes(p_buf, p_len);
            params[param_num++] =
                OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_FFC_P, p_buf, p_len);
        }
    }

    if(q && q_len > 0) {
        q_buf = OPENSSL_malloc(q_len);

        if(q_buf) {
            memcpy(q_buf, q, q_len);
            ossl_swap_bytes(q_buf, q_len);
            params[param_num++] =
                OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_FFC_Q, q_buf, q_len);
        }
    }

    if(g && g_len > 0) {
        g_buf = OPENSSL_malloc(g_len);

        if(g_buf) {
            memcpy(g_buf, g, g_len);
            ossl_swap_bytes(g_buf, g_len);
            params[param_num++] =
                OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_FFC_G, g_buf, g_len);
        }
    }

    if(y && y_len > 0) {
        y_buf = OPENSSL_malloc(y_len);

        if(y_buf) {
            memcpy(y_buf, y, y_len);
            ossl_swap_bytes(y_buf, y_len);
            params[param_num++] =
                OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_PUB_KEY, y_buf, y_len);
        }
    }

    if(x && x_len > 0) {
        x_buf = OPENSSL_malloc(x_len);

        if(x_buf) {
            memcpy(x_buf, x, x_len);
            ossl_swap_bytes(x_buf, x_len);
            params[param_num++] =
                OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_PRIV_KEY,
                                        x_buf, x_len);
        }
    }

    params[param_num] = OSSL_PARAM_construct_end();

    *dsactx = NULL;
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DSA, NULL);

    if(EVP_PKEY_fromdata_init(ctx) > 0)
        ret = EVP_PKEY_fromdata(ctx, dsactx, EVP_PKEY_KEYPAIR, params);

    if(p_buf)
        OPENSSL_clear_free(p_buf, p_len);
    if(q_buf)
        OPENSSL_clear_free(q_buf, q_len);
    if(g_buf)
        OPENSSL_clear_free(g_buf, g_len);
    if(x_buf)
        OPENSSL_clear_free(x_buf, x_len);
    if(y_buf)
        OPENSSL_clear_free(y_buf, y_len);

    EVP_PKEY_CTX_free(ctx);

    return (ret == 1) ? 0 : -1;

#else

    BIGNUM *p_bn;
    BIGNUM *q_bn;
    BIGNUM *g_bn;
    BIGNUM *pub_key;
    BIGNUM *priv_key = NULL;

    p_bn = BN_new();
    BN_bin2bn(p, (int)p_len, p_bn);

    q_bn = BN_new();
    BN_bin2bn(q, (int)q_len, q_bn);

    g_bn = BN_new();
    BN_bin2bn(g, (int)g_len, g_bn);

    pub_key = BN_new();
    BN_bin2bn(y, (int)y_len, pub_key);

    if(x_len) {
        priv_key = BN_new();
        BN_bin2bn(x, (int)x_len, priv_key);
    }

    *dsactx = DSA_new();

#ifdef HAVE_OPAQUE_STRUCTS
    DSA_set0_pqg(*dsactx, p_bn, q_bn, g_bn);
#else
    (*dsactx)->p = p_bn;
    (*dsactx)->g = g_bn;
    (*dsactx)->q = q_bn;
#endif

#ifdef HAVE_OPAQUE_STRUCTS
    DSA_set0_key(*dsactx, pub_key, priv_key);
#else
    (*dsactx)->pub_key = pub_key;
    (*dsactx)->priv_key = priv_key;
#endif
    return 0;

#endif /* USE_OPENSSL_3 */
}

int ssh2_dsa_sha1_verify(ssh2_dsa_ctx *dsactx,
                         const unsigned char *sig,
                         const unsigned char *m, size_t m_len)
{
#ifdef USE_OPENSSL_3
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char *der = NULL;
    int der_len = 0;
#endif

    unsigned char hash[SHA_DIGEST_LENGTH];
    DSA_SIG *dsasig;
    BIGNUM *r;
    BIGNUM *s;
    int ret = -1;

    r = BN_new();
    BN_bin2bn(sig, 20, r);
    s = BN_new();
    BN_bin2bn(sig + 20, 20, s);

    dsasig = DSA_SIG_new();
#ifdef HAVE_OPAQUE_STRUCTS
    DSA_SIG_set0(dsasig, r, s);
#else
    dsasig->r = r;
    dsasig->s = s;
#endif

#ifdef USE_OPENSSL_3
    ctx = EVP_PKEY_CTX_new(dsactx, NULL);
    der_len = i2d_DSA_SIG(dsasig, &der);

    if(ctx && !ssh2_ossl_sha1(m, m_len, hash)) {
        /* ssh2_ossl_sha1() succeeded */
        if(EVP_PKEY_verify_init(ctx) > 0)
            ret = EVP_PKEY_verify(ctx, der, der_len, hash, SHA_DIGEST_LENGTH);
    }

    if(ctx)
        EVP_PKEY_CTX_free(ctx);

    if(der)
        OPENSSL_clear_free(der, der_len);
#else
    if(!ssh2_ossl_sha1(m, m_len, hash))
        /* ssh2_ossl_sha1() succeeded */
        ret = DSA_do_verify(hash, SHA_DIGEST_LENGTH, dsasig, dsactx);
#endif

    DSA_SIG_free(dsasig);

    return (ret == 1) ? 0 : -1;
}
#endif /* LIBSSH_DSA */

#if LIBSSH2_ECDSA

/*
 * returns key curve type that maps to ssh2_curve_type
 */
ssh2_curve_type ssh2_ecdsa_get_curve_type(ssh2_ecdsa_ctx *ec_ctx)
{
#ifdef USE_OPENSSL_3
    int bits = 0;
    EVP_PKEY_get_int_param(ec_ctx, OSSL_PKEY_PARAM_BITS, &bits);

    if(bits == 256)
        return SSH2_EC_CURVE_NISTP256;
    else if(bits == 384)
        return SSH2_EC_CURVE_NISTP384;
    else if(bits == 521)
        return SSH2_EC_CURVE_NISTP521;

    return SSH2_EC_CURVE_NISTP256;
#else
    const EC_GROUP *group = EC_KEY_get0_group(ec_ctx);
    return EC_GROUP_get_curve_name(group);
#endif
}

/*
 * returns 0 for success, key curve type that maps to ssh2_curve_type
 */
int ssh2_ecdsa_curve_type_from_name(const char *name,
                                    ssh2_curve_type *out_type)
{
    ssh2_curve_type type;

    if(!name || strlen(name) != 19)
        return -1;

    if(strcmp(name, "ecdsa-sha2-nistp256") == 0)
        type = SSH2_EC_CURVE_NISTP256;
    else if(strcmp(name, "ecdsa-sha2-nistp384") == 0)
        type = SSH2_EC_CURVE_NISTP384;
    else if(strcmp(name, "ecdsa-sha2-nistp521") == 0)
        type = SSH2_EC_CURVE_NISTP521;
    else
        return -1;

    if(out_type)
        *out_type = type;

    return 0;
}

/*
 * Creates a new public key given an octal string, length and type
 */
int ssh2_ecdsa_curve_name_with_octal_new(ssh2_ecdsa_ctx **ec_ctx,
                                         const unsigned char *k, size_t k_len,
                                         ssh2_curve_type curve)
{
    int ret = 0;

#ifdef USE_OPENSSL_3
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    const char *n = EC_curve_nid2nist(curve);
    char *group_name = NULL;
    unsigned char *data = NULL;

    if(!ctx)
        return -1;

    if(n)
        group_name = OPENSSL_zalloc(strlen(n) + 1);

    if(k_len > 0)
        data = OPENSSL_malloc(k_len);

    if(group_name && data) {
        OSSL_PARAM params[3] = { 0 };

        /* NOLINTNEXTLINE(bugprone-not-null-terminated-result) */
        memcpy(group_name, n, strlen(n));
        memcpy(data, k, k_len);

        params[0] = OSSL_PARAM_construct_utf8_string(
            OSSL_PKEY_PARAM_GROUP_NAME, group_name, 0);

        params[1] = OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_PUB_KEY, data, k_len);

        params[2] = OSSL_PARAM_construct_end();

        if(EVP_PKEY_fromdata_init(ctx) > 0)
            ret = EVP_PKEY_fromdata(ctx, ec_ctx, EVP_PKEY_PUBLIC_KEY, params);
        else
            ret = -1;
    }
    else
        ret = -1;

    if(group_name)
        OPENSSL_clear_free(group_name, strlen(n));

    if(data)
        OPENSSL_clear_free(data, k_len);

    EVP_PKEY_CTX_free(ctx);
#else
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(curve);

    if(ec_key) {
        const EC_GROUP *ec_group = NULL;
        EC_POINT *point = NULL;

        ec_group = EC_KEY_get0_group(ec_key);
        point = EC_POINT_new(ec_group);

        if(point) {
            ret = EC_POINT_oct2point(ec_group, point, k, k_len, NULL);
            if(ret == 1)
                ret = EC_KEY_set_public_key(ec_key, point);

            EC_POINT_free(point);
        }
        else
            ret = -1;

        if(ret == 1 && ec_ctx)
            *ec_ctx = ec_key;
        else {
            EC_KEY_free(ec_key);
            ret = -1;
        }
    }
    else
        ret = -1;
#endif

    return (ret == 1) ? 0 : -1;
}

#ifdef USE_OPENSSL_3
#define SSH2_OSSL_ECDSA_VERIFY(digest_type)                              \
    do {                                                                 \
        unsigned char hash[SHA##digest_type##_DIGEST_LENGTH];            \
        if(ssh2_sha##digest_type(m, m_len, hash) == 0) {                 \
            ret = EVP_PKEY_verify_init(ctx);                             \
            if(ret > 0) {                                                \
                ret = EVP_PKEY_verify(ctx, der, der_len, hash,           \
                                      SHA##digest_type##_DIGEST_LENGTH); \
            }                                                            \
        }                                                                \
    } while(0)
#else
#define SSH2_OSSL_ECDSA_VERIFY(digest_type)                               \
    do {                                                                  \
        unsigned char hash[SHA##digest_type##_DIGEST_LENGTH];             \
        if(ssh2_sha##digest_type(m, m_len, hash) == 0) {                  \
            ret = ECDSA_do_verify(hash, SHA##digest_type##_DIGEST_LENGTH, \
                                  ecdsa_sig, ec_key);                     \
        }                                                                 \
    } while(0)
#endif

int ssh2_ecdsa_verify(ssh2_ecdsa_ctx *ec_ctx,
                      const unsigned char *r, size_t r_len,
                      const unsigned char *s, size_t s_len,
                      const unsigned char *m, size_t m_len)
{
    int ret = 0;
    ssh2_curve_type type = ssh2_ecdsa_get_curve_type(ec_ctx);

#ifdef USE_OPENSSL_3
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char *der = NULL;
    int der_len = 0;
#else
    EC_KEY *ec_key = (EC_KEY *)ec_ctx;
#endif

#ifdef HAVE_OPAQUE_STRUCTS
    ECDSA_SIG *ecdsa_sig = ECDSA_SIG_new();
    BIGNUM *pr = BN_new();
    BIGNUM *ps = BN_new();

    BN_bin2bn(r, (int)r_len, pr);
    BN_bin2bn(s, (int)s_len, ps);
    ECDSA_SIG_set0(ecdsa_sig, pr, ps);
#else
    ECDSA_SIG ecdsa_sig_;
    ECDSA_SIG *ecdsa_sig = &ecdsa_sig_;
    ecdsa_sig_.r = BN_new();
    BN_bin2bn(r, (int)r_len, ecdsa_sig_.r);
    ecdsa_sig_.s = BN_new();
    BN_bin2bn(s, (int)s_len, ecdsa_sig_.s);
#endif

#ifdef USE_OPENSSL_3
    ctx = EVP_PKEY_CTX_new(ec_ctx, NULL);
    if(!ctx) {
        ret = -1;
        goto cleanup;
    }

    der_len = i2d_ECDSA_SIG(ecdsa_sig, &der);
    if(der_len <= 0) {
        ret = -1;
        goto cleanup;
    }
#endif

    if(type == SSH2_EC_CURVE_NISTP256)
        SSH2_OSSL_ECDSA_VERIFY(256);
    else if(type == SSH2_EC_CURVE_NISTP384)
        SSH2_OSSL_ECDSA_VERIFY(384);
    else if(type == SSH2_EC_CURVE_NISTP521)
        SSH2_OSSL_ECDSA_VERIFY(512);

#ifdef USE_OPENSSL_3
cleanup:

    if(ctx)
        EVP_PKEY_CTX_free(ctx);

    if(der)
        OPENSSL_free(der);
#endif

#ifdef HAVE_OPAQUE_STRUCTS
    if(ecdsa_sig)
        ECDSA_SIG_free(ecdsa_sig);
#else
    if(ecdsa_sig_.s)
        BN_clear_free(ecdsa_sig_.s);
    if(ecdsa_sig_.r)
        BN_clear_free(ecdsa_sig_.r);
#endif

    return (ret == 1) ? 0 : -1;
}

#endif /* LIBSSH2_ECDSA */

int ssh2_cipher_init(ssh2_cipher_ctx *h, SSH2_CIPHER_T(algo),
                     unsigned char *iv, unsigned char *secret, int encrypt)
{
#ifdef HAVE_OPAQUE_STRUCTS
#if LIBSSH2_AES_GCM
    const int is_aesgcm = (algo == EVP_aes_128_gcm) ||
                          (algo == EVP_aes_256_gcm);
#endif /* LIBSSH2_AES_GCM */
    int rc;

    *h = EVP_CIPHER_CTX_new();
    rc = !EVP_CipherInit(*h, algo(), secret, iv, encrypt);
#if LIBSSH2_AES_GCM
    if(is_aesgcm) {
        /* Sets both fixed and invocation_counter parts of IV */
        rc |= !EVP_CIPHER_CTX_ctrl(*h, EVP_CTRL_AEAD_SET_IV_FIXED, -1, iv);
    }
#endif /* LIBSSH2_AES_GCM */

    return rc;
#else
# if LIBSSH2_AES_GCM
#  error AES-GCM is only supported with opaque structs in use
# endif /* LIBSSH2_AES_GCM */
    EVP_CIPHER_CTX_init(h);
    return !EVP_CipherInit(h, algo(), secret, iv, encrypt);
#endif
}

#ifndef EVP_MAX_BLOCK_LENGTH
#define EVP_MAX_BLOCK_LENGTH 32
#endif

int ssh2_cipher_crypt(ssh2_cipher_ctx *ctx, SSH2_CIPHER_T(algo), int encrypt,
                      unsigned char *block, size_t blocksize, int firstlast)
{
    unsigned char buf[EVP_MAX_BLOCK_LENGTH];
    int ret = 1;
    int rc = 1;

#if LIBSSH2_AES_GCM
    const int is_aesgcm = (algo == EVP_aes_128_gcm) ||
                          (algo == EVP_aes_256_gcm);
    char lastiv[1];
#else
    const int is_aesgcm = 0;
#endif /* LIBSSH2_AES_GCM */
    /* length of AES-GCM Authentication Tag */
    const int authlen = is_aesgcm ? 16 : 0;
    /* length of AAD, only on the first block */
    const int aadlen = (is_aesgcm && IS_FIRST(firstlast)) ? 4 : 0;
    /* size of AT, if present */
    const int authenticationtag = IS_LAST(firstlast) ? authlen : 0;
    /* length to encrypt */
    const int cryptlen = (unsigned int)blocksize - aadlen - authenticationtag;

    (void)algo;

    assert(blocksize <= sizeof(buf));
    assert(cryptlen >= 0);

#if LIBSSH2_AES_GCM
    /* First block */
    if(IS_FIRST(firstlast)) {
        /* Increments invocation_counter portion of IV */
        if(is_aesgcm)
            ret = EVP_CIPHER_CTX_ctrl(*ctx, EVP_CTRL_GCM_IV_GEN, 1, lastiv);

        if(aadlen)
            /* Include the 4 byte packet length as AAD */
            ret = EVP_Cipher(*ctx, NULL, block, aadlen);
    }

    /* Last portion of block to encrypt/decrypt */
    if(IS_LAST(firstlast) && is_aesgcm && !encrypt)
        /* set tag on decryption */
        ret = EVP_CIPHER_CTX_ctrl(*ctx, EVP_CTRL_GCM_SET_TAG, authlen,
                                  block + blocksize - authlen);
#else
    (void)encrypt;
    (void)firstlast;
#endif /* LIBSSH2_AES_GCM */

    if(cryptlen > 0) {
#ifdef HAVE_OPAQUE_STRUCTS
        ret = EVP_Cipher(*ctx, buf + aadlen, block + aadlen, cryptlen);
#else
        ret = EVP_Cipher(ctx, buf + aadlen, block + aadlen, cryptlen);
#endif
    }

#if defined(USE_OPENSSL_3) || defined(LIBSSH2_WOLFSSL)
    if(ret != -1)
#else
    if(ret >= 1)
#endif
    {
        if(IS_LAST(firstlast)) {
            /* This is the last block.
               encrypt: compute tag, if applicable
               decrypt: verify tag, if applicable
               in!=NULL is equivalent to EVP_CipherUpdate
               in==NULL is equivalent to EVP_CipherFinal */
#if defined(LIBSSH2_WOLFSSL) && LIBWOLFSSL_VERSION_HEX < 0x05007000
            /* Workaround for wolfSSL bug fixed in v5.7.0:
               https://github.com/wolfSSL/wolfssl/pull/7143 */
            unsigned char buf2[EVP_MAX_BLOCK_LENGTH];
            int outb;
            ret = EVP_CipherFinal(*ctx, buf2, &outb);
#elif defined(HAVE_OPAQUE_STRUCTS)
            ret = EVP_Cipher(*ctx, NULL, NULL, 0); /* final */
#else
            ret = EVP_Cipher(ctx, NULL, NULL, 0); /* final */
#endif
            if(ret < 0)
                ret = 0;
            else {
                ret = 1;
#if LIBSSH2_AES_GCM
                if(is_aesgcm && encrypt) {
                    /* write the Authentication Tag a.k.a. MAC at the end
                       of the block */
                    assert(authenticationtag == authlen);
                    ret = EVP_CIPHER_CTX_ctrl(*ctx, EVP_CTRL_GCM_GET_TAG,
                            authlen, block + blocksize - authenticationtag);
                }
#endif /* LIBSSH2_AES_GCM */
            }
        }
        /* Copy en/decrypted data back to the caller.
           The first aadlen should not be touched because they were not
           encrypted and are unmodified. */
        memcpy(block + aadlen, buf + aadlen, cryptlen);
        rc = !ret;
    }

    /* TODO: the return code should distinguish between decryption errors and
       invalid MACs */
    return rc;
}

void ssh2_crypto_init(void)
{
#if defined(LIBSSH2_WOLFSSL) && defined(DEBUG_WOLFSSL)
    wolfSSL_Debugging_ON();
#endif
}

#if LIBSSH2_RSA || LIBSSH2_DSA || LIBSSH2_ECDSA || LIBSSH2_ED25519
/* TODO: Optionally call a passphrase callback specified by the calling program
 */
static int ossl_passphrase_cb(char *buf, int size, int rwflag,
                              void *passphrase)
{
    int passphrase_len = (int)strlen(passphrase);

    (void)rwflag;

    if(passphrase_len > (size - 1))
        passphrase_len = size - 1;

    memcpy(buf, passphrase, passphrase_len);
    buf[passphrase_len] = '\0';

    return passphrase_len;
}
#endif /* LIBSSH2_RSA || LIBSSH2_DSA || LIBSSH2_ECDSA || LIBSSH2_ED25519 */

#if LIBSSH2_RSA
int ssh2_rsa_new_private_frommemory(ssh2_rsa_ctx **rsa,
                                    LIBSSH2_SESSION *session,
                                    const char *filedata, size_t filedata_len,
                                    const unsigned char *passphrase)
{
    int rc = 0;
    BIO *bp;

    ssh2_init_if_needed();

    bp = BIO_new_mem_buf(filedata, (int)filedata_len);
    if(bp)
#ifdef USE_OPENSSL_3
        *rsa = PEM_read_bio_PrivateKey(bp, NULL, ossl_passphrase_cb,
                                       SSH2_UNCONST(passphrase));
#else
        *rsa = PEM_read_bio_RSAPrivateKey(bp, NULL, ossl_passphrase_cb,
                                          SSH2_UNCONST(passphrase));
#endif
    BIO_free(bp);
    if(!*rsa)
        rc = ossl_key_from_openssh_blob(session, (void **)rsa, "ssh-rsa",
                                        NULL, NULL, NULL, NULL,
                                        filedata, filedata_len, passphrase);

    return rc;
}

static unsigned char *ossl_rsa_to_pubkey(LIBSSH2_SESSION *session,
                                         ssh2_rsa_ctx *rsa, size_t *key_len)
{
    int e_bytes, n_bytes;
    unsigned long len;
    unsigned char *key = NULL;
    unsigned char *p;

#ifdef USE_OPENSSL_3
    BIGNUM *e = NULL;
    BIGNUM *n = NULL;

    EVP_PKEY_get_bn_param(rsa, OSSL_PKEY_PARAM_RSA_E, &e);
    EVP_PKEY_get_bn_param(rsa, OSSL_PKEY_PARAM_RSA_N, &n);
#else
    const BIGNUM *e;
    const BIGNUM *n;
#ifdef HAVE_OPAQUE_STRUCTS
    e = NULL;
    n = NULL;

    RSA_get0_key(rsa, &n, &e, NULL);
#else
    e = rsa->e;
    n = rsa->n;
#endif
#endif
    if(!e || !n)
        goto fail;

    e_bytes = BN_num_bytes(e) + 1;
    n_bytes = BN_num_bytes(n) + 1;

    /* Key form is "ssh-rsa" + e + n. */
    len = 4 + 7 + 4 + e_bytes + 4 + n_bytes;

    key = SSH2_ALLOC(session, len);
    if(!key)
        goto fail;

    /* Process key encoding. */
    p = key;

    ssh2_htonu32(p, 7); /* Key type. */
    p += 4;
    /* NOLINTNEXTLINE(bugprone-not-null-terminated-result) */
    memcpy(p, "ssh-rsa", 7);
    p += 7;

    p = ossl_write_bn(p, e, e_bytes);
    p = ossl_write_bn(p, n, n_bytes);

    *key_len = (size_t)(p - key);
fail:
#ifdef USE_OPENSSL_3
    BN_clear_free(e);
    BN_clear_free(n);
#endif
    return key;
}

static int ossl_rsa_evp_to_pubkey(LIBSSH2_SESSION *session,
                                  unsigned char **method,
                                  size_t *method_len,
                                  unsigned char **pubkeydata,
                                  size_t *pubkeydata_len,
                                  EVP_PKEY *pk)
{
    ssh2_rsa_ctx *rsa = NULL;
    unsigned char *key;
    unsigned char *method_buf = NULL;
    size_t key_len;

    ssh2_deb((session, LIBSSH2_TRACE_AUTH,
              "Computing public key from RSA private key envelope"));

#ifdef USE_OPENSSL_3
    rsa = pk;
#else
    rsa = EVP_PKEY_get1_RSA(pk);
#endif
    if(!rsa)
        /* Assume memory allocation error... what else could it be? */
        goto alloc_error;

    method_buf = SSH2_ALLOC(session, 7); /* ssh-rsa. */
    if(!method_buf)
        goto alloc_error;

    key = ossl_rsa_to_pubkey(session, rsa, &key_len);
    if(!key)
        goto alloc_error;
#ifndef USE_OPENSSL_3
    RSA_free(rsa);
#endif

    /* NOLINTNEXTLINE(bugprone-not-null-terminated-result) */
    memcpy(method_buf, "ssh-rsa", 7);
    *method = method_buf;
    if(method_len)
        *method_len = 7;

    *pubkeydata = key;
    if(pubkeydata_len)
        *pubkeydata_len = key_len;

    return 0;

alloc_error:
#ifndef USE_OPENSSL_3
    if(rsa)
        RSA_free(rsa);
#endif
    if(method_buf)
        SSH2_FREE(session, method_buf);

    return ssh2_err(session, LIBSSH2_ERROR_ALLOC,
                    "Unable to allocate memory for private key data");
}

#ifndef USE_OPENSSL_3
static int ossl_rsa_additional_params_new(ssh2_rsa_ctx *rsa)
{
    BN_CTX *ctx = NULL;
    BIGNUM *aux = NULL;
    BIGNUM *dmp1 = NULL;
    BIGNUM *dmq1 = NULL;
    const BIGNUM *p = NULL;
    const BIGNUM *q = NULL;
    const BIGNUM *d = NULL;
    int rc = 0;

#ifdef HAVE_OPAQUE_STRUCTS
    RSA_get0_key(rsa, NULL, NULL, &d);
    RSA_get0_factors(rsa, &p, &q);
#else
    d = (*rsa).d;
    p = (*rsa).p;
    q = (*rsa).q;
#endif

    ctx = BN_CTX_new();
    if(!ctx)
        return -1;

    aux = BN_new();
    if(!aux) {
        rc = -1;
        goto out;
    }

    dmp1 = BN_new();
    if(!dmp1) {
        rc = -1;
        goto out;
    }

    dmq1 = BN_new();
    if(!dmq1) {
        rc = -1;
        goto out;
    }

    if(BN_sub(aux, q, BN_value_one()) == 0 || BN_mod(dmq1, d, aux, ctx) == 0 ||
       BN_sub(aux, p, BN_value_one()) == 0 || BN_mod(dmp1, d, aux, ctx) == 0) {
        rc = -1;
        goto out;
    }

#ifdef HAVE_OPAQUE_STRUCTS
    RSA_set0_crt_params(rsa, dmp1, dmq1, NULL);
#else
    (*rsa).dmp1 = dmp1;
    (*rsa).dmq1 = dmq1;
#endif

out:
    if(aux)
        BN_clear_free(aux);
    BN_CTX_free(ctx);

    if(rc) {
        if(dmp1)
            BN_clear_free(dmp1);
        if(dmq1)
            BN_clear_free(dmq1);
    }

    return rc;
}
#endif /* !USE_OPENSSL_3 */

static int ossl_rsa_openssh_priv_to_pubkey(LIBSSH2_SESSION *session,
                                           struct string_buf *decrypted,
                                           unsigned char **method,
                                           size_t *method_len,
                                           unsigned char **pubkeydata,
                                           size_t *pubkeydata_len,
                                           ssh2_rsa_ctx **rsa_ctx)
{
    int rc = 0;
    size_t nlen, elen, dlen, plen, qlen, coefflen, commentlen;
    unsigned char *n, *e, *d, *p, *q, *coeff, *comment;
    ssh2_rsa_ctx *rsa = NULL;

    ssh2_deb((session, LIBSSH2_TRACE_AUTH,
              "Computing RSA keys from private key data"));

    /* public key data */
    if(ssh2_get_bignum_bytes(decrypted, &n, &nlen)) {
        ssh2_err(session, LIBSSH2_ERROR_PROTO, "RSA no n");
        return -1;
    }

    if(ssh2_get_bignum_bytes(decrypted, &e, &elen)) {
        ssh2_err(session, LIBSSH2_ERROR_PROTO, "RSA no e");
        return -1;
    }

    /* private key data */
    if(ssh2_get_bignum_bytes(decrypted, &d, &dlen)) {
        ssh2_err(session, LIBSSH2_ERROR_PROTO, "RSA no d");
        return -1;
    }

    if(ssh2_get_bignum_bytes(decrypted, &coeff, &coefflen)) {
        ssh2_err(session, LIBSSH2_ERROR_PROTO, "RSA no coeff");
        return -1;
    }

    if(ssh2_get_bignum_bytes(decrypted, &p, &plen)) {
        ssh2_err(session, LIBSSH2_ERROR_PROTO, "RSA no p");
        return -1;
    }

    if(ssh2_get_bignum_bytes(decrypted, &q, &qlen)) {
        ssh2_err(session, LIBSSH2_ERROR_PROTO, "RSA no q");
        return -1;
    }

    if(ssh2_get_string(decrypted, &comment, &commentlen)) {
        ssh2_err(session, LIBSSH2_ERROR_PROTO, "RSA no comment");
        return -1;
    }

    rc = ssh2_rsa_new(&rsa,
                      e, (unsigned long)elen,
                      n, (unsigned long)nlen,
                      d, (unsigned long)dlen,
                      p, (unsigned long)plen,
                      q, (unsigned long)qlen,
                      NULL, 0, NULL, 0,
                      coeff, (unsigned long)coefflen);
    if(rc) {
        ssh2_deb((session, LIBSSH2_TRACE_AUTH,
                  "Could not create RSA private key"));
        goto fail;
    }

#ifndef USE_OPENSSL_3
    if(rsa)
        rc = ossl_rsa_additional_params_new(rsa);
#endif

    if(rsa && pubkeydata && method) {
#ifdef USE_OPENSSL_3
        EVP_PKEY *pk = rsa;
#else
        EVP_PKEY *pk = EVP_PKEY_new();
        EVP_PKEY_set1_RSA(pk, rsa);
#endif

        rc = ossl_rsa_evp_to_pubkey(session, method, method_len,
                                    pubkeydata, pubkeydata_len, pk);

#ifndef USE_OPENSSL_3
        if(pk)
            EVP_PKEY_free(pk);
#endif
    }

    if(rsa_ctx)
        *rsa_ctx = rsa;
    else
        ssh2_rsa_free(rsa);

    return rc;

fail:

    if(rsa)
        ssh2_rsa_free(rsa);

    return ssh2_err(session, LIBSSH2_ERROR_ALLOC,
                    "Unable to allocate memory for private key data");
}

static int ossl_rsa_openssh_priv_new(ssh2_rsa_ctx **rsa,
                                     LIBSSH2_SESSION *session,
                                     const char *filename,
                                     const unsigned char *passphrase)
{
    FILE *fp;
    int rc;
    unsigned char *buf = NULL;
    struct string_buf *decrypted = NULL;

    if(!session) {
        ssh2_err(session, LIBSSH2_ERROR_PROTO, "Session is required");
        return -1;
    }

    ssh2_init_if_needed();

    fp = fopen(filename, "r");
    if(!fp) {
        ssh2_err(session, LIBSSH2_ERROR_FILE,
                 "Unable to open OpenSSH RSA private key file");
        return -1;
    }

    rc = ssh2_openssh_pem_parse(session, passphrase, fp, &decrypted);
    fclose(fp);
    if(rc)
        return rc;

    /* We have a new key file, now try and parse it using supported types  */
    rc = ssh2_get_string(decrypted, &buf, NULL);

    if(rc || !buf) {
        ssh2_err(session, LIBSSH2_ERROR_PROTO,
                 "Public key type in decrypted key data not found");
        return -1;
    }

    if(strcmp("ssh-rsa", (const char *)buf) == 0)
        rc = ossl_rsa_openssh_priv_to_pubkey(session, decrypted,
                                             NULL, NULL, NULL, NULL, rsa);
    else
        rc = -1;

    if(decrypted)
        ssh2_string_buf_free(session, decrypted);

    return rc;
}

int ssh2_rsa_new_private(ssh2_rsa_ctx **rsa,
                         LIBSSH2_SESSION *session,
                         const char *filename,
                         const unsigned char *passphrase)
{
    int rc = 0;
    BIO *bp;

    ssh2_init_if_needed();

    bp = BIO_new_file(filename, "r");
    if(bp)
#ifdef USE_OPENSSL_3
        *rsa = PEM_read_bio_PrivateKey(bp, NULL, ossl_passphrase_cb,
                                       SSH2_UNCONST(passphrase));
#else
        *rsa = PEM_read_bio_RSAPrivateKey(bp, NULL, ossl_passphrase_cb,
                                          SSH2_UNCONST(passphrase));
#endif
    BIO_free(bp);
    if(!*rsa)
        rc = ossl_rsa_openssh_priv_new(rsa, session, filename, passphrase);

    return rc;
}
#endif

#if LIBSSH2_DSA
int ssh2_dsa_new_private_frommemory(ssh2_dsa_ctx **dsa,
                                    LIBSSH2_SESSION *session,
                                    const char *filedata,
                                    size_t filedata_len,
                                    const unsigned char *passphrase)
{
    int rc = 0;
    BIO *bp;

    ssh2_init_if_needed();

    bp = BIO_new_mem_buf(filedata, (int)filedata_len);
    if(bp)
#ifdef USE_OPENSSL_3
        *dsa = PEM_read_bio_PrivateKey(bp, NULL, ossl_passphrase_cb,
                                       SSH2_UNCONST(passphrase));
#else
        *dsa = PEM_read_bio_DSAPrivateKey(bp, NULL, ossl_passphrase_cb,
                                          SSH2_UNCONST(passphrase));
#endif
    BIO_free(bp);
    if(!*dsa)
        rc = ossl_key_from_openssh_blob(session, (void **)dsa, "ssh-dsa",
                                        NULL, NULL, NULL, NULL,
                                        filedata, filedata_len, passphrase);

    return rc;
}

static unsigned char *ossl_dsa_to_pubkey(LIBSSH2_SESSION *session,
                                         ssh2_dsa_ctx *dsa, size_t *key_len)
{
    int p_bytes, q_bytes, g_bytes, k_bytes;
    unsigned long len;
    unsigned char *key = NULL;
    unsigned char *p;

#ifdef USE_OPENSSL_3
    BIGNUM *p_bn = NULL;
    BIGNUM *q = NULL;
    BIGNUM *g = NULL;
    BIGNUM *pub_key = NULL;

    EVP_PKEY_get_bn_param(dsa, OSSL_PKEY_PARAM_FFC_P, &p_bn);
    EVP_PKEY_get_bn_param(dsa, OSSL_PKEY_PARAM_FFC_Q, &q);
    EVP_PKEY_get_bn_param(dsa, OSSL_PKEY_PARAM_FFC_G, &g);
    EVP_PKEY_get_bn_param(dsa, OSSL_PKEY_PARAM_PUB_KEY, &pub_key);
#else
    const BIGNUM *p_bn;
    const BIGNUM *q;
    const BIGNUM *g;
    const BIGNUM *pub_key;
#ifdef HAVE_OPAQUE_STRUCTS
    DSA_get0_pqg(dsa, &p_bn, &q, &g);
#else
    p_bn = dsa->p;
    q = dsa->q;
    g = dsa->g;
#endif

#ifdef HAVE_OPAQUE_STRUCTS
    DSA_get0_key(dsa, &pub_key, NULL);
#else
    pub_key = dsa->pub_key;
#endif
#endif
    p_bytes = BN_num_bytes(p_bn) + 1;
    q_bytes = BN_num_bytes(q) + 1;
    g_bytes = BN_num_bytes(g) + 1;
    k_bytes = BN_num_bytes(pub_key) + 1;

    /* Key form is "ssh-dss" + p + q + g + pub_key. */
    len = 4 + 7 + 4 + p_bytes + 4 + q_bytes + 4 + g_bytes + 4 + k_bytes;

    key = SSH2_ALLOC(session, len);
    if(!key)
        goto fail;

    /* Process key encoding. */
    p = key;

    ssh2_htonu32(p, 7); /* Key type. */
    p += 4;
    memcpy(p, "ssh-dss", 7);
    p += 7;

    p = ossl_write_bn(p, p_bn, p_bytes);
    p = ossl_write_bn(p, q, q_bytes);
    p = ossl_write_bn(p, g, g_bytes);
    p = ossl_write_bn(p, pub_key, k_bytes);

    *key_len = (size_t)(p - key);
fail:
#ifdef USE_OPENSSL_3
    BN_clear_free(p_bn);
    BN_clear_free(q);
    BN_clear_free(g);
    BN_clear_free(pub_key);
#endif
    return key;
}

static int ossl_dsa_evp_to_pubkey(LIBSSH2_SESSION *session,
                                  unsigned char **method,
                                  size_t *method_len,
                                  unsigned char **pubkeydata,
                                  size_t *pubkeydata_len,
                                  EVP_PKEY *pk)
{
    ssh2_dsa_ctx *dsa = NULL;
    unsigned char *key;
    unsigned char *method_buf = NULL;
    size_t key_len;

    ssh2_deb((session, LIBSSH2_TRACE_AUTH,
              "Computing public key from DSA private key envelope"));

#ifdef USE_OPENSSL_3
    dsa = pk;
#else
    dsa = EVP_PKEY_get1_DSA(pk);
#endif
    if(!dsa)
        /* Assume memory allocation error... what else could it be ? */
        goto alloc_error;

    method_buf = SSH2_ALLOC(session, 7); /* ssh-dss. */
    if(!method_buf)
        goto alloc_error;

    key = ossl_dsa_to_pubkey(session, dsa, &key_len);
    if(!key)
        goto alloc_error;
#ifndef USE_OPENSSL_3
    DSA_free(dsa);
#endif

    memcpy(method_buf, "ssh-dss", 7);
    *method = method_buf;
    if(method_len)
        *method_len = 7;

    *pubkeydata = key;
    if(pubkeydata_len)
        *pubkeydata_len = key_len;

    return 0;

alloc_error:
#ifndef USE_OPENSSL_3
    if(dsa)
        DSA_free(dsa);
#endif
    if(method_buf)
        SSH2_FREE(session, method_buf);

    return ssh2_err(session, LIBSSH2_ERROR_ALLOC,
                    "Unable to allocate memory for private key data");
}

static int ossl_dsa_openssh_priv_to_pubkey(LIBSSH2_SESSION *session,
                                           struct string_buf *decrypted,
                                           unsigned char **method,
                                           size_t *method_len,
                                           unsigned char **pubkeydata,
                                           size_t *pubkeydata_len,
                                           ssh2_dsa_ctx **dsa_ctx)
{
    int rc = 0;
    size_t plen, qlen, glen, pub_len, priv_len;
    unsigned char *p, *q, *g, *pub_key, *priv_key;
    ssh2_dsa_ctx *dsa = NULL;

    ssh2_deb((session, LIBSSH2_TRACE_AUTH,
              "Computing DSA keys from private key data"));

    if(ssh2_get_bignum_bytes(decrypted, &p, &plen)) {
        ssh2_err(session, LIBSSH2_ERROR_PROTO, "DSA no p");
        return -1;
    }

    if(ssh2_get_bignum_bytes(decrypted, &q, &qlen)) {
        ssh2_err(session, LIBSSH2_ERROR_PROTO, "DSA no q");
        return -1;
    }

    if(ssh2_get_bignum_bytes(decrypted, &g, &glen)) {
        ssh2_err(session, LIBSSH2_ERROR_PROTO, "DSA no g");
        return -1;
    }

    if(ssh2_get_bignum_bytes(decrypted, &pub_key, &pub_len)) {
        ssh2_err(session, LIBSSH2_ERROR_PROTO, "DSA no public key");
        return -1;
    }

    if(ssh2_get_bignum_bytes(decrypted, &priv_key, &priv_len)) {
        ssh2_err(session, LIBSSH2_ERROR_PROTO, "DSA no private key");
        return -1;
    }

    rc = ssh2_dsa_new(&dsa,
                      p, (unsigned long)plen,
                      q, (unsigned long)qlen,
                      g, (unsigned long)glen,
                      pub_key, (unsigned long)pub_len,
                      priv_key, (unsigned long)priv_len);
    if(rc) {
        ssh2_deb((session, LIBSSH2_ERROR_PROTO,
                  "Could not create DSA private key"));
        goto fail;
    }

    if(dsa && pubkeydata && method) {
#ifdef USE_OPENSSL_3
        EVP_PKEY *pk = dsa;
#else
        EVP_PKEY *pk = EVP_PKEY_new();
        EVP_PKEY_set1_DSA(pk, dsa);
#endif

        rc = ossl_dsa_evp_to_pubkey(session, method, method_len,
                                    pubkeydata, pubkeydata_len, pk);

#ifndef USE_OPENSSL_3
        if(pk)
            EVP_PKEY_free(pk);
#endif
    }

    if(dsa_ctx)
        *dsa_ctx = dsa;
    else
        ssh2_dsa_free(dsa);

    return rc;

fail:

    if(dsa)
        ssh2_dsa_free(dsa);

    return ssh2_err(session, LIBSSH2_ERROR_ALLOC,
                    "Unable to allocate memory for private key data");
}

static int ossl_dsa_openssh_priv_new(ssh2_dsa_ctx **dsa,
                                     LIBSSH2_SESSION *session,
                                     const char *filename,
                                     const unsigned char *passphrase)
{
    FILE *fp;
    int rc;
    unsigned char *buf = NULL;
    struct string_buf *decrypted = NULL;

    if(!session) {
        ssh2_err(session, LIBSSH2_ERROR_PROTO, "Session is required");
        return -1;
    }

    ssh2_init_if_needed();

    fp = fopen(filename, "r");
    if(!fp) {
        ssh2_err(session, LIBSSH2_ERROR_FILE,
                 "Unable to open OpenSSH DSA private key file");
        return -1;
    }

    rc = ssh2_openssh_pem_parse(session, passphrase, fp, &decrypted);
    fclose(fp);
    if(rc)
        return rc;

    /* We have a new key file, now try and parse it using supported types  */
    rc = ssh2_get_string(decrypted, &buf, NULL);

    if(rc || !buf) {
        ssh2_err(session, LIBSSH2_ERROR_PROTO,
                 "Public key type in decrypted key data not found");
        return -1;
    }

    if(strcmp("ssh-dss", (const char *)buf) == 0)
        rc = ossl_dsa_openssh_priv_to_pubkey(session, decrypted,
                                             NULL, NULL, NULL, NULL, dsa);
    else
        rc = -1;

    if(decrypted)
        ssh2_string_buf_free(session, decrypted);

    return rc;
}

int ssh2_dsa_new_private(ssh2_dsa_ctx **dsa,
                         LIBSSH2_SESSION *session,
                         const char *filename,
                         const unsigned char *passphrase)
{
    int rc = 0;
    BIO *bp;

    ssh2_init_if_needed();

    bp = BIO_new_file(filename, "r");
    if(bp)
#ifdef USE_OPENSSL_3
        *dsa = PEM_read_bio_PrivateKey(bp, NULL, ossl_passphrase_cb,
                                       SSH2_UNCONST(passphrase));
#else
        *dsa = PEM_read_bio_DSAPrivateKey(bp, NULL, ossl_passphrase_cb,
                                          SSH2_UNCONST(passphrase));
#endif
    BIO_free(bp);
    if(!*dsa)
        rc = ossl_dsa_openssh_priv_new(dsa, session, filename, passphrase);

    return rc;
}
#endif /* LIBSSH_DSA */

#if LIBSSH2_ECDSA
int ssh2_ecdsa_new_private_frommemory(ssh2_ecdsa_ctx **ec_ctx,
                                      LIBSSH2_SESSION *session,
                                      const char *filedata,
                                      size_t filedata_len,
                                      const unsigned char *passphrase)
{
    int rc = 0;
    BIO *bp;

    ssh2_init_if_needed();

    bp = BIO_new_mem_buf(filedata, (int)filedata_len);
    if(bp)
#ifdef USE_OPENSSL_3
        *ec_ctx = PEM_read_bio_PrivateKey(bp, NULL, ossl_passphrase_cb,
                                          SSH2_UNCONST(passphrase));
#else
        *ec_ctx = PEM_read_bio_ECPrivateKey(bp, NULL, ossl_passphrase_cb,
                                            SSH2_UNCONST(passphrase));
#endif
    BIO_free(bp);
    if(!*ec_ctx)
        rc = ossl_key_from_openssh_blob(session, (void **)ec_ctx, "ssh-ecdsa",
                                        NULL, NULL, NULL, NULL,
                                        filedata, filedata_len, passphrase);

    return rc;
}

int ssh2_ecdsa_new_private_frommemory_sk(ssh2_ecdsa_ctx **ec_ctx,
                                         unsigned char *flags,
                                         const char **application,
                                         const unsigned char **key_handle,
                                         size_t *handle_len,
                                         LIBSSH2_SESSION *session,
                                         const char *filedata,
                                         size_t filedata_len,
                                         const unsigned char *passphrase)
{
    int algorithm;
    return ossl_key_sk_from_openssh_blob(session, (void **)ec_ctx,
                                         "sk-ecdsa-sha2-nistp256@openssh.com",
                                         NULL, NULL, NULL, NULL,
                                         &algorithm, flags, application,
                                         key_handle, handle_len,
                                         filedata, filedata_len,
                                         passphrase);
}

#endif /* LIBSSH2_ECDSA */

#if LIBSSH2_ED25519

int ssh2_curve25519_new(LIBSSH2_SESSION *session,
                        unsigned char **out_public_key,
                        unsigned char **out_private_key)
{
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    unsigned char *priv = NULL, *pub = NULL;
    size_t privLen, pubLen;
    int rc = -1;

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if(!pctx)
        return -1;

    if(EVP_PKEY_keygen_init(pctx) != 1 ||
       EVP_PKEY_keygen(pctx, &key) != 1) {
        goto clean_exit;
    }

    if(out_private_key) {
        privLen = SSH2_ED25519_KEY_LEN;
        priv = SSH2_ALLOC(session, privLen);
        if(!priv)
            goto clean_exit;

        if(EVP_PKEY_get_raw_private_key(key, priv, &privLen) != 1 ||
           privLen != SSH2_ED25519_KEY_LEN) {
            goto clean_exit;
        }

        *out_private_key = priv;
        priv = NULL;
    }

    if(out_public_key) {
        pubLen = SSH2_ED25519_KEY_LEN;
        pub = SSH2_ALLOC(session, pubLen);
        if(!pub)
            goto clean_exit;

        if(EVP_PKEY_get_raw_public_key(key, pub, &pubLen) != 1 ||
           pubLen != SSH2_ED25519_KEY_LEN) {
            goto clean_exit;
        }

        *out_public_key = pub;
        pub = NULL;
    }

    /* success */
    rc = 0;

clean_exit:

    if(pctx)
        EVP_PKEY_CTX_free(pctx);
    if(key)
        EVP_PKEY_free(key);
    if(priv)
        SSH2_FREE(session, priv);
    if(pub)
        SSH2_FREE(session, pub);

    return rc;
}

static int ossl_ed25519_evp_to_pubkey(LIBSSH2_SESSION *session,
                                      unsigned char **method,
                                      size_t *method_len,
                                      unsigned char **pubkeydata,
                                      size_t *pubkeydata_len,
                                      EVP_PKEY *pk)
{
    const char methodName[] = "ssh-ed25519";
    unsigned char *methodBuf = NULL;
    size_t rawKeyLen = 0;
    unsigned char *keyBuf = NULL;
    size_t bufLen = 0;
    unsigned char *bufPos = NULL;

    ssh2_deb((session, LIBSSH2_TRACE_AUTH,
              "Computing public key from ED private key envelope"));

    methodBuf = SSH2_ALLOC(session, sizeof(methodName) - 1);
    if(!methodBuf) {
        ssh2_err(session, LIBSSH2_ERROR_ALLOC,
                 "Unable to allocate memory for private key data");
        goto fail;
    }
    memcpy(methodBuf, methodName, sizeof(methodName) - 1);

    if(EVP_PKEY_get_raw_public_key(pk, NULL, &rawKeyLen) != 1) {
        ssh2_err(session, LIBSSH2_ERROR_PROTO,
                 "EVP_PKEY_get_raw_public_key failed");
        goto fail;
    }

    /* Key form is: type_len(4) + type(11) + pub_key_len(4) + pub_key(32). */
    bufLen = 4 + sizeof(methodName) - 1 + 4 + rawKeyLen;
    bufPos = keyBuf = SSH2_ALLOC(session, bufLen);
    if(!keyBuf) {
        ssh2_err(session, LIBSSH2_ERROR_ALLOC,
                 "Unable to allocate memory for private key data");
        goto fail;
    }

    ssh2_store_str(&bufPos, methodName, sizeof(methodName) - 1);
    ssh2_store_u32(&bufPos, (uint32_t)rawKeyLen);

    if(EVP_PKEY_get_raw_public_key(pk, bufPos, &rawKeyLen) != 1) {
        ssh2_err(session, LIBSSH2_ERROR_PROTO,
                 "EVP_PKEY_get_raw_public_key failed");
        goto fail;
    }

    *method = methodBuf;
    if(method_len)
        *method_len = sizeof(methodName) - 1;

    *pubkeydata = keyBuf;
    if(pubkeydata_len)
        *pubkeydata_len = bufLen;

    return 0;

fail:
    if(methodBuf)
        SSH2_FREE(session, methodBuf);
    if(keyBuf)
        SSH2_FREE(session, keyBuf);
    return -1;
}

static int ossl_ed25519_openssh_priv_to_pubkey(LIBSSH2_SESSION *session,
                                               struct string_buf *decrypted,
                                               unsigned char **method,
                                               size_t *method_len,
                                               unsigned char **pubkeydata,
                                               size_t *pubkeydata_len,
                                               ssh2_ed25519_ctx **out_ctx)
{
    ssh2_ed25519_ctx *ctx = NULL;
    unsigned char *method_buf = NULL;
    unsigned char *key = NULL;
    int i, ret = 0;
    unsigned char *pub_key, *priv_key, *buf;
    size_t key_len = 0, tmp_len = 0;
    unsigned char *p;

    ssh2_deb((session, LIBSSH2_TRACE_AUTH,
              "Computing ED25519 keys from private key data"));

    if(ssh2_get_string(decrypted, &pub_key, &tmp_len) ||
       tmp_len != SSH2_ED25519_KEY_LEN) {
        ssh2_err(session, LIBSSH2_ERROR_PROTO, "Wrong public key length");
        return -1;
    }

    if(ssh2_get_string(decrypted, &priv_key, &tmp_len) ||
       tmp_len != SSH2_ED25519_PRIVATE_KEY_LEN) {
        ssh2_err(session, LIBSSH2_ERROR_PROTO, "Wrong private key length");
        goto clean_exit;
    }

    /* first 32 bytes of priv_key is the private key, the last 32 bytes are
       the public key */
    ctx = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL,
                                       (const unsigned char *)priv_key,
                                       SSH2_ED25519_KEY_LEN);

    /* comment */
    if(ssh2_get_string(decrypted, &buf, &tmp_len)) {
        ssh2_err(session, LIBSSH2_ERROR_PROTO, "Unable to read comment");
        goto clean_exit;
    }

    if(tmp_len > 0) {
        unsigned char *comment = SSH2_CALLOC(session, tmp_len + 1);
        if(comment) {
            memcpy(comment, buf, tmp_len);
            /* NOLINTNEXTLINE(bugprone-not-null-terminated-result) */
            memcpy(comment + tmp_len, "\0", 1);

            ssh2_deb((session, LIBSSH2_TRACE_AUTH, "Key comment: %s",
                      comment));

            SSH2_FREE(session, comment);
        }
    }

    /* Padding */
    i = 1;
    while(decrypted->dataptr < decrypted->data + decrypted->len) {
        if(*decrypted->dataptr != i) {
            ssh2_err(session, LIBSSH2_ERROR_PROTO, "Wrong padding");
            goto clean_exit;
        }
        i++;
        decrypted->dataptr++;
    }

    if(ret == 0) {
        ssh2_deb((session, LIBSSH2_TRACE_AUTH,
                  "Computing public key from ED25519 private key envelope"));

        method_buf = SSH2_ALLOC(session, 11); /* ssh-ed25519. */
        if(!method_buf) {
            ssh2_err(session, LIBSSH2_ERROR_ALLOC,
                     "Unable to allocate memory for ED25519 key");
            goto clean_exit;
        }

        /* Key form is: type_len(4) + type(11) + pub_key_len(4) +
           pub_key(32). */
        key_len = SSH2_ED25519_KEY_LEN + 19;
        key = SSH2_CALLOC(session, key_len);
        if(!key) {
            ssh2_err(session, LIBSSH2_ERROR_ALLOC,
                     "Unable to allocate memory for ED25519 key");
            goto clean_exit;
        }

        p = key;

        ssh2_store_str(&p, "ssh-ed25519", 11);
        ssh2_store_str(&p, (const char *)pub_key, SSH2_ED25519_KEY_LEN);

        /* NOLINTNEXTLINE(bugprone-not-null-terminated-result) */
        memcpy(method_buf, "ssh-ed25519", 11);

        if(method)
            *method = method_buf;
        else
            SSH2_FREE(session, method_buf);

        if(method_len)
            *method_len = 11;

        if(pubkeydata)
            *pubkeydata = key;
        else
            SSH2_FREE(session, key);

        if(pubkeydata_len)
            *pubkeydata_len = key_len;

        if(out_ctx)
            *out_ctx = ctx;
        else if(ctx)
            ssh2_ed25519_free(ctx);

        return 0;
    }

clean_exit:

    if(ctx)
        ssh2_ed25519_free(ctx);

    if(method_buf)
        SSH2_FREE(session, method_buf);

    if(key)
        SSH2_FREE(session, key);

    return -1;
}

static int ossl_ed25519_openssh_sk_priv_to_pubkey(
    LIBSSH2_SESSION *session,
    struct string_buf *decrypted,
    unsigned char **method,
    size_t *method_len,
    unsigned char **pubkeydata,
    size_t *pubkeydata_len,
    unsigned char *flags,
    const char **application,
    const unsigned char **key_handle,
    size_t *handle_len,
    ssh2_ed25519_ctx **out_ctx)
{
    const char *key_type = "sk-ssh-ed25519@openssh.com";

    ssh2_ed25519_ctx *ctx = NULL;
    unsigned char *method_buf = NULL;
    unsigned char *key = NULL;
    int ret = 0;
    unsigned char *pub_key, *app;
    size_t key_len = 0, app_len = 0, tmp_len = 0;
    unsigned char *p;

    ssh2_deb((session, LIBSSH2_TRACE_AUTH,
              "Computing sk-ED25519 keys from private key data"));

    if(ssh2_get_string(decrypted, &pub_key, &tmp_len) ||
       tmp_len != SSH2_ED25519_KEY_LEN) {
        ssh2_err(session, LIBSSH2_ERROR_PROTO, "Wrong public key length");
        return -1;
    }

    if(ssh2_get_string(decrypted, &app, &app_len)) {
        ssh2_err(session, LIBSSH2_ERROR_PROTO, "No SK application.");
        return -1;
    }

    if(flags && ssh2_get_byte(decrypted, flags)) {
        ssh2_err(session, LIBSSH2_ERROR_PROTO, "No SK flags.");
        return -1;
    }

    if(key_handle && handle_len) {
        unsigned char *handle = NULL;
        if(ssh2_get_string(decrypted, &handle, handle_len)) {
            ssh2_err(session, LIBSSH2_ERROR_PROTO, "No SK key_handle.");
            return -1;
        }

        if(*handle_len > 0) {
            *key_handle = SSH2_ALLOC(session, *handle_len);
            if(key_handle && *key_handle)
                memcpy(SSH2_UNCONST(*key_handle), handle, *handle_len);
        }
    }

    ctx = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL,
                                      (const unsigned char *)pub_key,
                                      SSH2_ED25519_KEY_LEN);

    if(ret == 0) {
        ssh2_deb((session, LIBSSH2_TRACE_AUTH,
                  "Computing public key from ED25519 private key envelope"));

        /* sk-ssh-ed25519@openssh.com. */
        method_buf = SSH2_ALLOC(session, strlen(key_type));
        if(!method_buf) {
            ssh2_err(session, LIBSSH2_ERROR_ALLOC,
                     "Unable to allocate memory for ED25519 key");
            goto clean_exit;
        }

        /* Key form is: type_len(4) + type(26) + pub_key_len(4) +
           pub_key(32) + application_len(4) + application(X). */
        key_len = SSH2_ED25519_KEY_LEN + 38 + app_len;
        key = SSH2_CALLOC(session, key_len);
        if(!key) {
            ssh2_err(session, LIBSSH2_ERROR_ALLOC,
                     "Unable to allocate memory for ED25519 key");
            goto clean_exit;
        }

        p = key;

        ssh2_store_str(&p, key_type, strlen(key_type));
        ssh2_store_str(&p, (const char *)pub_key, SSH2_ED25519_KEY_LEN);
        ssh2_store_str(&p, (const char *)app, app_len);

        if(application && app_len > 0) {
            *application = SSH2_ALLOC(session, app_len + 1);
            ssh2_explicit_zero(SSH2_UNCONST(*application), app_len + 1);
            memcpy(SSH2_UNCONST(*application), app, app_len);
        }

        /* NOLINTNEXTLINE(bugprone-not-null-terminated-result) */
        memcpy(method_buf, key_type, strlen(key_type));

        if(method)
            *method = method_buf;
        else
            SSH2_FREE(session, method_buf);

        if(method_len)
            *method_len = strlen(key_type);

        if(pubkeydata)
            *pubkeydata = key;
        else if(key)
            SSH2_FREE(session, key);

        if(pubkeydata_len)
            *pubkeydata_len = key_len;

        if(out_ctx)
            *out_ctx = ctx;
        else if(ctx)
            ssh2_ed25519_free(ctx);

        return 0;
    }

clean_exit:

    if(ctx)
        ssh2_ed25519_free(ctx);

    if(method_buf)
        SSH2_FREE(session, method_buf);

    if(key)
        SSH2_FREE(session, key);

    if(application && *application) {
        SSH2_FREE(session, SSH2_UNCONST(*application));
        *application = NULL;
    }

    if(key_handle && *key_handle) {
        SSH2_FREE(session, SSH2_UNCONST(*key_handle));
        *key_handle = NULL;
    }

    return -1;
}

int ssh2_ed25519_new_private(ssh2_ed25519_ctx **ed_ctx,
                             LIBSSH2_SESSION *session,
                             const char *filename,
                             const uint8_t *passphrase)
{
    int rc;
    FILE *fp;
    unsigned char *buf;
    struct string_buf *decrypted = NULL;
    ssh2_ed25519_ctx *ctx = NULL;

    if(!session) {
        ssh2_err(session, LIBSSH2_ERROR_PROTO, "Session is required");
        return -1;
    }

    ssh2_init_if_needed();

    fp = fopen(filename, "r");
    if(!fp) {
        ssh2_err(session, LIBSSH2_ERROR_FILE,
                 "Unable to open ED25519 private key file");
        return -1;
    }

    rc = ssh2_openssh_pem_parse(session, passphrase, fp, &decrypted);
    fclose(fp);
    if(rc)
        return rc;

    /* We have a new key file, now try and parse it using supported types  */
    rc = ssh2_get_string(decrypted, &buf, NULL);

    if(rc || !buf) {
        ssh2_err(session, LIBSSH2_ERROR_PROTO,
                 "Public key type in decrypted key data not found");
        return -1;
    }

    if(strcmp("ssh-ed25519", (const char *)buf) == 0)
        rc = ossl_ed25519_openssh_priv_to_pubkey(session, decrypted,
                                                 NULL, NULL, NULL, NULL, &ctx);
    else
        rc = -1;

    if(decrypted)
        ssh2_string_buf_free(session, decrypted);

    if(rc == 0) {
        if(ed_ctx)
            *ed_ctx = ctx;
        else if(ctx)
            ssh2_ed25519_free(ctx);
    }

    return rc;
}

int ssh2_ed25519_new_private_sk(ssh2_ed25519_ctx **ed_ctx,
                                unsigned char *flags,
                                const char **application,
                                const unsigned char **key_handle,
                                size_t *handle_len,
                                LIBSSH2_SESSION *session,
                                const char *filename,
                                const uint8_t *passphrase)
{
    int rc;
    FILE *fp;
    unsigned char *buf;
    struct string_buf *decrypted = NULL;
    ssh2_ed25519_ctx *ctx = NULL;

    if(!session) {
        ssh2_err(session, LIBSSH2_ERROR_PROTO, "Session is required");
        return -1;
    }

    ssh2_init_if_needed();

    fp = fopen(filename, "r");
    if(!fp) {
        ssh2_err(session, LIBSSH2_ERROR_FILE,
                 "Unable to open ED25519 SK private key file");
        return -1;
    }

    rc = ssh2_openssh_pem_parse(session, passphrase, fp, &decrypted);
    fclose(fp);
    if(rc)
        return rc;

    /* We have a new key file, now try and parse it using supported types  */
    rc = ssh2_get_string(decrypted, &buf, NULL);

    if(rc || !buf) {
        ssh2_err(session, LIBSSH2_ERROR_PROTO,
                 "Public key type in decrypted key data not found");
        return -1;
    }

    if(strcmp("sk-ssh-ed25519@openssh.com", (const char *)buf) == 0)
        rc = ossl_ed25519_openssh_sk_priv_to_pubkey(session, decrypted,
                                                    NULL, NULL, NULL, NULL,
                                                    flags, application,
                                                    key_handle, handle_len,
                                                    &ctx);
    else
        rc = -1;

    if(decrypted)
        ssh2_string_buf_free(session, decrypted);

    if(rc == 0) {
        if(ed_ctx)
            *ed_ctx = ctx;
        else if(ctx)
            ssh2_ed25519_free(ctx);
    }

    return rc;
}

int ssh2_ed25519_new_private_frommemory(ssh2_ed25519_ctx **ed_ctx,
                                        LIBSSH2_SESSION *session,
                                        const char *filedata,
                                        size_t filedata_len,
                                        const unsigned char *passphrase)
{
    ssh2_ed25519_ctx *ctx = NULL;
    BIO *bp;

    ssh2_init_if_needed();

    bp = BIO_new_mem_buf(filedata, (int)filedata_len);
    if(bp) {
        ctx = PEM_read_bio_PrivateKey(bp, NULL, ossl_passphrase_cb,
                                      SSH2_UNCONST(passphrase));
        BIO_free(bp);
        if(ctx) {
            if(EVP_PKEY_id(ctx) != EVP_PKEY_ED25519) {
                ssh2_ed25519_free(ctx);
                return ssh2_err(session, LIBSSH2_ERROR_PROTO,
                                "Private key is not an ED25519 key");
            }

            *ed_ctx = ctx;
            return 0;
        }
    }

    return ossl_key_from_openssh_blob(session, (void **)ed_ctx, "ssh-ed25519",
                                      NULL, NULL, NULL, NULL,
                                      filedata, filedata_len, passphrase);
}

int ssh2_ed25519_new_private_frommemory_sk(ssh2_ed25519_ctx **ed_ctx,
                                           unsigned char *flags,
                                           const char **application,
                                           const unsigned char **key_handle,
                                           size_t *handle_len,
                                           LIBSSH2_SESSION *session,
                                           const char *filedata,
                                           size_t filedata_len,
                                           const unsigned char *passphrase)
{
    int algorithm;
    return ossl_key_sk_from_openssh_blob(session, (void **)ed_ctx,
                                         "sk-ssh-ed25519@openssh.com",
                                         NULL, NULL, NULL, NULL,
                                         &algorithm, flags, application,
                                         key_handle, handle_len,
                                         filedata, filedata_len,
                                         passphrase);
}

int ssh2_ed25519_new_public(ssh2_ed25519_ctx **ed_ctx,
                            LIBSSH2_SESSION *session,
                            const unsigned char *raw_pub_key,
                            const size_t key_len)
{
    ssh2_ed25519_ctx *ctx = NULL;

    if(!ed_ctx)
        return -1;

    ctx = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL,
                                      raw_pub_key, key_len);
    if(!ctx)
        return ssh2_err(session, LIBSSH2_ERROR_PROTO,
                        "could not create ED25519 public key");

    if(ed_ctx)
        *ed_ctx = ctx;
    else if(ctx)
        ssh2_ed25519_free(ctx);

    return 0;
}
#endif /* LIBSSH2_ED25519 */

#if LIBSSH2_MLKEM

int ssh2_mlkem_new(LIBSSH2_SESSION *session, int ml_kem_size,
                   unsigned char **out_public_key,
                   unsigned char **out_private_key)
{
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    unsigned char *priv = NULL, *pub = NULL;
    const char *evp_name;
    size_t privLen, actualPrivLen, pubLen, actualPubLen;
    int rc = -1;

    switch(ml_kem_size) {
    case 512:
        evp_name = "ML-KEM-512";
        privLen = SSH2_MLKEM_512_PRIVATE_KEY_LEN;
        pubLen = SSH2_MLKEM_512_PUBLIC_KEY_LEN;
        break;
    case 768:
        evp_name = "ML-KEM-768";
        privLen = SSH2_MLKEM_768_PRIVATE_KEY_LEN;
        pubLen = SSH2_MLKEM_768_PUBLIC_KEY_LEN;
        break;
    case 1024:
        evp_name = "ML-KEM-1024";
        privLen = SSH2_MLKEM_1024_PRIVATE_KEY_LEN;
        pubLen = SSH2_MLKEM_1024_PUBLIC_KEY_LEN;
        break;
    default:
        goto clean_exit;
    }

    pctx = EVP_PKEY_CTX_new_from_name(NULL, evp_name, NULL);
    if(!pctx)
        return -1;

    if(EVP_PKEY_keygen_init(pctx) != 1 ||
       EVP_PKEY_keygen(pctx, &key) != 1) {
        goto clean_exit;
    }

    if(out_private_key) {
        priv = SSH2_ALLOC(session, privLen);
        actualPrivLen = privLen;
        if(!priv)
            goto clean_exit;

        if(EVP_PKEY_get_raw_private_key(key, priv, &actualPrivLen) != 1 ||
           privLen != actualPrivLen) {
            goto clean_exit;
        }

        *out_private_key = priv;
        priv = NULL;
    }

    if(out_public_key) {
        pub = SSH2_ALLOC(session, pubLen);
        if(!pub)
            goto clean_exit;

        if(EVP_PKEY_get_raw_public_key(key, pub, &actualPubLen) != 1 ||
           pubLen != actualPubLen) {
            goto clean_exit;
        }

        *out_public_key = pub;
        pub = NULL;
    }

    /* success */
    rc = 0;

clean_exit:

    if(pctx)
        EVP_PKEY_CTX_free(pctx);
    if(key)
        EVP_PKEY_free(key);
    if(priv)
        SSH2_FREE(session, priv);
    if(pub)
        SSH2_FREE(session, pub);

    return rc;
}

int ssh2_mlkem_get_sk(unsigned char *out_shared_key, int ml_kem_size,
                      uint8_t *private_key, uint8_t *server_ciphertext)
{
    int rc = -1;
    EVP_PKEY *client_key = NULL;
    EVP_PKEY_CTX *client_key_ctx = NULL;
    size_t out_len = 0;
    const char *evp_name;
    size_t privLen, ciphertextLen;

    switch(ml_kem_size) {
    case 512:
        evp_name = "ML-KEM-512";
        privLen = SSH2_MLKEM_512_PRIVATE_KEY_LEN;
        ciphertextLen = SSH2_MLKEM_512_CIPHERTEXT;
        break;
    case 768:
        evp_name = "ML-KEM-768";
        privLen = SSH2_MLKEM_768_PRIVATE_KEY_LEN;
        ciphertextLen = SSH2_MLKEM_768_CIPHERTEXT;
        break;
    case 1024:
        evp_name = "ML-KEM-1024";
        privLen = SSH2_MLKEM_1024_PRIVATE_KEY_LEN;
        ciphertextLen = SSH2_MLKEM_1024_CIPHERTEXT;
        break;
    default:
        goto clean_exit;
    }

    if(!out_shared_key)
        return -1;

    client_key = EVP_PKEY_new_raw_private_key_ex(NULL, evp_name,
                                                 NULL, private_key, privLen);

    if(!client_key)
        goto clean_exit;

    client_key_ctx = EVP_PKEY_CTX_new(client_key, NULL);
    if(!client_key_ctx)
        goto clean_exit;

    rc = EVP_PKEY_decapsulate_init(client_key_ctx, NULL);
    if(rc <= 0)
        goto clean_exit;

    rc = EVP_PKEY_decapsulate(client_key_ctx, NULL, &out_len,
                              server_ciphertext, ciphertextLen);
    if(rc <= 0)
        goto clean_exit;

    if(out_len != SSH2_MLKEM_SHARED_SECRET_LEN) {
        rc = -1;
        goto clean_exit;
    }

    rc = EVP_PKEY_decapsulate(client_key_ctx, out_shared_key, &out_len,
                              server_ciphertext, ciphertextLen);

clean_exit:

    if(client_key_ctx)
        EVP_PKEY_CTX_free(client_key_ctx);
    if(client_key)
        EVP_PKEY_free(client_key);

    return (rc == 1) ? 0 : -1;
}

#endif

#if LIBSSH2_RSA
int ssh2_rsa_sha2_sign(LIBSSH2_SESSION *session, ssh2_rsa_ctx *rsactx,
                       const unsigned char *hash, size_t hash_len,
                       unsigned char **signature, size_t *signature_len)
{
    int ret = -1;
    unsigned char *sig = NULL;

#ifdef USE_OPENSSL_3
    size_t sig_len = 0;
    BIGNUM *n = NULL;
    const EVP_MD *md = NULL;

    if(EVP_PKEY_get_bn_param(rsactx, OSSL_PKEY_PARAM_RSA_N, &n) > 0) {
        sig_len = BN_num_bytes(n);
        BN_clear_free(n);
    }

    if(sig_len > 0)
        sig = SSH2_ALLOC(session, sig_len);
#else
    unsigned int sig_len = 0;

    sig_len = RSA_size(rsactx);
    sig = SSH2_ALLOC(session, sig_len);
#endif

    if(!sig)
        return -1;

#ifdef USE_OPENSSL_3
    if(hash_len == SHA_DIGEST_LENGTH)
        md = EVP_sha1();
    else if(hash_len == SHA256_DIGEST_LENGTH)
        md = EVP_sha256();
    else if(hash_len == SHA512_DIGEST_LENGTH)
        md = EVP_sha512();
    else
        ssh2_err(session, LIBSSH2_ERROR_PROTO,
                 "Unsupported hash digest length");

    if(md) {
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(rsactx, NULL);
        if(ctx &&
           EVP_PKEY_sign_init(ctx) > 0 &&
           EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) > 0 &&
           EVP_PKEY_CTX_set_signature_md(ctx, md) > 0) {
            ret = EVP_PKEY_sign(ctx, sig, &sig_len, hash, hash_len);
        }

        if(ctx)
            EVP_PKEY_CTX_free(ctx);
    }
#else
    if(hash_len == SHA_DIGEST_LENGTH)
        ret = RSA_sign(NID_sha1,
                       hash, (unsigned int)hash_len, sig, &sig_len, rsactx);
    else if(hash_len == SHA256_DIGEST_LENGTH)
        ret = RSA_sign(NID_sha256,
                       hash, (unsigned int)hash_len, sig, &sig_len, rsactx);
    else if(hash_len == SHA512_DIGEST_LENGTH)
        ret = RSA_sign(NID_sha512,
                       hash, (unsigned int)hash_len, sig, &sig_len, rsactx);
    else {
        ssh2_err(session, LIBSSH2_ERROR_PROTO,
                 "Unsupported hash digest length");
        ret = -1;
    }
#endif

    if(!ret) {
        SSH2_FREE(session, sig);
        return -1;
    }

    *signature = sig;
    *signature_len = sig_len;

    return 0;
}

#if LIBSSH2_RSA_SHA1
int ssh2_rsa_sha1_sign(LIBSSH2_SESSION *session, ssh2_rsa_ctx *rsactx,
                       const unsigned char *hash, size_t hash_len,
                       unsigned char **signature, size_t *signature_len)
{
    return ssh2_rsa_sha2_sign(session, rsactx, hash, hash_len,
                              signature, signature_len);
}
#endif
#endif

#if LIBSSH2_DSA
int ssh2_dsa_sha1_sign(ssh2_dsa_ctx *dsactx,
                       const unsigned char *hash,
                       size_t hash_len, unsigned char *signature)
{
    DSA_SIG *sig = NULL;
    const BIGNUM *r;
    const BIGNUM *s;
    int r_len, s_len;

#ifdef USE_OPENSSL_3
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(dsactx, NULL);
    unsigned char *buf = NULL;
    size_t sig_len = 0;
    int size = 0;

    if(EVP_PKEY_get_int_param(dsactx, OSSL_PKEY_PARAM_MAX_SIZE, &size) > 0) {
        sig_len = size;
        buf = OPENSSL_malloc(size);
    }

    if(buf && ctx && EVP_PKEY_sign_init(ctx) > 0)
        EVP_PKEY_sign(ctx, buf, &sig_len, hash, hash_len);

    if(ctx)
        EVP_PKEY_CTX_free(ctx);

    if(buf) {
        const unsigned char *in = buf;
        d2i_DSA_SIG(&sig, &in, (long)sig_len);
        OPENSSL_clear_free(buf, size);
    }
#else
    (void)hash_len;

    sig = DSA_do_sign(hash, SHA_DIGEST_LENGTH, dsactx);
#endif

    if(!sig)
        return -1;

#ifdef HAVE_OPAQUE_STRUCTS
    DSA_SIG_get0(sig, &r, &s);
#else
    r = sig->r;
    s = sig->s;
#endif
    r_len = BN_num_bytes(r);
    if(r_len < 1 || r_len > SHA_DIGEST_LENGTH) {
        DSA_SIG_free(sig);
        return -1;
    }
    s_len = BN_num_bytes(s);
    if(s_len < 1 || s_len > SHA_DIGEST_LENGTH) {
        DSA_SIG_free(sig);
        return -1;
    }

    memset(signature, 0, SHA_DIGEST_LENGTH * 2);

    BN_bn2bin(r, signature + (SHA_DIGEST_LENGTH - r_len));
    BN_bn2bin(s, signature + SHA_DIGEST_LENGTH + (SHA_DIGEST_LENGTH - s_len));

    DSA_SIG_free(sig);

    return 0;
}
#endif /* LIBSSH_DSA */

#if LIBSSH2_ECDSA

int ssh2_ecdsa_sign(LIBSSH2_SESSION *session, ssh2_ecdsa_ctx *ec_ctx,
                    const unsigned char *hash, size_t hash_len,
                    unsigned char **signature, size_t *signature_len)
{
    int r_len, s_len;
    int rc = 0;
    size_t out_buffer_len = 0;
    unsigned char *sp;
    const BIGNUM *pr = NULL, *ps = NULL;
    unsigned char *temp_buffer = NULL;
    unsigned char *out_buffer = NULL;
    ECDSA_SIG *sig = NULL;

#ifdef USE_OPENSSL_3
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(ec_ctx, NULL);
    const unsigned char *p = NULL;
    rc = -1;

    if(!ctx)
        return ssh2_err(session, LIBSSH2_ERROR_ALLOC, "out of memory");

    out_buffer_len = EVP_PKEY_get_size(ec_ctx);
    temp_buffer = OPENSSL_malloc(out_buffer_len);
    if(!temp_buffer)
        goto clean_exit;

    rc = EVP_PKEY_sign_init(ctx);
    if(rc <= 0) {
        rc = -1;
        goto clean_exit;
    }

    rc = EVP_PKEY_sign(ctx, temp_buffer, &out_buffer_len, hash, hash_len);
    if(rc <= 0) {
        rc = -1;
        goto clean_exit;
    }

    rc = 0;

    p = temp_buffer;
    sig = d2i_ECDSA_SIG(NULL, &p, (long)out_buffer_len);
    OPENSSL_clear_free(temp_buffer, out_buffer_len);
#else
    sig = ECDSA_do_sign(hash, (int)hash_len, ec_ctx);
    if(!sig)
        return -1;
#endif

#ifdef HAVE_OPAQUE_STRUCTS
    ECDSA_SIG_get0(sig, &pr, &ps);
#else
    pr = sig->r;
    ps = sig->s;
#endif

    r_len = BN_num_bytes(pr) + 1;
    s_len = BN_num_bytes(ps) + 1;

    temp_buffer = malloc(r_len + s_len + 8);
    if(!temp_buffer) {
        rc = -1;
        goto clean_exit;
    }

    sp = temp_buffer;
    sp = ossl_write_bn(sp, pr, r_len);
    sp = ossl_write_bn(sp, ps, s_len);

    out_buffer_len = (size_t)(sp - temp_buffer);

    out_buffer = SSH2_CALLOC(session, out_buffer_len);
    if(!out_buffer) {
        rc = -1;
        goto clean_exit;
    }

    memcpy(out_buffer, temp_buffer, out_buffer_len);

    *signature = out_buffer;
    *signature_len = out_buffer_len;

clean_exit:

    if(temp_buffer)
        free(temp_buffer);

    if(sig)
        ECDSA_SIG_free(sig);

#ifdef USE_OPENSSL_3
    if(ctx)
        EVP_PKEY_CTX_free(ctx);
#endif

    return rc;
}
#endif /* LIBSSH2_ECDSA */

int ssh2_ossl_sha1_init(ssh2_sha1_ctx *ctx)
{
#ifdef HAVE_OPAQUE_STRUCTS
    *ctx = EVP_MD_CTX_new();

    if(!*ctx)
        return 0;

    if(EVP_DigestInit(*ctx, EVP_get_digestbyname("sha1")))
        return 1;

    EVP_MD_CTX_free(*ctx);
    *ctx = NULL;

    return 0;
#else
    EVP_MD_CTX_init(ctx);
    return EVP_DigestInit(ctx, EVP_get_digestbyname("sha1"));
#endif
}

int ssh2_ossl_sha1_update(ssh2_sha1_ctx *ctx, const void *data, size_t len)
{
#ifdef HAVE_OPAQUE_STRUCTS
    return EVP_DigestUpdate(*ctx, data, len);
#else
    return EVP_DigestUpdate(ctx, data, len);
#endif
}

int ssh2_ossl_sha1_final(ssh2_sha1_ctx *ctx, unsigned char *out)
{
#ifdef HAVE_OPAQUE_STRUCTS
    int ret = EVP_DigestFinal(*ctx, out, NULL);
    EVP_MD_CTX_free(*ctx);
    return ret;
#else
    return EVP_DigestFinal(ctx, out, NULL);
#endif
}

int ssh2_ossl_sha1(const unsigned char *message, size_t len,
                   unsigned char *out)
{
#ifdef HAVE_OPAQUE_STRUCTS
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    if(!ctx)
        return 1; /* error */

    if(EVP_DigestInit(ctx, EVP_get_digestbyname("sha1"))) {
        EVP_DigestUpdate(ctx, message, len);
        EVP_DigestFinal(ctx, out, NULL);
        EVP_MD_CTX_free(ctx);
        return 0; /* success */
    }
    EVP_MD_CTX_free(ctx);
#else
    EVP_MD_CTX ctx;

    EVP_MD_CTX_init(&ctx);
    if(EVP_DigestInit(&ctx, EVP_get_digestbyname("sha1"))) {
        EVP_DigestUpdate(&ctx, message, len);
        EVP_DigestFinal(&ctx, out, NULL);
        return 0; /* success */
    }
#endif
    return 1; /* error */
}

int ssh2_ossl_sha256_init(ssh2_sha256_ctx *ctx)
{
#ifdef HAVE_OPAQUE_STRUCTS
    *ctx = EVP_MD_CTX_new();

    if(!*ctx)
        return 0;

    if(EVP_DigestInit(*ctx, EVP_get_digestbyname("sha256")))
        return 1;

    EVP_MD_CTX_free(*ctx);
    *ctx = NULL;

    return 0;
#else
    EVP_MD_CTX_init(ctx);
    return EVP_DigestInit(ctx, EVP_get_digestbyname("sha256"));
#endif
}

int ssh2_ossl_sha256_update(ssh2_sha256_ctx *ctx, const void *data, size_t len)
{
#ifdef HAVE_OPAQUE_STRUCTS
    return EVP_DigestUpdate(*ctx, data, len);
#else
    return EVP_DigestUpdate(ctx, data, len);
#endif
}

int ssh2_ossl_sha256_final(ssh2_sha256_ctx *ctx, unsigned char *out)
{
#ifdef HAVE_OPAQUE_STRUCTS
    int ret = EVP_DigestFinal(*ctx, out, NULL);
    EVP_MD_CTX_free(*ctx);
    return ret;
#else
    return EVP_DigestFinal(ctx, out, NULL);
#endif
}

int ssh2_ossl_sha256(const unsigned char *message, size_t len,
                     unsigned char *out)
{
#ifdef HAVE_OPAQUE_STRUCTS
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    if(!ctx)
        return 1; /* error */

    if(EVP_DigestInit(ctx, EVP_get_digestbyname("sha256"))) {
        EVP_DigestUpdate(ctx, message, len);
        EVP_DigestFinal(ctx, out, NULL);
        EVP_MD_CTX_free(ctx);
        return 0; /* success */
    }
    EVP_MD_CTX_free(ctx);
#else
    EVP_MD_CTX ctx;

    EVP_MD_CTX_init(&ctx);
    if(EVP_DigestInit(&ctx, EVP_get_digestbyname("sha256"))) {
        EVP_DigestUpdate(&ctx, message, len);
        EVP_DigestFinal(&ctx, out, NULL);
        return 0; /* success */
    }
#endif
    return 1; /* error */
}

int ssh2_ossl_sha384_init(ssh2_sha384_ctx *ctx)
{
#ifdef HAVE_OPAQUE_STRUCTS
    *ctx = EVP_MD_CTX_new();

    if(!*ctx)
        return 0;

    if(EVP_DigestInit(*ctx, EVP_get_digestbyname("sha384")))
        return 1;

    EVP_MD_CTX_free(*ctx);
    *ctx = NULL;

    return 0;
#else
    EVP_MD_CTX_init(ctx);
    return EVP_DigestInit(ctx, EVP_get_digestbyname("sha384"));
#endif
}

int ssh2_ossl_sha384_update(ssh2_sha384_ctx *ctx, const void *data, size_t len)
{
#ifdef HAVE_OPAQUE_STRUCTS
    return EVP_DigestUpdate(*ctx, data, len);
#else
    return EVP_DigestUpdate(ctx, data, len);
#endif
}

int ssh2_ossl_sha384_final(ssh2_sha384_ctx *ctx, unsigned char *out)
{
#ifdef HAVE_OPAQUE_STRUCTS
    int ret = EVP_DigestFinal(*ctx, out, NULL);
    EVP_MD_CTX_free(*ctx);
    return ret;
#else
    return EVP_DigestFinal(ctx, out, NULL);
#endif
}

int ssh2_ossl_sha384(const unsigned char *message, size_t len,
                     unsigned char *out)
{
#ifdef HAVE_OPAQUE_STRUCTS
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    if(!ctx)
        return 1; /* error */

    if(EVP_DigestInit(ctx, EVP_get_digestbyname("sha384"))) {
        EVP_DigestUpdate(ctx, message, len);
        EVP_DigestFinal(ctx, out, NULL);
        EVP_MD_CTX_free(ctx);
        return 0; /* success */
    }
    EVP_MD_CTX_free(ctx);
#else
    EVP_MD_CTX ctx;

    EVP_MD_CTX_init(&ctx);
    if(EVP_DigestInit(&ctx, EVP_get_digestbyname("sha384"))) {
        EVP_DigestUpdate(&ctx, message, len);
        EVP_DigestFinal(&ctx, out, NULL);
        return 0; /* success */
    }
#endif
    return 1; /* error */
}

int ssh2_ossl_sha512_init(ssh2_sha512_ctx *ctx)
{
#ifdef HAVE_OPAQUE_STRUCTS
    *ctx = EVP_MD_CTX_new();

    if(!*ctx)
        return 0;

    if(EVP_DigestInit(*ctx, EVP_get_digestbyname("sha512")))
        return 1;

    EVP_MD_CTX_free(*ctx);
    *ctx = NULL;

    return 0;
#else
    EVP_MD_CTX_init(ctx);
    return EVP_DigestInit(ctx, EVP_get_digestbyname("sha512"));
#endif
}

int ssh2_ossl_sha512_update(ssh2_sha512_ctx *ctx, const void *data, size_t len)
{
#ifdef HAVE_OPAQUE_STRUCTS
    return EVP_DigestUpdate(*ctx, data, len);
#else
    return EVP_DigestUpdate(ctx, data, len);
#endif
}

int ssh2_ossl_sha512_final(ssh2_sha512_ctx *ctx, unsigned char *out)
{
#ifdef HAVE_OPAQUE_STRUCTS
    int ret = EVP_DigestFinal(*ctx, out, NULL);
    EVP_MD_CTX_free(*ctx);
    return ret;
#else
    return EVP_DigestFinal(ctx, out, NULL);
#endif
}

int ssh2_ossl_sha512(const unsigned char *message, size_t len,
                     unsigned char *out)
{
#ifdef HAVE_OPAQUE_STRUCTS
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    if(!ctx)
        return 1; /* error */

    if(EVP_DigestInit(ctx, EVP_get_digestbyname("sha512"))) {
        EVP_DigestUpdate(ctx, message, len);
        EVP_DigestFinal(ctx, out, NULL);
        EVP_MD_CTX_free(ctx);
        return 0; /* success */
    }
    EVP_MD_CTX_free(ctx);
#else
    EVP_MD_CTX ctx;

    EVP_MD_CTX_init(&ctx);
    if(EVP_DigestInit(&ctx, EVP_get_digestbyname("sha512"))) {
        EVP_DigestUpdate(&ctx, message, len);
        EVP_DigestFinal(&ctx, out, NULL);
        return 0; /* success */
    }
#endif
    return 1; /* error */
}

#if LIBSSH2_MD5 || LIBSSH2_MD5_PEM
int ssh2_ossl_md5_init(ssh2_md5_ctx *ctx)
{
    /* MD5 digest is not supported in OpenSSL FIPS mode
     * Trying to init it results in a latent OpenSSL error:
     * "digital envelope routines:FIPS_DIGESTINIT:disabled for fips"
     * Thus, return 0 in FIPS mode
     */
#if !defined(USE_OPENSSL_3) && \
    !defined(LIBRESSL_VERSION_NUMBER) && \
    !defined(LIBSSH2_WOLFSSL)

    if(FIPS_mode())
        return 0;
#endif

#ifdef HAVE_OPAQUE_STRUCTS
    *ctx = EVP_MD_CTX_new();

    if(!*ctx)
        return 0;

    if(EVP_DigestInit(*ctx, EVP_get_digestbyname("md5")))
        return 1;

    EVP_MD_CTX_free(*ctx);
    *ctx = NULL;

    return 0;
#else
    EVP_MD_CTX_init(ctx);
    return EVP_DigestInit(ctx, EVP_get_digestbyname("md5"));
#endif
}

int ssh2_ossl_md5_update(ssh2_md5_ctx *ctx, const void *data, size_t len)
{
#ifdef HAVE_OPAQUE_STRUCTS
    return EVP_DigestUpdate(*ctx, data, len);
#else
    return EVP_DigestUpdate(ctx, data, len);
#endif
}

int ssh2_ossl_md5_final(ssh2_md5_ctx *ctx, unsigned char *out)
{
#ifdef HAVE_OPAQUE_STRUCTS
    int ret = EVP_DigestFinal(*ctx, out, NULL);
    EVP_MD_CTX_free(*ctx);
    return ret;
#else
    return EVP_DigestFinal(ctx, out, NULL);
#endif
}
#endif

#if LIBSSH2_ECDSA

static int ossl_ecdsa_evp_to_pubkey(LIBSSH2_SESSION *session,
                                    unsigned char **method, size_t *method_len,
                                    unsigned char **pubkeydata,
                                    size_t *pubkeydata_len,
                                    int is_sk,
                                    EVP_PKEY *pk)
{
    int rc = 0;
    unsigned char *p;
    unsigned char *method_buf = NULL;
    unsigned char *key;
    size_t method_buf_len = 0;
    size_t key_len = 0;
    unsigned char *octal_value = NULL;
    size_t octal_len;
    ssh2_curve_type type;

#ifdef USE_OPENSSL_3
    ssh2_deb((session, LIBSSH2_TRACE_AUTH,
              "Computing public key from EC private key envelope"));

    type = ssh2_ecdsa_get_curve_type(pk);
#else
    EC_KEY *ec = NULL;
    const EC_POINT *public_key;
    const EC_GROUP *group;
    BN_CTX *bn_ctx = NULL;

    ssh2_deb((session, LIBSSH2_TRACE_AUTH,
              "Computing public key from EC private key envelope"));

    bn_ctx = BN_CTX_new();
    if(!bn_ctx)
        return -1;

    ec = EVP_PKEY_get1_EC_KEY(pk);
    if(!ec) {
        rc = -1;
        goto clean_exit;
    }

    public_key = EC_KEY_get0_public_key(ec);
    group = EC_KEY_get0_group(ec);
    type = ssh2_ecdsa_get_curve_type(ec);
#endif

    if(is_sk)
        method_buf_len = 34;
    else
        method_buf_len = 19;

    method_buf = SSH2_ALLOC(session, method_buf_len);
    if(!method_buf)
        return ssh2_err(session, LIBSSH2_ERROR_ALLOC, "out of memory");

    if(is_sk)
        memcpy(method_buf, "sk-ecdsa-sha2-nistp256@openssh.com",
               method_buf_len);
    else if(type == SSH2_EC_CURVE_NISTP256)
        memcpy(method_buf, "ecdsa-sha2-nistp256", method_buf_len);
    else if(type == SSH2_EC_CURVE_NISTP384)
        memcpy(method_buf, "ecdsa-sha2-nistp384", method_buf_len);
    else if(type == SSH2_EC_CURVE_NISTP521)
        memcpy(method_buf, "ecdsa-sha2-nistp521", method_buf_len);
    else {
        ssh2_deb((session, LIBSSH2_TRACE_ERROR,
                  "Unsupported EC private key type"));
        rc = -1;
        goto clean_exit;
    }

#ifdef USE_OPENSSL_3
    octal_len = EC_MAX_POINT_LEN;
    octal_value = SSH2_ALLOC(session, octal_len);
    EVP_PKEY_get_octet_string_param(pk, OSSL_PKEY_PARAM_PUB_KEY,
                                    octal_value, octal_len, &octal_len);
#else
    /* get length */
    octal_len = EC_POINT_point2oct(group, public_key,
                                   POINT_CONVERSION_UNCOMPRESSED,
                                   NULL, 0, bn_ctx);
    if(octal_len > EC_MAX_POINT_LEN) {
        rc = -1;
        goto clean_exit;
    }

    octal_value = malloc(octal_len);
    if(!octal_value) {
        rc = -1;
        goto clean_exit;
    }

    /* convert to octal */
    if(EC_POINT_point2oct(group, public_key, POINT_CONVERSION_UNCOMPRESSED,
                          octal_value, octal_len, bn_ctx) != octal_len) {
        rc = -1;
        goto clean_exit;
    }
#endif

    /* Key form is: type_len(4) + type(method_buf_len) + domain_len(4)
       + domain(8) + pub_key_len(4) + pub_key(~65). */
    key_len = 4 + method_buf_len + 4 + 8 + 4 + octal_len;
    key = SSH2_ALLOC(session, key_len);
    if(!key) {
        rc = -1;
        goto clean_exit;
    }

    /* Process key encoding. */
    p = key;

    /* Key type */
    ssh2_store_str(&p, (const char *)method_buf, method_buf_len);

    /* Name domain */
    if(is_sk)
        ssh2_store_str(&p, "nistp256", 8);
    else
        ssh2_store_str(&p, (const char *)method_buf + 11, 8);

    /* Public key */
    ssh2_store_str(&p, (const char *)octal_value, octal_len);

    *method = method_buf;
    if(method_len)
        *method_len = method_buf_len;

    *pubkeydata = key;
    if(pubkeydata_len)
        *pubkeydata_len = key_len;

clean_exit:

#ifndef USE_OPENSSL_3
    if(ec)
        EC_KEY_free(ec);

    if(bn_ctx)
        BN_CTX_free(bn_ctx);
#endif

    if(octal_value)
        free(octal_value);

    if(rc == 0)
        return 0;

    if(method_buf)
        SSH2_FREE(session, method_buf);

    return -1;
}

static int ossl_ecdsa_openssh_priv_to_pubkey(LIBSSH2_SESSION *session,
                                             ssh2_curve_type curve_type,
                                             struct string_buf *decrypted,
                                             unsigned char **method,
                                             size_t *method_len,
                                             unsigned char **pubkeydata,
                                             size_t *pubkeydata_len,
                                             ssh2_ecdsa_ctx **ec_ctx)
{
    int rc = 0;
    size_t curvelen, exponentlen, pointlen;
    unsigned char *curve, *exponent, *point_buf;
    ssh2_ecdsa_ctx *ec_key = NULL;

#ifdef USE_OPENSSL_3
    EVP_PKEY_CTX *fromdata_ctx = NULL;
    OSSL_PARAM params[4];
    const char *n = EC_curve_nid2nist(curve_type);
    char *group_name = NULL;
#else
    BIGNUM *bn_exponent;
#endif

    ssh2_deb((session, LIBSSH2_TRACE_AUTH,
              "Computing ECDSA keys from private key data"));

    if(ssh2_get_string(decrypted, &curve, &curvelen) || curvelen == 0) {
        ssh2_err(session, LIBSSH2_ERROR_PROTO, "ECDSA no curve");
        return -1;
    }

    if(ssh2_get_string(decrypted, &point_buf, &pointlen)) {
        ssh2_err(session, LIBSSH2_ERROR_PROTO, "ECDSA no point");
        return -1;
    }

    if(ssh2_get_bignum_bytes(decrypted, &exponent, &exponentlen)) {
        ssh2_err(session, LIBSSH2_ERROR_PROTO, "ECDSA no exponent");
        return -1;
    }

#ifdef USE_OPENSSL_3
    if(!n)
        return -1;

    fromdata_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);

    if(!fromdata_ctx)
        goto fail;

    group_name = OPENSSL_zalloc(strlen(n) + 1);

    if(!group_name)
        goto fail;

    /* NOLINTNEXTLINE(bugprone-not-null-terminated-result) */
    memcpy(group_name, n, strlen(n));
    ossl_swap_bytes(exponent, (unsigned long)exponentlen);

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                 group_name, 0);

    params[1] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                                  point_buf, pointlen);

    params[2] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_PRIV_KEY, exponent,
                                        exponentlen);

    params[3] = OSSL_PARAM_construct_end();

    if(EVP_PKEY_fromdata_init(fromdata_ctx) <= 0)
        goto fail;

    rc = EVP_PKEY_fromdata(fromdata_ctx, &ec_key, EVP_PKEY_KEYPAIR, params);
    rc = rc != 1;

    if(group_name)
        OPENSSL_clear_free(group_name, strlen(n));
#else
    rc = ssh2_ecdsa_curve_name_with_octal_new(&ec_key, point_buf, pointlen,
                                              curve_type);
    if(rc) {
        rc = -1;
        ssh2_err(session, LIBSSH2_ERROR_PROTO, "ECDSA could not create key");
        goto fail;
    }

    bn_exponent = BN_new();
    if(!bn_exponent) {
        rc = -1;
        ssh2_err(session, LIBSSH2_ERROR_ALLOC,
                 "Unable to allocate memory for private key data");
        goto fail;
    }

    BN_bin2bn(exponent, (int)exponentlen, bn_exponent);
    rc = (EC_KEY_set_private_key(ec_key, bn_exponent) != 1);
#endif

    if(rc == 0 && ec_key && pubkeydata && method) {
#ifdef USE_OPENSSL_3
        EVP_PKEY *pk = ec_key;
#else
        EVP_PKEY *pk = EVP_PKEY_new();
        EVP_PKEY_set1_EC_KEY(pk, ec_key);
#endif

        rc = ossl_ecdsa_evp_to_pubkey(session, method, method_len,
                                      pubkeydata, pubkeydata_len, 0, pk);

#ifndef USE_OPENSSL_3
        if(pk)
            EVP_PKEY_free(pk);
#endif
    }

#ifdef USE_OPENSSL_3
    if(fromdata_ctx)
        EVP_PKEY_CTX_free(fromdata_ctx);
#endif

    if(ec_ctx)
        *ec_ctx = ec_key;
    else
        ssh2_ecdsa_free(ec_key);

    return rc;

fail:
#ifdef USE_OPENSSL_3
    if(fromdata_ctx)
        EVP_PKEY_CTX_free(fromdata_ctx);
#endif

    if(ec_key)
        ssh2_ecdsa_free(ec_key);

    return rc;
}

static int ossl_ecdsa_sk_openssh_priv_to_pubkey(
    LIBSSH2_SESSION *session,
    struct string_buf *decrypted,
    unsigned char **method,
    size_t *method_len,
    unsigned char **pubkeydata,
    size_t *pubkeydata_len,
    uint8_t *flags,
    const char **application,
    const unsigned char **key_handle,
    size_t *handle_len,
    ssh2_ecdsa_ctx **ec_ctx)
{
    int rc = 0;
    size_t curvelen, pointlen, key_len, app_len;
    unsigned char *curve, *point_buf, *p, *key, *app;
    ssh2_ecdsa_ctx *ec_key = NULL;

    ssh2_deb((session, LIBSSH2_TRACE_AUTH, "Extracting ECDSA-SK public key"));

    if(ssh2_get_string(decrypted, &curve, &curvelen) || curvelen == 0) {
        ssh2_err(session, LIBSSH2_ERROR_PROTO, "ECDSA no curve");
        return -1;
    }

    if(ssh2_get_string(decrypted, &point_buf, &pointlen)) {
        ssh2_err(session, LIBSSH2_ERROR_PROTO, "ECDSA no point");
        return -1;
    }

    rc = ssh2_ecdsa_curve_name_with_octal_new(&ec_key, point_buf, pointlen,
                                              SSH2_EC_CURVE_NISTP256);
    if(rc) {
        rc = -1;
        ssh2_err(session, LIBSSH2_ERROR_PROTO, "ECDSA could not create key");
        goto fail;
    }

    if(ssh2_get_string(decrypted, &app, &app_len)) {
        ssh2_err(session, LIBSSH2_ERROR_PROTO, "No SK application.");
        goto fail;
    }

    if(flags && ssh2_get_byte(decrypted, flags)) {
        ssh2_err(session, LIBSSH2_ERROR_PROTO, "No SK flags.");
        goto fail;
    }

    if(key_handle && handle_len) {
        unsigned char *handle = NULL;
        if(ssh2_get_string(decrypted, &handle, handle_len)) {
            ssh2_err(session, LIBSSH2_ERROR_PROTO, "No SK key_handle.");
            goto fail;
        }

        if(*handle_len > 0) {
            *key_handle = SSH2_ALLOC(session, *handle_len);
            if(*key_handle)
                memcpy(SSH2_UNCONST(*key_handle), handle, *handle_len);
        }
    }

    if(rc == 0 && ec_key && pubkeydata && method) {
#ifdef USE_OPENSSL_3
        EVP_PKEY *pk = ec_key;
#else
        EVP_PKEY *pk = EVP_PKEY_new();
        EVP_PKEY_set1_EC_KEY(pk, ec_key);
#endif

        rc = ossl_ecdsa_evp_to_pubkey(session, method, method_len,
                                      pubkeydata, pubkeydata_len, 1, pk);

#ifndef USE_OPENSSL_3
        if(pk)
            EVP_PKEY_free(pk);
#endif
    }

    if(rc == 0 && pubkeydata) {
        key_len = *pubkeydata_len + app_len + 4;
        key = SSH2_ALLOC(session, key_len);

        if(!key) {
            rc = -1;
            goto fail;
        }

        p = key + *pubkeydata_len;

        memcpy(key, *pubkeydata, *pubkeydata_len);
        ssh2_store_str(&p, (const char *)app, app_len);

        if(application && app_len > 0) {
            *application = SSH2_ALLOC(session, app_len + 1);
            ssh2_explicit_zero(SSH2_UNCONST(*application), app_len + 1);
            memcpy(SSH2_UNCONST(*application), app, app_len);
        }

        SSH2_FREE(session, *pubkeydata);
        *pubkeydata_len = key_len;
        *pubkeydata = key;
    }

    if(ec_ctx)
        *ec_ctx = ec_key;
    else
        ssh2_ecdsa_free(ec_key);

    return rc;

fail:
    if(ec_key)
        ssh2_ecdsa_free(ec_key);

    if(application && *application) {
        SSH2_FREE(session, (void *)application);
        *application = NULL;
    }

    if(key_handle && *key_handle) {
        SSH2_FREE(session, (void *)key_handle);
        *key_handle = NULL;
    }

    return rc;
}

static int ossl_ecdsa_openssh_priv_new(ssh2_ecdsa_ctx **ec_ctx,
                                       LIBSSH2_SESSION *session,
                                       const char *filename,
                                       const unsigned char *passphrase)
{
    FILE *fp;
    int rc;
    unsigned char *buf = NULL;
    struct string_buf *decrypted = NULL;
    ssh2_curve_type type;

    if(!session) {
        ssh2_err(session, LIBSSH2_ERROR_PROTO, "Session is required");
        return -1;
    }

    ssh2_init_if_needed();

    fp = fopen(filename, "r");
    if(!fp) {
        ssh2_err(session, LIBSSH2_ERROR_FILE,
                 "Unable to open OpenSSH ECDSA private key file");
        return -1;
    }

    rc = ssh2_openssh_pem_parse(session, passphrase, fp, &decrypted);
    fclose(fp);
    if(rc)
        return rc;

    /* We have a new key file, now try and parse it using supported types  */
    rc = ssh2_get_string(decrypted, &buf, NULL);

    if(rc || !buf) {
        ssh2_err(session, LIBSSH2_ERROR_PROTO,
                 "Public key type in decrypted key data not found");
        return -1;
    }

    rc = ssh2_ecdsa_curve_type_from_name((const char *)buf, &type);

    if(rc == 0)
        rc = ossl_ecdsa_openssh_priv_to_pubkey(session, type, decrypted,
                                               NULL, NULL, NULL, NULL, ec_ctx);
    else
        rc = -1;

    if(decrypted)
        ssh2_string_buf_free(session, decrypted);

    return rc;
}

static int ossl_ecdsa_sk_openssh_priv_new(ssh2_ecdsa_ctx **ec_ctx,
                                          uint8_t *flags,
                                          const char **application,
                                          const unsigned char **key_handle,
                                          size_t *handle_len,
                                          LIBSSH2_SESSION *session,
                                          const char *filename,
                                          const unsigned char *passphrase)
{
    FILE *fp;
    int rc;
    unsigned char *buf = NULL;
    struct string_buf *decrypted = NULL;

    if(!session) {
        ssh2_err(session, LIBSSH2_ERROR_PROTO, "Session is required");
        return -1;
    }

    ssh2_init_if_needed();

    fp = fopen(filename, "r");
    if(!fp) {
        ssh2_err(session, LIBSSH2_ERROR_FILE,
                 "Unable to open OpenSSH ECDSA private key file");
        return -1;
    }

    rc = ssh2_openssh_pem_parse(session, passphrase, fp, &decrypted);
    fclose(fp);
    if(rc)
        return rc;

    /* We have a new key file, now try and parse it using supported types  */
    rc = ssh2_get_string(decrypted, &buf, NULL);

    if(rc || !buf) {
        ssh2_err(session, LIBSSH2_ERROR_PROTO,
                 "Public key type in decrypted key data not found");
        return -1;
    }

    if(strcmp("sk-ecdsa-sha2-nistp256@openssh.com", (const char *)buf) == 0)
        rc = ossl_ecdsa_sk_openssh_priv_to_pubkey(session, decrypted,
                                                  NULL, NULL, NULL, NULL,
                                                  flags, application,
                                                  key_handle, handle_len,
                                                  ec_ctx);
    else
        rc = -1;

    if(decrypted)
        ssh2_string_buf_free(session, decrypted);

    return rc;
}

int ssh2_ecdsa_new_private(ssh2_ecdsa_ctx **ec_ctx,
                           LIBSSH2_SESSION *session,
                           const char *filename,
                           const unsigned char *passphrase)
{
    int rc = 0;
    BIO *bp;

    ssh2_init_if_needed();

    bp = BIO_new_file(filename, "r");
    if(bp)
#ifdef USE_OPENSSL_3
        *ec_ctx = PEM_read_bio_PrivateKey(bp, NULL, ossl_passphrase_cb,
                                          SSH2_UNCONST(passphrase));
#else
        *ec_ctx = PEM_read_bio_ECPrivateKey(bp, NULL, ossl_passphrase_cb,
                                            SSH2_UNCONST(passphrase));
#endif
    BIO_free(bp);
    if(!*ec_ctx)
        rc = ossl_ecdsa_openssh_priv_new(ec_ctx, session, filename,
                                         passphrase);

    return rc;
}

int ssh2_ecdsa_new_private_sk(ssh2_ecdsa_ctx **ec_ctx,
                              unsigned char *flags,
                              const char **application,
                              const unsigned char **key_handle,
                              size_t *handle_len,
                              LIBSSH2_SESSION *session,
                              const char *filename,
                              const unsigned char *passphrase)
{
    int rc = 0;
    BIO *bp;

    ssh2_init_if_needed();

    bp = BIO_new_file(filename, "r");
    if(bp)
#ifdef USE_OPENSSL_3
        *ec_ctx = PEM_read_bio_PrivateKey(bp, NULL, ossl_passphrase_cb,
                                          SSH2_UNCONST(passphrase));
#else
        *ec_ctx = PEM_read_bio_ECPrivateKey(bp, NULL, ossl_passphrase_cb,
                                            SSH2_UNCONST(passphrase));
#endif
    BIO_free(bp);
    if(!*ec_ctx)
        rc = ossl_ecdsa_sk_openssh_priv_new(ec_ctx, flags, application,
                                            key_handle, handle_len, session,
                                            filename, passphrase);

    return rc;
}

/*
 * Creates a local private key based on input curve
 * and returns octal value and octal length
 */
int ssh2_ecdsa_create_key(LIBSSH2_SESSION *session,
                          ssh2_ec_key **out_private_key,
                          unsigned char **out_public_key_octal,
                          size_t *out_public_key_octal_len,
                          ssh2_curve_type curve_type)
{
    int ret = 1;
    size_t octal_len = 0;
    unsigned char octal_value[EC_MAX_POINT_LEN];
    ssh2_ec_key *private_key = NULL;

#ifdef USE_OPENSSL_3
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);

    if(ctx &&
       EVP_PKEY_keygen_init(ctx) > 0 &&
       EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, curve_type) > 0) {
        ret = EVP_PKEY_keygen(ctx, &private_key);
    }

    if(ret <= 0)
        goto clean_exit;

    if(out_private_key)
        *out_private_key = private_key;

    ret = EVP_PKEY_get_octet_string_param(private_key, OSSL_PKEY_PARAM_PUB_KEY,
                                          NULL, 0, &octal_len);

    if(ret <= 0)
        goto clean_exit;

    *out_public_key_octal = SSH2_ALLOC(session, octal_len);

    if(!*out_public_key_octal) {
        ret = -1;
        goto clean_exit;
    }

    ret = EVP_PKEY_get_octet_string_param(private_key, OSSL_PKEY_PARAM_PUB_KEY,
                                          octal_value, octal_len, &octal_len);

    if(ret <= 0)
        goto clean_exit;

    memcpy(*out_public_key_octal, octal_value, octal_len);

    if(out_public_key_octal_len)
        *out_public_key_octal_len = octal_len;
#else
    const EC_POINT *public_key = NULL;
    const EC_GROUP *group = NULL;

    /* create key */
    BN_CTX *bn_ctx = BN_CTX_new();
    if(!bn_ctx)
        return -1;

    private_key = EC_KEY_new_by_curve_name(curve_type);
    group = EC_KEY_get0_group(private_key);

    EC_KEY_generate_key(private_key);
    public_key = EC_KEY_get0_public_key(private_key);

    /* get length */
    octal_len = EC_POINT_point2oct(group, public_key,
                                   POINT_CONVERSION_UNCOMPRESSED,
                                   NULL, 0, bn_ctx);
    if(octal_len > EC_MAX_POINT_LEN) {
        ret = -1;
        goto clean_exit;
    }

    /* convert to octal */
    if(EC_POINT_point2oct(group, public_key, POINT_CONVERSION_UNCOMPRESSED,
                          octal_value, octal_len, bn_ctx) != octal_len) {
        ret = -1;
        goto clean_exit;
    }

    if(out_private_key)
        *out_private_key = private_key;

    if(out_public_key_octal) {
        *out_public_key_octal = SSH2_ALLOC(session, octal_len);
        if(!*out_public_key_octal) {
            ret = -1;
            goto clean_exit;
        }

        memcpy(*out_public_key_octal, octal_value, octal_len);
    }

    if(out_public_key_octal_len)
        *out_public_key_octal_len = octal_len;
#endif /* USE_OPENSSL_3 */

clean_exit:
#ifdef USE_OPENSSL_3
    if(ctx)
        EVP_PKEY_CTX_free(ctx);
#else
    if(bn_ctx)
        BN_CTX_free(bn_ctx);
#endif

    return (ret == 1) ? 0 : -1;
}

/*
 * Computes the shared secret K given a local private key,
 * remote public key and length
 */
int ssh2_ecdh_gen_k(ssh2_bn **k, ssh2_ec_key *private_key,
                    const unsigned char *server_public_key,
                    size_t server_public_key_len)
{
    int ret = 0;
    BN_CTX *bn_ctx = NULL;

#ifdef USE_OPENSSL_3
    char *group_name = NULL;
    size_t group_name_len = 0;
    unsigned char *out_shared_key = NULL;
    EVP_PKEY *peer_key = NULL, *server_key = NULL;
    EVP_PKEY_CTX *key_fromdata_ctx = NULL;
    EVP_PKEY_CTX *server_key_ctx = NULL;
    OSSL_PARAM params[3];

    size_t out_len = 0;

    if(!k || !*k || server_public_key_len <= 0)
        return -1;

    bn_ctx = BN_CTX_new();
    if(!bn_ctx)
        goto clean_exit;

    key_fromdata_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if(!key_fromdata_ctx)
        goto clean_exit;

    ret = EVP_PKEY_get_utf8_string_param(private_key,
                                         OSSL_PKEY_PARAM_GROUP_NAME,
                                         NULL, 0, &group_name_len);

    if(ret <= 0)
        goto clean_exit;

    group_name_len += 1;
    group_name = OPENSSL_zalloc(group_name_len);

    if(!group_name)
        goto clean_exit;

    ret = EVP_PKEY_get_utf8_string_param(private_key,
                                         OSSL_PKEY_PARAM_GROUP_NAME,
                                         group_name, group_name_len,
                                         &group_name_len);

    if(ret <= 0)
        goto clean_exit;

    out_shared_key = OPENSSL_malloc(server_public_key_len);

    if(!out_shared_key)
        goto clean_exit;

    memcpy(out_shared_key, server_public_key, server_public_key_len);

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                 group_name, 0);

    params[1] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                                  out_shared_key,
                                                  server_public_key_len);

    params[2] = OSSL_PARAM_construct_end();

    ret = EVP_PKEY_fromdata_init(key_fromdata_ctx);
    if(ret <= 0)
        goto clean_exit;

    ret = EVP_PKEY_fromdata(key_fromdata_ctx, &peer_key,
                            EVP_PKEY_PUBLIC_KEY, params);

    if(ret <= 0)
        goto clean_exit;

    server_key = private_key;

    if(!peer_key || !server_key)
        goto clean_exit;

    server_key_ctx = EVP_PKEY_CTX_new(server_key, NULL);
    if(!server_key_ctx)
        goto clean_exit;

    ret = EVP_PKEY_derive_init(server_key_ctx);
    if(ret <= 0)
        goto clean_exit;

    ret = EVP_PKEY_derive_set_peer(server_key_ctx, peer_key);
    if(ret <= 0)
        goto clean_exit;

    ret = EVP_PKEY_derive(server_key_ctx, NULL, &out_len);
    if(ret <= 0)
        goto clean_exit;

    ret = EVP_PKEY_derive(server_key_ctx, out_shared_key, &out_len);

    if(ret == 1)
        BN_bin2bn(out_shared_key, (int)out_len, *k);
    else
        ret = -1;
#else
    int rc = -1;
    size_t secret_len;
    unsigned char *secret = NULL;
    const EC_GROUP *private_key_group;
    EC_POINT *server_public_key_point;

    bn_ctx = BN_CTX_new();

    if(!bn_ctx)
        return -1;

    if(!k)
        return -1;

    private_key_group = EC_KEY_get0_group(private_key);

    server_public_key_point = EC_POINT_new(private_key_group);
    if(!server_public_key_point)
        return -1;

    rc = EC_POINT_oct2point(private_key_group, server_public_key_point,
                            server_public_key, server_public_key_len, bn_ctx);
    if(rc != 1) {
        ret = -1;
        goto clean_exit;
    }

    secret_len = (EC_GROUP_get_degree(private_key_group) + 7) / 8;
    secret = malloc(secret_len);
    if(!secret) {
        ret = -1;
        goto clean_exit;
    }

    secret_len = ECDH_compute_key(secret, secret_len, server_public_key_point,
                                  private_key, NULL);

    if(secret_len <= 0 || secret_len > EC_MAX_POINT_LEN) {
        ret = -1;
        goto clean_exit;
    }

    BN_bin2bn(secret, (int)secret_len, *k);
#endif

clean_exit:
#ifdef USE_OPENSSL_3
    if(group_name)
        OPENSSL_clear_free(group_name, group_name_len);

    if(out_shared_key)
        OPENSSL_clear_free(out_shared_key, server_public_key_len);

    if(server_key_ctx)
        EVP_PKEY_CTX_free(server_key_ctx);
#else
    if(server_public_key_point)
        EC_POINT_free(server_public_key_point);

    if(bn_ctx)
        BN_CTX_free(bn_ctx);

    if(secret)
        free(secret);
#endif

#ifdef USE_OPENSSL_3
    return ret == 1 ? 0 : -1;
#else
    return ret;
#endif
}

#endif /* LIBSSH2_ECDSA */

#if LIBSSH2_ED25519

int ssh2_ed25519_sign(ssh2_ed25519_ctx *ctx, LIBSSH2_SESSION *session,
                      uint8_t **out_sig, size_t *out_sig_len,
                      const uint8_t *message, size_t message_len)
{
    int rc = -1;
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    size_t sig_len = 0;
    unsigned char *sig = NULL;

    if(md_ctx) {
        if(EVP_DigestSignInit(md_ctx, NULL, NULL, NULL, ctx) != 1)
            goto clean_exit;
        if(EVP_DigestSign(md_ctx, NULL, &sig_len, message, message_len) != 1)
            goto clean_exit;

        if(sig_len != SSH2_ED25519_SIG_LEN)
            goto clean_exit;

        sig = SSH2_CALLOC(session, sig_len);
        if(!sig)
            goto clean_exit;

        rc = EVP_DigestSign(md_ctx, sig, &sig_len, message, message_len);
    }

    if(rc == 1) {
        *out_sig = sig;
        *out_sig_len = sig_len;
    }
    else {
        *out_sig_len = 0;
        *out_sig = NULL;
        SSH2_FREE(session, sig);
    }

clean_exit:

    if(md_ctx)
        EVP_MD_CTX_free(md_ctx);

    return (rc == 1) ? 0 : -1;
}

int ssh2_curve25519_gen_k(ssh2_bn **k,
                          uint8_t private_key[SSH2_ED25519_KEY_LEN],
                          uint8_t server_public_key[SSH2_ED25519_KEY_LEN])
{
    int rc = -1;
    unsigned char out_shared_key[SSH2_ED25519_KEY_LEN];
    EVP_PKEY *peer_key = NULL, *server_key = NULL;
    EVP_PKEY_CTX *server_key_ctx = NULL;
    BN_CTX *bn_ctx = NULL;
    size_t out_len = 0;

    if(!k || !*k)
        return -1;

    bn_ctx = BN_CTX_new();
    if(!bn_ctx)
        return -1;

    peer_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL,
                                           server_public_key,
                                           SSH2_ED25519_KEY_LEN);

    server_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL,
                                              private_key,
                                              SSH2_ED25519_KEY_LEN);

    if(!peer_key || !server_key)
        goto clean_exit;

    server_key_ctx = EVP_PKEY_CTX_new(server_key, NULL);
    if(!server_key_ctx)
        goto clean_exit;

    rc = EVP_PKEY_derive_init(server_key_ctx);
    if(rc <= 0)
        goto clean_exit;

    rc = EVP_PKEY_derive_set_peer(server_key_ctx, peer_key);
    if(rc <= 0)
        goto clean_exit;

    rc = EVP_PKEY_derive(server_key_ctx, NULL, &out_len);
    if(rc <= 0)
        goto clean_exit;

    if(out_len != SSH2_ED25519_KEY_LEN) {
        rc = -1;
        goto clean_exit;
    }

    rc = EVP_PKEY_derive(server_key_ctx, out_shared_key, &out_len);

    if(rc == 1 && out_len == SSH2_ED25519_KEY_LEN)
        BN_bin2bn(out_shared_key, SSH2_ED25519_KEY_LEN, *k);
    else
        rc = -1;

clean_exit:

    if(server_key_ctx)
        EVP_PKEY_CTX_free(server_key_ctx);
    if(peer_key)
        EVP_PKEY_free(peer_key);
    if(server_key)
        EVP_PKEY_free(server_key);
    if(bn_ctx)
        BN_CTX_free(bn_ctx);

    return (rc == 1) ? 0 : -1;
}

int ssh2_ed25519_verify(ssh2_ed25519_ctx *ctx, const uint8_t *s,
                        size_t s_len, const uint8_t *m, size_t m_len)
{
    int ret = -1;

    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if(!md_ctx)
        return -1;

    ret = EVP_DigestVerifyInit(md_ctx, NULL, NULL, NULL, ctx);
    if(ret != 1)
        goto clean_exit;

    ret = EVP_DigestVerify(md_ctx, s, s_len, m, m_len);

clean_exit:

    EVP_MD_CTX_free(md_ctx);

    return (ret == 1) ? 0 : -1;
}

#endif /* LIBSSH2_ED25519 */

static int ossl_key_from_openssh_file(LIBSSH2_SESSION *session,
                                      unsigned char **method,
                                      size_t *method_len,
                                      unsigned char **pubkeydata,
                                      size_t *pubkeydata_len,
                                      const char *privatekey,
                                      const char *passphrase)
{
    FILE *fp;
    unsigned char *buf = NULL;
    struct string_buf *decrypted = NULL;
    int rc = 0;
#if LIBSSH2_ECDSA
    ssh2_curve_type type;
#endif

    if(!session) {
        ssh2_err(session, LIBSSH2_ERROR_PROTO, "Session is required");
        return -1;
    }

    ssh2_init_if_needed();

    fp = fopen(privatekey, "r");
    if(!fp) {
        ssh2_err(session, LIBSSH2_ERROR_FILE,
                 "Unable to open private key file");
        return -1;
    }

    rc = ssh2_openssh_pem_parse(session, (const unsigned char *)passphrase,
                                fp, &decrypted);
    fclose(fp);
    if(rc) {
        ssh2_err(session, LIBSSH2_ERROR_FILE, "Not an OpenSSH key file");
        return rc;
    }

    /* We have a new key file, now try and parse it using supported types  */
    rc = ssh2_get_string(decrypted, &buf, NULL);

    if(rc || !buf) {
        ssh2_err(session, LIBSSH2_ERROR_PROTO,
                 "Public key type in decrypted key data not found");
        return -1;
    }

    rc = -1;

    /* Avoid unused variable warnings when all branches below are disabled */
    (void)method;
    (void)method_len;
    (void)pubkeydata;
    (void)pubkeydata_len;

#if LIBSSH2_ED25519
    if(strcmp("ssh-ed25519", (const char *)buf) == 0)
        rc = ossl_ed25519_openssh_priv_to_pubkey(session, decrypted,
                                                 method, method_len,
                                                 pubkeydata, pubkeydata_len,
                                                 NULL);
#endif
#if LIBSSH2_RSA
    if(strcmp("ssh-rsa", (const char *)buf) == 0)
        rc = ossl_rsa_openssh_priv_to_pubkey(session, decrypted,
                                             method, method_len,
                                             pubkeydata, pubkeydata_len,
                                             NULL);
#endif
#if LIBSSH2_DSA
    if(strcmp("ssh-dss", (const char *)buf) == 0)
        rc = ossl_dsa_openssh_priv_to_pubkey(session, decrypted,
                                             method, method_len,
                                             pubkeydata, pubkeydata_len,
                                             NULL);
#endif
#if LIBSSH2_ECDSA
    if(ssh2_ecdsa_curve_type_from_name((const char *)buf, &type) == 0)
        rc = ossl_ecdsa_openssh_priv_to_pubkey(session, type, decrypted,
                                               method, method_len,
                                               pubkeydata, pubkeydata_len,
                                               NULL);
#endif

    if(decrypted)
        ssh2_string_buf_free(session, decrypted);

    if(rc)
        ssh2_err(session, LIBSSH2_ERROR_FILE, "Unsupported OpenSSH key type");

    return rc;
}

int ssh2_pub_priv_keyfile(LIBSSH2_SESSION *session,
                          unsigned char **method,
                          size_t *method_len,
                          unsigned char **pubkeydata,
                          size_t *pubkeydata_len,
                          const char *privatekey,
                          const char *passphrase)
{
    int st;
    BIO *bp;
    EVP_PKEY *pk;
    int pktype;
    int rc;

    ssh2_deb((session, LIBSSH2_TRACE_AUTH,
              "Computing public key from private key file: %s", privatekey));

    bp = BIO_new_file(privatekey, "r");
    if(!bp)
        return ssh2_err(session, LIBSSH2_ERROR_FILE,
                        "Unable to extract public key from private key file: "
                        "Unable to open private key file");

    (void)BIO_reset(bp);
    pk = PEM_read_bio_PrivateKey(bp, NULL, NULL, SSH2_UNCONST(passphrase));
    BIO_free(bp);

    if(!pk) {
        /* Try OpenSSH format */
        rc = ossl_key_from_openssh_file(session,
                                        method, method_len,
                                        pubkeydata, pubkeydata_len,
                                        privatekey, passphrase);
        if(rc)
            return ssh2_err(session, LIBSSH2_ERROR_FILE,
                            "Unable to extract public key "
                            "from private key file: "
                            "Wrong passphrase or invalid/unrecognized "
                            "private key file format");
        return 0;
    }

#ifdef HAVE_OPAQUE_STRUCTS
    pktype = EVP_PKEY_id(pk);
#else
    pktype = pk->type;
#endif

    switch(pktype) {
#if LIBSSH2_ED25519
    case EVP_PKEY_ED25519:
        st = ossl_ed25519_evp_to_pubkey(session, method, method_len,
                                        pubkeydata, pubkeydata_len, pk);
        break;
#endif /* LIBSSH2_ED25519 */
#if LIBSSH2_RSA
    case EVP_PKEY_RSA:
        st = ossl_rsa_evp_to_pubkey(session, method, method_len,
                                    pubkeydata, pubkeydata_len, pk);
        break;
#endif /* LIBSSH2_RSA */
#if LIBSSH2_DSA
    case EVP_PKEY_DSA:
        st = ossl_dsa_evp_to_pubkey(session, method, method_len,
                                    pubkeydata, pubkeydata_len, pk);
        break;
#endif /* LIBSSH2_DSA */
#if LIBSSH2_ECDSA
    case EVP_PKEY_EC:
        st = ossl_ecdsa_evp_to_pubkey(session, method, method_len,
                                      pubkeydata, pubkeydata_len, 0, pk);
        break;
#endif /* LIBSSH2_ECDSA */
    default:
        st = ssh2_err(session, LIBSSH2_ERROR_FILE,
                      "Unable to extract public key from private key file: "
                      "Unsupported private key file format");
        break;
    }

    EVP_PKEY_free(pk);
    return st;
}

static int ossl_key_from_openssh_blob(LIBSSH2_SESSION *session,
                                      void **key_ctx,
                                      const char *key_type,
                                      unsigned char **method,
                                      size_t *method_len,
                                      unsigned char **pubkeydata,
                                      size_t *pubkeydata_len,
                                      const char *privatekeydata,
                                      size_t privatekeydata_len,
                                      const unsigned char *passphrase)
{
    int rc;
    unsigned char *buf = NULL;
    struct string_buf *decrypted = NULL;
#if LIBSSH2_ECDSA
    ssh2_curve_type type;
#endif

    if(key_ctx)
        *key_ctx = NULL;

    if(!session)
        return ssh2_err(session, LIBSSH2_ERROR_PROTO, "Session is required");

    if(key_type && (strlen(key_type) > 11 || strlen(key_type) < 7))
        return ssh2_err(session, LIBSSH2_ERROR_PROTO, "type is invalid");

    ssh2_init_if_needed();

    rc = ssh2_openssh_pem_parse_memory(session, passphrase,
                                       privatekeydata,
                                       privatekeydata_len, &decrypted);

    if(rc)
        return rc;

    /* We have a new key file, now try and parse it using supported types  */
    rc = ssh2_get_string(decrypted, &buf, NULL);

    if(rc || !buf)
        return ssh2_err(session, LIBSSH2_ERROR_PROTO,
                        "Public key type in decrypted key data not found");

    rc = LIBSSH2_ERROR_FILE;

    /* Avoid unused variable warnings when all branches below are disabled */
    (void)method;
    (void)method_len;
    (void)pubkeydata;
    (void)pubkeydata_len;

#if LIBSSH2_ED25519
    if(strcmp("ssh-ed25519", (const char *)buf) == 0) {
        if(!key_type || strcmp("ssh-ed25519", key_type) == 0)
            rc = ossl_ed25519_openssh_priv_to_pubkey(session, decrypted,
                                                     method, method_len,
                                                     pubkeydata,
                                                     pubkeydata_len,
                                                 (ssh2_ed25519_ctx **)key_ctx);
    }

    if(strcmp("sk-ssh-ed25519@openssh.com", (const char *)buf) == 0) {
        if(!key_type || strcmp("sk-ssh-ed25519@openssh.com", key_type) == 0)
            rc = ossl_ed25519_openssh_sk_priv_to_pubkey(session, decrypted,
                                                        method, method_len,
                                                        pubkeydata,
                                                        pubkeydata_len,
                                                        NULL, NULL, NULL, NULL,
                                                 (ssh2_ed25519_ctx **)key_ctx);
    }
#endif
#if LIBSSH2_RSA
    if(strcmp("ssh-rsa", (const char *)buf) == 0) {
        if(!key_type || strcmp("ssh-rsa", key_type) == 0)
            rc = ossl_rsa_openssh_priv_to_pubkey(session, decrypted,
                                                 method, method_len,
                                                 pubkeydata, pubkeydata_len,
                                                 (ssh2_rsa_ctx **)key_ctx);
    }
#endif
#if LIBSSH2_DSA
    if(strcmp("ssh-dss", (const char *)buf) == 0) {
        if(!key_type || strcmp("ssh-dss", key_type) == 0)
            rc = ossl_dsa_openssh_priv_to_pubkey(session, decrypted,
                                                 method, method_len,
                                                 pubkeydata, pubkeydata_len,
                                                 (ssh2_dsa_ctx **)key_ctx);
    }
#endif
#if LIBSSH2_ECDSA
    if(strcmp("sk-ecdsa-sha2-nistp256@openssh.com", (const char *)buf) == 0)
        rc = ossl_ecdsa_sk_openssh_priv_to_pubkey(session, decrypted,
                                                  method, method_len,
                                                  pubkeydata, pubkeydata_len,
                                                  NULL, NULL, NULL, NULL,
                                                  (ssh2_ecdsa_ctx **)key_ctx);
    else if(ssh2_ecdsa_curve_type_from_name((const char *)buf, &type) == 0) {
        if(!key_type || strcmp("ssh-ecdsa", key_type) == 0)
            rc = ossl_ecdsa_openssh_priv_to_pubkey(session, type, decrypted,
                                                   method, method_len,
                                                   pubkeydata, pubkeydata_len,
                                                   (ssh2_ecdsa_ctx **)key_ctx);
    }
#endif

    if(rc == LIBSSH2_ERROR_FILE)
        rc = ssh2_err(session, LIBSSH2_ERROR_FILE,
                      "Unable to extract public key from private key file: "
                      "invalid/unrecognized private key file format");

    if(decrypted)
        ssh2_string_buf_free(session, decrypted);

    return rc;
}

static int ossl_key_sk_from_openssh_blob(LIBSSH2_SESSION *session,
                                         void **key_ctx,
                                         const char *key_type,
                                         unsigned char **method,
                                         size_t *method_len,
                                         unsigned char **pubkeydata,
                                         size_t *pubkeydata_len,
                                         int *algorithm,
                                         unsigned char *flags,
                                         const char **application,
                                         const unsigned char **key_handle,
                                         size_t *handle_len,
                                         const char *privatekeydata,
                                         size_t privatekeydata_len,
                                         const unsigned char *passphrase)
{
    int rc;
    unsigned char *buf = NULL;
    struct string_buf *decrypted = NULL;

    if(key_ctx)
        *key_ctx = NULL;

    if(!session)
        return ssh2_err(session, LIBSSH2_ERROR_PROTO, "Session is required");

    if(key_type && strlen(key_type) < 7)
        return ssh2_err(session, LIBSSH2_ERROR_PROTO, "type is invalid");

    ssh2_init_if_needed();

    rc = ssh2_openssh_pem_parse_memory(session, passphrase,
                                       privatekeydata,
                                       privatekeydata_len, &decrypted);

    if(rc)
        return rc;

    /* We have a new key file, now try and parse it using supported types  */
    rc = ssh2_get_string(decrypted, &buf, NULL);

    if(rc || !buf)
        return ssh2_err(session, LIBSSH2_ERROR_PROTO,
                        "Public key type in decrypted key data not found");

    rc = LIBSSH2_ERROR_FILE;

    /* Avoid unused variable warnings when all branches below are disabled */
    (void)method;
    (void)method_len;
    (void)pubkeydata;
    (void)pubkeydata_len;
    (void)algorithm;
    (void)flags;
    (void)application;
    (void)key_handle;
    (void)handle_len;

#if LIBSSH2_ED25519
    if(strcmp("sk-ssh-ed25519@openssh.com", (const char *)buf) == 0) {
        *algorithm = LIBSSH2_HOSTKEY_TYPE_ED25519;
        if(!key_type || strcmp("sk-ssh-ed25519@openssh.com", key_type) == 0)
            rc = ossl_ed25519_openssh_sk_priv_to_pubkey(session, decrypted,
                                                        method, method_len,
                                                        pubkeydata,
                                                        pubkeydata_len,
                                                        flags, application,
                                                        key_handle, handle_len,
                                                 (ssh2_ed25519_ctx **)key_ctx);
    }
#endif
#if LIBSSH2_ECDSA
    if(strcmp("sk-ecdsa-sha2-nistp256@openssh.com", (const char *)buf) == 0) {
        *algorithm = LIBSSH2_HOSTKEY_TYPE_ECDSA_256;
        rc = ossl_ecdsa_sk_openssh_priv_to_pubkey(session, decrypted,
                                                  method, method_len,
                                                  pubkeydata, pubkeydata_len,
                                                  flags, application,
                                                  key_handle, handle_len,
                                                  (ssh2_ecdsa_ctx **)key_ctx);
    }
#endif

    if(rc == LIBSSH2_ERROR_FILE)
        rc = ssh2_err(session, LIBSSH2_ERROR_FILE,
                      "Unable to extract public key from private key "
                      "file: invalid/unrecognized private key file format");

    if(decrypted)
        ssh2_string_buf_free(session, decrypted);

    return rc;
}

#ifdef USE_OPENSSL_3
#define HAVE_SSLERROR_BAD_DECRYPT
#endif

int ssh2_pub_priv_keyfilememory(LIBSSH2_SESSION *session,
                                unsigned char **method, size_t *method_len,
                                unsigned char **pubkeydata,
                                size_t *pubkeydata_len,
                                const char *privatekeydata,
                                size_t privatekeydata_len,
                                const char *passphrase)
{
    int st;
    BIO *bp;
    EVP_PKEY *pk;
    int pktype;
#ifdef HAVE_SSLERROR_BAD_DECRYPT
    unsigned long sslError;
#endif

    ssh2_deb((session, LIBSSH2_TRACE_AUTH,
              "Computing public key from private key."));

    bp = BIO_new_mem_buf(privatekeydata, (int)privatekeydata_len);
    if(!bp)
        return ssh2_err(session, LIBSSH2_ERROR_ALLOC,
                        "Unable to allocate memory when computing public key");
    (void)BIO_reset(bp);
    pk = PEM_read_bio_PrivateKey(bp, NULL, NULL, SSH2_UNCONST(passphrase));
#ifdef HAVE_SSLERROR_BAD_DECRYPT
    sslError = ERR_get_error();
#endif
    BIO_free(bp);

    if(!pk) {
        /* Try OpenSSH format */
        st = ossl_key_from_openssh_blob(session, NULL, NULL,
                                        method, method_len,
                                        pubkeydata, pubkeydata_len,
                                        privatekeydata, privatekeydata_len,
                                        (const unsigned char *)passphrase);
        if(st == 0)
            return 0;

#ifdef HAVE_SSLERROR_BAD_DECRYPT
        if((ERR_GET_LIB(sslError) == ERR_LIB_PEM &&
            ERR_GET_REASON(sslError) == PEM_R_BAD_DECRYPT) ||
           (ERR_GET_LIB(sslError) == ERR_LIB_PROV &&
            ERR_GET_REASON(sslError) == EVP_R_BAD_DECRYPT))
            return ssh2_err(session, LIBSSH2_ERROR_KEYFILE_AUTH_FAILED,
                            "Wrong passphrase for private key");
#endif
        return ssh2_err(session, LIBSSH2_ERROR_FILE,
                        "Unable to extract public key from private key file: "
                        "Unsupported private key file format");
    }

#ifdef HAVE_OPAQUE_STRUCTS
    pktype = EVP_PKEY_id(pk);
#else
    pktype = pk->type;
#endif

    switch(pktype) {
#if LIBSSH2_ED25519
    case EVP_PKEY_ED25519:
        st = ossl_ed25519_evp_to_pubkey(session, method, method_len,
                                        pubkeydata, pubkeydata_len, pk);
        break;
#endif /* LIBSSH2_ED25519 */
#if LIBSSH2_RSA
    case EVP_PKEY_RSA:
        st = ossl_rsa_evp_to_pubkey(session, method, method_len,
                                    pubkeydata, pubkeydata_len, pk);
        break;
#endif /* LIBSSH2_RSA */
#if LIBSSH2_DSA
    case EVP_PKEY_DSA:
        st = ossl_dsa_evp_to_pubkey(session, method, method_len,
                                    pubkeydata, pubkeydata_len, pk);
        break;
#endif /* LIBSSH2_DSA */
#if LIBSSH2_ECDSA
    case EVP_PKEY_EC:
        st = ossl_ecdsa_evp_to_pubkey(session, method, method_len,
                                      pubkeydata, pubkeydata_len, 0, pk);
        break;
#endif /* LIBSSH2_ECDSA */
    default:
        st = ssh2_err(session, LIBSSH2_ERROR_FILE,
                      "Unable to extract public key from private key file: "
                      "Unsupported private key file format");
        break;
    }

    EVP_PKEY_free(pk);
    return st;
}

int ssh2_sk_pub_keyfilememory(LIBSSH2_SESSION *session,
                              unsigned char **method,
                              size_t *method_len,
                              unsigned char **pubkeydata,
                              size_t *pubkeydata_len,
                              int *algorithm,
                              unsigned char *flags,
                              const char **application,
                              const unsigned char **key_handle,
                              size_t *handle_len,
                              const char *privatekeydata,
                              size_t privatekeydata_len,
                              const char *passphrase)
{
    int st = -1;
    BIO *bp;
    EVP_PKEY *pk;

    ssh2_deb((session, LIBSSH2_TRACE_AUTH,
              "Computing public key from private key."));

    bp = BIO_new_mem_buf(privatekeydata, (int)privatekeydata_len);
    if(!bp)
        return ssh2_err(session, LIBSSH2_ERROR_ALLOC,
                        "Unable to allocate memory when computing public key");
    (void)BIO_reset(bp);
    pk = PEM_read_bio_PrivateKey(bp, NULL, NULL, SSH2_UNCONST(passphrase));
    BIO_free(bp);

    if(!pk)
        /* Try OpenSSH format */
        st = ossl_key_sk_from_openssh_blob(session, NULL, NULL,
                                           method, method_len,
                                           pubkeydata, pubkeydata_len,
                                           algorithm, flags, application,
                                           key_handle, handle_len,
                                           privatekeydata, privatekeydata_len,
                                           (const unsigned char *)passphrase);

    return st;
}

void ssh2_dh_init(ssh2_dh_ctx *dhctx)
{
    *dhctx = BN_new(); /* Random from client */
}

int ssh2_ossl_dh_key_pair(ssh2_dh_ctx *dhctx, ssh2_bn *pub, ssh2_bn *g,
                          ssh2_bn *p, int group_order, ssh2_bn_ctx *bnctx)
{
    /* Generate x and e */
    BN_rand(*dhctx, group_order * 8 - 1, 0, -1);
    BN_mod_exp(pub, g, *dhctx, p, bnctx);
    return 0;
}

int ssh2_ossl_dh_secret(ssh2_dh_ctx *dhctx, ssh2_bn *secret, ssh2_bn *f,
                        ssh2_bn *p, ssh2_bn_ctx *bnctx)
{
    /* Compute the shared secret */
    BN_mod_exp(secret, f, *dhctx, p, bnctx);
    return 0;
}

void ssh2_dh_dtor(ssh2_dh_ctx *dhctx)
{
    BN_clear_free(*dhctx);
    *dhctx = NULL;
}

int ssh2_bn_from_bin(ssh2_bn *bn, size_t len, const unsigned char *val)
{
    if(!BN_bin2bn(val, (int)len, bn))
        return -1;

    return 0;
}

/*
 * Return supported key hash algo upgrades, see crypto.h
 */
const char *ssh2_supported_key_sign_algs(LIBSSH2_SESSION *session,
                                         unsigned char *key_method,
                                         size_t key_method_len)
{
    (void)session;

#if LIBSSH2_RSA_SHA2
    if((key_method_len == 7 &&
        memcmp(key_method, "ssh-rsa", key_method_len) == 0) ||
       (key_method_len == 28 &&
        memcmp(key_method, "ssh-rsa-cert-v01@openssh.com",
               key_method_len) == 0)
       ) {
        return "rsa-sha2-512,rsa-sha2-256"
#if LIBSSH2_RSA_SHA1
            ",ssh-rsa"
#endif
            ;
    }
#endif

    return NULL;
}

#endif /* LIBSSH2_OPENSSL || LIBSSH2_WOLFSSL */
