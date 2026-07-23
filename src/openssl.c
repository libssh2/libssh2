/* Copyright (C) Simon Josefsson
 * Copyright (C) The Written Word, Inc.
 * Copyright (C) Sara Golemon <sarag@libssh2.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "libssh2_priv.h"

#if defined(LIBSSH2_OPENSSL) || defined(LIBSSH2_WOLFSSL)

#include <stdlib.h>
#include <assert.h>

void ssh2_crypto_init(void)
{
#if defined(LIBSSH2_WOLFSSL) && defined(DEBUG_WOLFSSL)
#define OSSL_INIT_IF_NEEDED() ssh2_init_if_needed()
    wolfSSL_Debugging_ON();
#else
#define OSSL_INIT_IF_NEEDED() do {} while(0)
#endif
}

int ssh2_hash_init(ssh2_hash_ctx *ctx, ssh2_hash_alg alg)
{
#if !defined(USE_OPENSSL_3) && \
    !defined(LIBRESSL_VERSION_NUMBER) && \
    !defined(LIBSSH2_WOLFSSL) && \
    (LIBSSH2_MD5 || LIBSSH2_MD5_PEM)
    /* OpenSSL 1.1.1
     * MD5 digest is not supported in OpenSSL FIPS mode
     * Trying to init it results in a latent OpenSSL error:
     * "digital envelope routines:FIPS_DIGESTINIT:disabled for fips"
     * Thus, return 0 in FIPS mode
     */
    if(alg == SSH2_MD5_ALG && FIPS_mode()) {
        *ctx = NULL;
        return 0;
    }
#endif

    *ctx = EVP_MD_CTX_new();
    if(!*ctx)
        return 0;

    if(EVP_DigestInit_ex(*ctx, alg, NULL))
        return 1;

    EVP_MD_CTX_free(*ctx);
    *ctx = NULL;

    return 0;
}

int ssh2_hash_final(ssh2_hash_ctx *ctx, void *digest, size_t digest_len)
{
    int ret = EVP_DigestFinal_ex(*ctx, digest, NULL);
    (void)digest_len;
    EVP_MD_CTX_free(*ctx);
    *ctx = NULL;
    return ret;
}

int ssh2_hmac_ctx_init(ssh2_hmac_ctx *ctx)
{
#ifdef USE_OPENSSL_3
    *ctx = NULL;
    return 1;
#else
    *ctx = HMAC_CTX_new();
    return *ctx ? 1 : 0;
#endif
}

int ssh2_hmac_init(ssh2_hmac_ctx *ctx, ssh2_hmac_alg alg,
                   void *key, size_t key_len)
{
#ifdef USE_OPENSSL_3
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
        OSSL_MAC_PARAM_KEY, key, key_len);
    params[1] = OSSL_PARAM_construct_utf8_string(
        OSSL_MAC_PARAM_DIGEST, (char *)SSH2_UNCONST(alg), 0);
    params[2] = OSSL_PARAM_construct_end();

    return EVP_MAC_init(*ctx, NULL, 0, params);
#else
    return HMAC_Init_ex(*ctx, key, (int)key_len, alg, NULL);
#endif
}

int ssh2_hmac_final(ssh2_hmac_ctx *ctx, void *mac, size_t mac_len)
{
#ifdef USE_OPENSSL_3
    return EVP_MAC_final(*ctx, mac, NULL, mac_len);
#else
    (void)mac_len;
    return HMAC_Final(*ctx, mac, NULL);
#endif
}

void ssh2_hmac_cleanup(ssh2_hmac_ctx *ctx)
{
#ifdef USE_OPENSSL_3
    EVP_MAC_CTX_free(*ctx);
#else
    HMAC_CTX_free(*ctx);
#endif
}

static int ossl_key_from_openssh(LIBSSH2_SESSION *session,
                                 void **key_ctx,
                                 const char *want_method,
                                 char **method,
                                 unsigned char **pubkeydata,
                                 size_t *pubkeydata_len,
                                 const char *privkeyfile,
                                 const char *privkeyblob,
                                 size_t privkeyblob_len,
                                 const char *passphrase);

#if LIBSSH2_RSA || LIBSSH2_DSA || LIBSSH2_ECDSA
static unsigned char *ossl_write_bn(unsigned char *buf,
                                    const BIGNUM *bn, int bn_bytes)
{
    unsigned char *p = buf;

    p += 4;  /* Left space for bn size which is written below. */

    *p = 0;
    BN_bn2bin(bn, p + 1);

    if(!(p[1] & 0x80))
        memmove(p, p + 1, --bn_bytes);

    ssh2_htonu32(p - 4, bn_bytes);  /* Post write bn size. */

    return p + bn_bytes;
}
#endif

#ifdef USE_OPENSSL_3
static SSH2_INLINE void ossl_swap_bytes(unsigned char *buf, size_t len)
{
#if !defined(WORDS_BIGENDIAN) || !WORDS_BIGENDIAN
    size_t i, j;
    for(i = 0, j = len - 1; i < j; i++, j--) {
        unsigned char temp = buf[i];
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
                 const unsigned char *edata, size_t elen,
                 const unsigned char *ndata, size_t nlen,
                 const unsigned char *ddata, size_t dlen,
                 const unsigned char *pdata, size_t plen,
                 const unsigned char *qdata, size_t qlen,
                 const unsigned char *e1data, size_t e1len,
                 const unsigned char *e2data, size_t e2len,
                 const unsigned char *coeffdata, size_t coefflen)
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

    if(ctx && EVP_PKEY_fromdata_init(ctx) > 0)
        ret = EVP_PKEY_fromdata(ctx, rsa, EVP_PKEY_KEYPAIR, params);

    if(nbuf)
        OPENSSL_clear_free(nbuf, nlen);
    if(ebuf)
        OPENSSL_clear_free(ebuf, elen);
    if(dbuf)
        OPENSSL_clear_free(dbuf, dlen);

    EVP_PKEY_CTX_free(ctx);

    return ret == 1 ? 0 : -1;
#else /* !USE_OPENSSL_3 */
    BIGNUM *e = NULL;
    BIGNUM *n = NULL;
    BIGNUM *d = NULL;
    BIGNUM *p = NULL;
    BIGNUM *q = NULL;
    BIGNUM *dmp1 = NULL;
    BIGNUM *dmq1 = NULL;
    BIGNUM *iqmp = NULL;

    e = BN_new();
    if(!e)
        goto fail;
    BN_bin2bn(edata, (int)elen, e);

    n = BN_new();
    if(!n)
        goto fail;
    BN_bin2bn(ndata, (int)nlen, n);

    if(ddata) {
        d = BN_new();
        if(!d)
            goto fail;
        BN_bin2bn(ddata, (int)dlen, d);

        p = BN_new();
        if(!p)
            goto fail;
        BN_bin2bn(pdata, (int)plen, p);

        q = BN_new();
        if(!q)
            goto fail;
        BN_bin2bn(qdata, (int)qlen, q);

        dmp1 = BN_new();
        if(!dmp1)
            goto fail;
        BN_bin2bn(e1data, (int)e1len, dmp1);

        dmq1 = BN_new();
        if(!dmq1)
            goto fail;
        BN_bin2bn(e2data, (int)e2len, dmq1);

        iqmp = BN_new();
        if(!iqmp)
            goto fail;
        BN_bin2bn(coeffdata, (int)coefflen, iqmp);
    }

    *rsa = RSA_new();
    if(!*rsa)
        goto fail;

    RSA_set0_key(*rsa, n, e, d);
    RSA_set0_factors(*rsa, p, q);
    RSA_set0_crt_params(*rsa, dmp1, dmq1, iqmp);

    return 0;

fail:

    BN_clear_free(e);
    BN_clear_free(n);
    BN_clear_free(d);
    BN_clear_free(p);
    BN_clear_free(q);
    BN_clear_free(dmp1);
    BN_clear_free(dmq1);
    BN_clear_free(iqmp);

    return -1;
#endif /* USE_OPENSSL_3 */
}

int ssh2_rsa_sha2_verify(ssh2_rsa_ctx *rsa, size_t hash_len,
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

    if(hash_len == SSH2_SHA1_DIG_LEN) {
        nid_type = NID_sha1;
        ret = ssh2_hash(SSH2_SHA1_ALG, m, m_len, hash, hash_len);
    }
    else if(hash_len == SSH2_SHA256_DIG_LEN) {
        nid_type = NID_sha256;
        ret = ssh2_hash(SSH2_SHA256_ALG, m, m_len, hash, hash_len);
    }
    else if(hash_len == SSH2_SHA512_DIG_LEN) {
        nid_type = NID_sha512;
        ret = ssh2_hash(SSH2_SHA512_ALG, m, m_len, hash, hash_len);
    }
    else {
        nid_type = 0;
        ret = 0; /* unsupported digest */
    }

    if(!ret) {
        free(hash);
        return -1; /* failure */
    }

#ifdef USE_OPENSSL_3
    ret = 0;

    ctx = EVP_PKEY_CTX_new(rsa, NULL);

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
    ret = RSA_verify(nid_type,
                     hash, (unsigned int)hash_len,
                     (const unsigned char *)sig, (unsigned int)sig_len,
                     rsa);
#endif

    free(hash);

    return ret == 1 ? 0 : -1;
}

#if LIBSSH2_RSA_SHA1
int ssh2_rsa_sha1_verify(ssh2_rsa_ctx *rsa,
                         const unsigned char *sig, size_t sig_len,
                         const unsigned char *m, size_t m_len)
{
    return ssh2_rsa_sha2_verify(rsa, SSH2_SHA1_DIG_LEN, sig, sig_len, m,
                                m_len);
}
#endif
#endif /* LIBSSH2_RSA */

#if LIBSSH2_DSA
int ssh2_dsa_new(ssh2_dsa_ctx **dsa,
                 const unsigned char *pdata, size_t plen,
                 const unsigned char *qdata, size_t qlen,
                 const unsigned char *gdata, size_t glen,
                 const unsigned char *ydata, size_t ylen,
                 const unsigned char *xdata, size_t xlen)
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

    if(pdata && plen > 0) {
        p_buf = OPENSSL_malloc(plen);
        if(p_buf) {
            memcpy(p_buf, pdata, plen);
            ossl_swap_bytes(p_buf, plen);
            params[param_num++] =
                OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_FFC_P, p_buf, plen);
        }
    }

    if(qdata && qlen > 0) {
        q_buf = OPENSSL_malloc(qlen);
        if(q_buf) {
            memcpy(q_buf, qdata, qlen);
            ossl_swap_bytes(q_buf, qlen);
            params[param_num++] =
                OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_FFC_Q, q_buf, qlen);
        }
    }

    if(gdata && glen > 0) {
        g_buf = OPENSSL_malloc(glen);
        if(g_buf) {
            memcpy(g_buf, gdata, glen);
            ossl_swap_bytes(g_buf, glen);
            params[param_num++] =
                OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_FFC_G, g_buf, glen);
        }
    }

    if(ydata && ylen > 0) {
        y_buf = OPENSSL_malloc(ylen);
        if(y_buf) {
            memcpy(y_buf, ydata, ylen);
            ossl_swap_bytes(y_buf, ylen);
            params[param_num++] =
                OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_PUB_KEY, y_buf, ylen);
        }
    }

    if(xdata && xlen > 0) {
        x_buf = OPENSSL_malloc(xlen);
        if(x_buf) {
            memcpy(x_buf, xdata, xlen);
            ossl_swap_bytes(x_buf, xlen);
            params[param_num++] =
                OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_PRIV_KEY, x_buf, xlen);
        }
    }

    params[param_num] = OSSL_PARAM_construct_end();

    *dsa = NULL;
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DSA, NULL);

    if(ctx && EVP_PKEY_fromdata_init(ctx) > 0)
        ret = EVP_PKEY_fromdata(ctx, dsa, EVP_PKEY_KEYPAIR, params);

    if(p_buf)
        OPENSSL_clear_free(p_buf, plen);
    if(q_buf)
        OPENSSL_clear_free(q_buf, qlen);
    if(g_buf)
        OPENSSL_clear_free(g_buf, glen);
    if(x_buf)
        OPENSSL_clear_free(x_buf, xlen);
    if(y_buf)
        OPENSSL_clear_free(y_buf, ylen);

    EVP_PKEY_CTX_free(ctx);

    return ret == 1 ? 0 : -1;
#else /* !USE_OPENSSL_3 */
    BIGNUM *p_bn = NULL;
    BIGNUM *q_bn = NULL;
    BIGNUM *g_bn = NULL;
    BIGNUM *pub_key = NULL;
    BIGNUM *priv_key = NULL;

    p_bn = BN_new();
    if(!p_bn)
        goto fail;
    BN_bin2bn(pdata, (int)plen, p_bn);

    q_bn = BN_new();
    if(!q_bn)
        goto fail;
    BN_bin2bn(qdata, (int)qlen, q_bn);

    g_bn = BN_new();
    if(!g_bn)
        goto fail;
    BN_bin2bn(gdata, (int)glen, g_bn);

    pub_key = BN_new();
    if(!pub_key)
        goto fail;
    BN_bin2bn(ydata, (int)ylen, pub_key);

    if(xlen) {
        priv_key = BN_new();
        if(!priv_key)
            goto fail;
        BN_bin2bn(xdata, (int)xlen, priv_key);
    }

    *dsa = DSA_new();
    if(!*dsa)
        goto fail;

    DSA_set0_pqg(*dsa, p_bn, q_bn, g_bn);
    DSA_set0_key(*dsa, pub_key, priv_key);

    return 0;

fail:

    BN_clear_free(p_bn);
    BN_clear_free(q_bn);
    BN_clear_free(g_bn);
    BN_free(pub_key);
    BN_clear_free(priv_key);

    return -1;
#endif /* USE_OPENSSL_3 */
}

int ssh2_dsa_sha1_verify(ssh2_dsa_ctx *dsa,
                         const unsigned char *sig,
                         const unsigned char *m, size_t m_len)
{
#ifdef USE_OPENSSL_3
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char *der = NULL;
    int der_len = 0;
#endif

    int ret = -1;
    unsigned char hash[SSH2_SHA1_DIG_LEN];
    DSA_SIG *dsasig;
    BIGNUM *r;
    BIGNUM *s;

    r = BN_new();
    if(!r)
        return -1;

    s = BN_new();
    if(!s) {
        BN_free(r);
        return -1;
    }

    dsasig = DSA_SIG_new();
    if(!dsasig) {
        BN_free(r);
        BN_free(s);
        return -1;
    }

    BN_bin2bn(sig, 20, r);
    BN_bin2bn(sig + 20, 20, s);

    DSA_SIG_set0(dsasig, r, s);

#ifdef USE_OPENSSL_3
    ctx = EVP_PKEY_CTX_new(dsa, NULL);
    der_len = i2d_DSA_SIG(dsasig, &der);

    if(ctx && ssh2_hash(SSH2_SHA1_ALG, m, m_len, hash, sizeof(hash)))
        if(EVP_PKEY_verify_init(ctx) > 0)
            ret = EVP_PKEY_verify(ctx, der, der_len, hash, SSH2_SHA1_DIG_LEN);

    if(ctx)
        EVP_PKEY_CTX_free(ctx);

    if(der)
        OPENSSL_clear_free(der, der_len);
#else
    if(ssh2_hash(SSH2_SHA1_ALG, m, m_len, hash, sizeof(hash)))
        ret = DSA_do_verify(hash, SSH2_SHA1_DIG_LEN, dsasig, dsa);
#endif

    DSA_SIG_free(dsasig);

    return ret == 1 ? 0 : -1;
}
#endif /* LIBSSH2_DSA */

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
#else
    const EC_GROUP *group = EC_KEY_get0_group(ec_ctx);
    int curve = EC_GROUP_get_curve_name(group);

    if(curve == NID_X9_62_prime256v1)
        return SSH2_EC_CURVE_NISTP256;
    else if(curve == NID_secp384r1)
        return SSH2_EC_CURVE_NISTP384;
    else if(curve == NID_secp521r1)
        return SSH2_EC_CURVE_NISTP521;
#endif
    return SSH2_EC_CURVE_NISTP256;
}

/*
 * returns 0 for success, key curve type that maps to ssh2_curve_type
 */
static int ossl_ecdsa_curve_type_from_name(const char *name,
                                           ssh2_curve_type *out_curve)
{
    ssh2_curve_type type;

    if(!name || strlen(name) != 19)
        return -1;

    if(!strcmp(name, "ecdsa-sha2-nistp256"))
        type = SSH2_EC_CURVE_NISTP256;
    else if(!strcmp(name, "ecdsa-sha2-nistp384"))
        type = SSH2_EC_CURVE_NISTP384;
    else if(!strcmp(name, "ecdsa-sha2-nistp521"))
        type = SSH2_EC_CURVE_NISTP521;
    else
        return -1;

    if(out_curve)
        *out_curve = type;

    return 0;
}

/*
 * Creates a new public key given an octal string, length and type
 */
int ssh2_ecdsa_curve_name_with_octal_new(
    ssh2_ecdsa_ctx **ec_ctx,
    const unsigned char *publickey_encoded, size_t publickey_encoded_len,
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

    if(publickey_encoded_len > 0)
        data = OPENSSL_malloc(publickey_encoded_len);

    if(group_name && data) {
        OSSL_PARAM params[3] = { 0 };

        memcpy(group_name, n, strlen(n) + 1);
        memcpy(data, publickey_encoded, publickey_encoded_len);

        params[0] = OSSL_PARAM_construct_utf8_string(
            OSSL_PKEY_PARAM_GROUP_NAME, group_name, 0);
        params[1] = OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_PUB_KEY, data, publickey_encoded_len);
        params[2] = OSSL_PARAM_construct_end();

        if(EVP_PKEY_fromdata_init(ctx) > 0)
            ret = EVP_PKEY_fromdata(ctx, ec_ctx, EVP_PKEY_PUBLIC_KEY, params);
        else
            ret = -1;
    }
    else
        ret = -1;

    if(group_name)
        OPENSSL_clear_free(group_name, strlen(n) + 1);

    if(data)
        OPENSSL_clear_free(data, publickey_encoded_len);

    EVP_PKEY_CTX_free(ctx);
#else
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(curve);

    if(ec_key) {
        const EC_GROUP *ec_group = NULL;
        EC_POINT *point = NULL;

        ec_group = EC_KEY_get0_group(ec_key);
        point = EC_POINT_new(ec_group);
        if(point) {
            ret = EC_POINT_oct2point(ec_group, point,
                                     publickey_encoded, publickey_encoded_len,
                                     NULL);
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

    return ret == 1 ? 0 : -1;
}

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

    ECDSA_SIG *ecdsa_sig;
    BIGNUM *pr;
    BIGNUM *ps;

    pr = BN_new();
    if(!pr)
        return -1;

    ps = BN_new();
    if(!ps) {
        BN_free(pr);
        return -1;
    }

    ecdsa_sig = ECDSA_SIG_new();
    if(!ecdsa_sig) {
        BN_free(pr);
        BN_free(ps);
        return -1;
    }

    BN_bin2bn(r, (int)r_len, pr);
    BN_bin2bn(s, (int)s_len, ps);

    ECDSA_SIG_set0(ecdsa_sig, pr, ps);

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

    if(type == SSH2_EC_CURVE_NISTP256) {
        unsigned char hash[SSH2_SHA256_DIG_LEN];
        if(ssh2_hash(SSH2_SHA256_ALG, m, m_len, hash, sizeof(hash))) {
            ret = EVP_PKEY_verify_init(ctx);
            if(ret > 0)
                ret = EVP_PKEY_verify(ctx, der, der_len, hash, sizeof(hash));
        }
    }
    else if(type == SSH2_EC_CURVE_NISTP384) {
        unsigned char hash[SSH2_SHA384_DIG_LEN];
        if(ssh2_hash(SSH2_SHA384_ALG, m, m_len, hash, sizeof(hash))) {
            ret = EVP_PKEY_verify_init(ctx);
            if(ret > 0)
                ret = EVP_PKEY_verify(ctx, der, der_len, hash, sizeof(hash));
        }
    }
    else if(type == SSH2_EC_CURVE_NISTP521) {
        unsigned char hash[SSH2_SHA512_DIG_LEN];
        if(ssh2_hash(SSH2_SHA512_ALG, m, m_len, hash, sizeof(hash))) {
            ret = EVP_PKEY_verify_init(ctx);
            if(ret > 0)
                ret = EVP_PKEY_verify(ctx, der, der_len, hash, sizeof(hash));
        }
    }
cleanup:

    if(ctx)
        EVP_PKEY_CTX_free(ctx);

    if(der)
        OPENSSL_free(der);
#else
    if(type == SSH2_EC_CURVE_NISTP256) {
        unsigned char hash[SSH2_SHA256_DIG_LEN];
        if(ssh2_hash(SSH2_SHA256_ALG, m, m_len, hash, sizeof(hash)))
            ret = ECDSA_do_verify(hash, sizeof(hash), ecdsa_sig, ec_key);
    }
    else if(type == SSH2_EC_CURVE_NISTP384) {
        unsigned char hash[SSH2_SHA384_DIG_LEN];
        if(ssh2_hash(SSH2_SHA384_ALG, m, m_len, hash, sizeof(hash)))
            ret = ECDSA_do_verify(hash, sizeof(hash), ecdsa_sig, ec_key);
    }
    else if(type == SSH2_EC_CURVE_NISTP521) {
        unsigned char hash[SSH2_SHA512_DIG_LEN];
        if(ssh2_hash(SSH2_SHA512_ALG, m, m_len, hash, sizeof(hash)))
            ret = ECDSA_do_verify(hash, sizeof(hash), ecdsa_sig, ec_key);
    }
#endif

    if(ecdsa_sig)
        ECDSA_SIG_free(ecdsa_sig);

    return ret == 1 ? 0 : -1;
}

#endif /* LIBSSH2_ECDSA */

int ssh2_cipher_init(ssh2_cipher_ctx *ctx, SSH2_CIPHER_T(algo),
                     unsigned char *iv, unsigned char *secret, int encrypt)
{
#if LIBSSH2_AES_GCM
    const int is_aesgcm = (algo == EVP_aes_128_gcm) ||
                          (algo == EVP_aes_256_gcm);
#endif /* LIBSSH2_AES_GCM */
    int rc;

    *ctx = EVP_CIPHER_CTX_new();
    rc = !EVP_CipherInit(*ctx, algo(), secret, iv, encrypt);
#if LIBSSH2_AES_GCM
    if(is_aesgcm)
        /* Sets both fixed and invocation_counter parts of IV */
        rc |= !EVP_CIPHER_CTX_ctrl(*ctx, EVP_CTRL_AEAD_SET_IV_FIXED, -1, iv);
#endif /* LIBSSH2_AES_GCM */

    return rc;
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
            /* Include the 4-byte packet length as AAD */
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

    if(cryptlen > 0)
        ret = EVP_Cipher(*ctx, buf + aadlen, block + aadlen, cryptlen);

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
#else
            ret = EVP_Cipher(*ctx, NULL, NULL, 0); /* final */
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
static unsigned char *ossl_rsa_to_pubkey(LIBSSH2_SESSION *session,
                                         ssh2_rsa_ctx *rsa, size_t *key_len)
{
    static const char method_name[] = "ssh-rsa";
    int e_bytes, n_bytes;
    size_t len;
    unsigned char *key = NULL;
    unsigned char *p;

#ifdef USE_OPENSSL_3
    BIGNUM *e = NULL;
    BIGNUM *n = NULL;

    EVP_PKEY_get_bn_param(rsa, OSSL_PKEY_PARAM_RSA_E, &e);
    EVP_PKEY_get_bn_param(rsa, OSSL_PKEY_PARAM_RSA_N, &n);
#else
    const BIGNUM *e = NULL;
    const BIGNUM *n = NULL;

    RSA_get0_key(rsa, &n, &e, NULL);
#endif
    if(!e || !n)
        goto fail;

    e_bytes = BN_num_bytes(e) + 1;
    n_bytes = BN_num_bytes(n) + 1;

    /* Key form is "ssh-rsa" + e + n. */
    len = 4 + sizeof(method_name) - 1 + 4 + e_bytes + 4 + n_bytes;
    key = p = SSH2_ALLOC(session, len);
    if(!key)
        goto fail;

    ssh2_htonu32(p, sizeof(method_name) - 1); /* Key type. */
    p += 4;
    memcpy(p, method_name, sizeof(method_name) - 1);
    p += sizeof(method_name) - 1;

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

static int ossl_rsa_evp_to_pubkey(LIBSSH2_SESSION *session, char **method,
                                  unsigned char **pubkeydata,
                                  size_t *pubkeydata_len,
                                  EVP_PKEY *pk)
{
    static const char method_name[] = "ssh-rsa";
    ssh2_rsa_ctx *rsa = NULL;
    unsigned char *key;
    char *method_buf = NULL;
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

    method_buf = SSH2_ALLOC(session, sizeof(method_name));
    if(!method_buf)
        goto alloc_error;

    key = ossl_rsa_to_pubkey(session, rsa, &key_len);
    if(!key)
        goto alloc_error;
#ifndef USE_OPENSSL_3
    RSA_free(rsa);
#endif

    memcpy(method_buf, method_name, sizeof(method_name));
    *method = method_buf;

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

    RSA_get0_key(rsa, NULL, NULL, &d);
    RSA_get0_factors(rsa, &p, &q);

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

    RSA_set0_crt_params(rsa, dmp1, dmq1, NULL);

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
                                           char **method,
                                           unsigned char **pubkeydata,
                                           size_t *pubkeydata_len,
                                           ssh2_rsa_ctx **rsa)
{
    int rc = 0;
    size_t nlen, elen, dlen, plen, qlen, coefflen, commentlen;
    unsigned char *n, *e, *d, *p, *q, *coeff, *comment;
    ssh2_rsa_ctx *ctx = NULL;

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

    rc = ssh2_rsa_new(&ctx, e, elen, n, nlen, d, dlen,
                      p, plen, q, qlen, NULL, 0, NULL, 0, coeff, coefflen);
    if(rc) {
        ssh2_deb((session, LIBSSH2_TRACE_AUTH,
                  "Could not create RSA private key"));
        goto fail;
    }

#ifndef USE_OPENSSL_3
    if(ctx)
        rc = ossl_rsa_additional_params_new(ctx);
#endif

    if(ctx && pubkeydata && method) {
#ifdef USE_OPENSSL_3
        EVP_PKEY *pk = ctx;
#else
        EVP_PKEY *pk = EVP_PKEY_new();
        EVP_PKEY_set1_RSA(pk, ctx);
#endif

        rc = ossl_rsa_evp_to_pubkey(session, method,
                                    pubkeydata, pubkeydata_len, pk);

#ifndef USE_OPENSSL_3
        if(pk)
            EVP_PKEY_free(pk);
#endif
    }

    if(rsa)
        *rsa = ctx;
    else
        ssh2_rsa_free(ctx);

    return rc;

fail:

    if(ctx)
        ssh2_rsa_free(ctx);

    return ssh2_err(session, LIBSSH2_ERROR_ALLOC,
                    "Unable to allocate memory for private key data");
}

int ssh2_rsa_new_priv(ssh2_rsa_ctx **rsa,
                      LIBSSH2_SESSION *session,
                      const char *filename,
                      const char *blob, size_t blob_len,
                      const char *passphrase)
{
    int rc = 0;
    BIO *bp;

    OSSL_INIT_IF_NEEDED();

    *rsa = NULL;

    if(filename)
        bp = BIO_new_file(filename, "r");
    else
        bp = BIO_new_mem_buf(blob, (int)blob_len);
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
        rc = ossl_key_from_openssh(session, (void **)rsa, "ssh-rsa",
                                   NULL, NULL, NULL,
                                   filename, blob, blob_len, passphrase);

    return rc;
}
#endif

#if LIBSSH2_DSA
static unsigned char *ossl_dsa_to_pubkey(LIBSSH2_SESSION *session,
                                         ssh2_dsa_ctx *dsa, size_t *key_len)
{
    static const char method_name[] = "ssh-dss";
    int p_bytes, q_bytes, g_bytes, k_bytes;
    size_t len;
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

    DSA_get0_pqg(dsa, &p_bn, &q, &g);
    DSA_get0_key(dsa, &pub_key, NULL);
#endif
    p_bytes = BN_num_bytes(p_bn) + 1;
    q_bytes = BN_num_bytes(q) + 1;
    g_bytes = BN_num_bytes(g) + 1;
    k_bytes = BN_num_bytes(pub_key) + 1;

    /* Key form is "ssh-dss" + p + q + g + pub_key. */
    len = 4 + sizeof(method_name) - 1 + 4 + p_bytes + 4 + q_bytes +
          4 + g_bytes + 4 + k_bytes;
    key = p = SSH2_ALLOC(session, len);
    if(!key)
        goto fail;

    ssh2_htonu32(p, sizeof(method_name) - 1); /* Key type. */
    p += 4;
    memcpy(p, method_name, sizeof(method_name) - 1);
    p += sizeof(method_name) - 1;

    p = ossl_write_bn(p, p_bn, p_bytes);
    p = ossl_write_bn(p, q, q_bytes);
    p = ossl_write_bn(p, g, g_bytes);
    p = ossl_write_bn(p, pub_key, k_bytes);

    *key_len = p - key;
fail:
#ifdef USE_OPENSSL_3
    BN_clear_free(p_bn);
    BN_clear_free(q);
    BN_clear_free(g);
    BN_clear_free(pub_key);
#endif
    return key;
}

static int ossl_dsa_evp_to_pubkey(LIBSSH2_SESSION *session, char **method,
                                  unsigned char **pubkeydata,
                                  size_t *pubkeydata_len,
                                  EVP_PKEY *pk)
{
    static const char method_name[] = "ssh-dss";
    ssh2_dsa_ctx *dsa = NULL;
    unsigned char *key;
    char *method_buf = NULL;
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

    method_buf = SSH2_ALLOC(session, sizeof(method_name));
    if(!method_buf)
        goto alloc_error;

    key = ossl_dsa_to_pubkey(session, dsa, &key_len);
    if(!key)
        goto alloc_error;
#ifndef USE_OPENSSL_3
    DSA_free(dsa);
#endif

    memcpy(method_buf, method_name, sizeof(method_name));
    *method = method_buf;

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
                                           char **method,
                                           unsigned char **pubkeydata,
                                           size_t *pubkeydata_len,
                                           ssh2_dsa_ctx **dsa)
{
    int rc = 0;
    size_t plen, qlen, glen, pub_len, priv_len;
    unsigned char *p, *q, *g, *pub_key, *priv_key;
    ssh2_dsa_ctx *ctx = NULL;

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

    rc = ssh2_dsa_new(&ctx, p, plen, q, qlen, g, glen,
                      pub_key, pub_len, priv_key, priv_len);
    if(rc) {
        ssh2_deb((session, LIBSSH2_ERROR_PROTO,
                  "Could not create DSA private key"));
        goto fail;
    }

    if(ctx && pubkeydata && method) {
#ifdef USE_OPENSSL_3
        EVP_PKEY *pk = ctx;
#else
        EVP_PKEY *pk = EVP_PKEY_new();
        EVP_PKEY_set1_DSA(pk, ctx);
#endif

        rc = ossl_dsa_evp_to_pubkey(session, method,
                                    pubkeydata, pubkeydata_len, pk);

#ifndef USE_OPENSSL_3
        if(pk)
            EVP_PKEY_free(pk);
#endif
    }

    if(dsa)
        *dsa = ctx;
    else
        ssh2_dsa_free(ctx);

    return rc;

fail:

    if(ctx)
        ssh2_dsa_free(ctx);

    return ssh2_err(session, LIBSSH2_ERROR_ALLOC,
                    "Unable to allocate memory for private key data");
}

int ssh2_dsa_new_priv(ssh2_dsa_ctx **dsa,
                      LIBSSH2_SESSION *session,
                      const char *filename,
                      const char *blob, size_t blob_len,
                      const char *passphrase)
{
    int rc = 0;
    BIO *bp;

    OSSL_INIT_IF_NEEDED();

    *dsa = NULL;

    if(filename)
        bp = BIO_new_file(filename, "r");
    else
        bp = BIO_new_mem_buf(blob, (int)blob_len);
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
        rc = ossl_key_from_openssh(session, (void **)dsa, "ssh-dss",
                                   NULL, NULL, NULL,
                                   filename, blob, blob_len, passphrase);

    return rc;
}
#endif /* LIBSSH2_DSA */

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

static int ossl_ed25519_evp_to_pubkey(LIBSSH2_SESSION *session, char **method,
                                      unsigned char **pubkeydata,
                                      size_t *pubkeydata_len,
                                      EVP_PKEY *pk)
{
    static const char method_name[] = "ssh-ed25519";
    char *method_buf = NULL;
    size_t rawKeyLen = 0;
    unsigned char *pub_key = NULL;
    size_t key_len = 0;
    unsigned char *p = NULL;

    ssh2_deb((session, LIBSSH2_TRACE_AUTH,
              "Computing public key from ED private key envelope"));

    method_buf = SSH2_ALLOC(session, sizeof(method_name));
    if(!method_buf) {
        ssh2_err(session, LIBSSH2_ERROR_ALLOC,
                 "Unable to allocate memory for private key data");
        goto fail;
    }
    memcpy(method_buf, method_name, sizeof(method_name));

    if(EVP_PKEY_get_raw_public_key(pk, NULL, &rawKeyLen) != 1) {
        ssh2_err(session, LIBSSH2_ERROR_PROTO,
                 "EVP_PKEY_get_raw_public_key failed");
        goto fail;
    }

    /* Key form is: type_len(4) + type(11) + pub_key_len(4) + pub_key(32). */
    key_len = 4 + sizeof(method_name) - 1 + 4 + rawKeyLen;
    pub_key = p = SSH2_ALLOC(session, key_len);
    if(!pub_key) {
        ssh2_err(session, LIBSSH2_ERROR_ALLOC,
                 "Unable to allocate memory for private key data");
        goto fail;
    }

    ssh2_store_str(&p, method_name, sizeof(method_name) - 1);
    ssh2_store_u32(&p, (uint32_t)rawKeyLen);

    if(EVP_PKEY_get_raw_public_key(pk, p, &rawKeyLen) != 1) {
        ssh2_err(session, LIBSSH2_ERROR_PROTO,
                 "EVP_PKEY_get_raw_public_key failed");
        goto fail;
    }

    *method = method_buf;

    *pubkeydata = pub_key;
    if(pubkeydata_len)
        *pubkeydata_len = key_len;

    return 0;

fail:
    if(method_buf)
        SSH2_FREE(session, method_buf);
    if(pub_key)
        SSH2_FREE(session, pub_key);
    return -1;
}

static int ossl_ed25519_openssh_priv_to_pubkey(LIBSSH2_SESSION *session,
                                               struct string_buf *decrypted,
                                               char **method,
                                               unsigned char **pubkeydata,
                                               size_t *pubkeydata_len,
                                               ssh2_ed25519_ctx **ed_ctx)
{
    static const char method_name[] = "ssh-ed25519";
    ssh2_ed25519_ctx *ctx = NULL;
    char *method_buf = NULL;
    unsigned char *key = NULL;
    int i;
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

    if(tmp_len > 0 && tmp_len <= INT_MAX)
        ssh2_deb((session, LIBSSH2_TRACE_AUTH, "Key comment: %.*s",
                  (int)tmp_len, buf));

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

    ssh2_deb((session, LIBSSH2_TRACE_AUTH,
              "Computing public key from ED25519 private key envelope"));

    method_buf = SSH2_ALLOC(session, sizeof(method_name));
    if(!method_buf) {
        ssh2_err(session, LIBSSH2_ERROR_ALLOC,
                 "Unable to allocate memory for ED25519 key");
        goto clean_exit;
    }

    /* Key form is: type_len(4) + type(11) + pub_key_len(4) + pub_key(32). */
    key_len = 4 + sizeof(method_name) - 1 + 4 + SSH2_ED25519_KEY_LEN;
    key = p = SSH2_CALLOC(session, key_len);
    if(!key) {
        ssh2_err(session, LIBSSH2_ERROR_ALLOC,
                 "Unable to allocate memory for ED25519 key");
        goto clean_exit;
    }

    ssh2_store_str(&p, method_name, sizeof(method_name) - 1);
    ssh2_store_str(&p, pub_key, SSH2_ED25519_KEY_LEN);

    memcpy(method_buf, method_name, sizeof(method_name));

    if(method)
        *method = method_buf;
    else
        SSH2_FREE(session, method_buf);

    if(pubkeydata)
        *pubkeydata = key;
    else
        SSH2_FREE(session, key);

    if(pubkeydata_len)
        *pubkeydata_len = key_len;

    if(ed_ctx)
        *ed_ctx = ctx;
    else if(ctx)
        ssh2_ed25519_free(ctx);

    return 0;

clean_exit:

    if(ctx)
        ssh2_ed25519_free(ctx);

    if(method_buf)
        SSH2_FREE(session, method_buf);

    if(key)
        SSH2_FREE(session, key);

    return -1;
}

static int ossl_ed25519_sk_openssh_priv_to_pubkey(
    LIBSSH2_SESSION *session,
    struct string_buf *decrypted,
    char **method,
    unsigned char **pubkeydata,
    size_t *pubkeydata_len,
    unsigned char *flags,
    const char **application,
    const unsigned char **key_handle,
    size_t *key_handle_len,
    ssh2_ed25519_ctx **ed_ctx)
{
    static const char method_name[] = "sk-ssh-ed25519@openssh.com";
    ssh2_ed25519_ctx *ctx = NULL;
    char *method_buf = NULL;
    unsigned char *key = NULL;
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

    if(key_handle && key_handle_len) {
        unsigned char *handle = NULL;
        if(ssh2_get_string(decrypted, &handle, key_handle_len)) {
            ssh2_err(session, LIBSSH2_ERROR_PROTO, "No SK key_handle.");
            return -1;
        }

        if(*key_handle_len > 0) {
            *key_handle = SSH2_ALLOC(session, *key_handle_len);
            if(*key_handle)
                memcpy(SSH2_UNCONST(*key_handle), handle, *key_handle_len);
        }
    }

    ctx = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL,
                                      (const unsigned char *)pub_key,
                                      SSH2_ED25519_KEY_LEN);

    ssh2_deb((session, LIBSSH2_TRACE_AUTH,
              "Computing public key from ED25519 private key envelope"));

    /* sk-ssh-ed25519@openssh.com. */
    method_buf = SSH2_ALLOC(session, sizeof(method_name));
    if(!method_buf) {
        ssh2_err(session, LIBSSH2_ERROR_ALLOC,
                 "Unable to allocate memory for ED25519 key");
        goto clean_exit;
    }

    /* Key form is: type_len(4) + type(26) + pub_key_len(4) +
       pub_key(32) + application_len(4) + application(X). */
    key_len = SSH2_ED25519_KEY_LEN + 38 + app_len;
    key = p = SSH2_CALLOC(session, key_len);
    if(!key) {
        ssh2_err(session, LIBSSH2_ERROR_ALLOC,
                 "Unable to allocate memory for ED25519 key");
        goto clean_exit;
    }

    ssh2_store_str(&p, method_name, sizeof(method_name) - 1);
    ssh2_store_str(&p, pub_key, SSH2_ED25519_KEY_LEN);
    ssh2_store_str(&p, app, app_len);

    if(application && app_len > 0) {
        *application = SSH2_ALLOC(session, app_len + 1);
        if(!*application) {
            ssh2_err(session, LIBSSH2_ERROR_ALLOC,
                     "Unable to allocate memory for ED25519 application");
            goto clean_exit;
        }
        ssh2_explicit_zero(SSH2_UNCONST(*application), app_len + 1);
        memcpy(SSH2_UNCONST(*application), app, app_len);
    }

    memcpy(method_buf, method_name, sizeof(method_name));

    if(method)
        *method = method_buf;
    else
        SSH2_FREE(session, method_buf);

    if(pubkeydata)
        *pubkeydata = key;
    else
        SSH2_FREE(session, key);

    if(pubkeydata_len)
        *pubkeydata_len = key_len;

    if(ed_ctx)
        *ed_ctx = ctx;
    else if(ctx)
        ssh2_ed25519_free(ctx);

    return 0;

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

int ssh2_ed25519_new_priv(ssh2_ed25519_ctx **ed_ctx,
                          LIBSSH2_SESSION *session,
                          const char *filename,
                          const char *blob, size_t blob_len,
                          const char *passphrase)
{
    int rc = 0;
    BIO *bp = NULL;

    OSSL_INIT_IF_NEEDED();

    *ed_ctx = NULL;

    if(filename)
        bp = BIO_new_file(filename, "r");
    else
        bp = BIO_new_mem_buf(blob, (int)blob_len);
    if(bp)
        *ed_ctx = PEM_read_bio_PrivateKey(bp, NULL, ossl_passphrase_cb,
                                          SSH2_UNCONST(passphrase));
    BIO_free(bp);

    if(*ed_ctx && EVP_PKEY_id(*ed_ctx) != EVP_PKEY_ED25519) {
        ssh2_ed25519_free(*ed_ctx);
        *ed_ctx = NULL;
        return ssh2_err(session, LIBSSH2_ERROR_PROTO,
                        "Private key is not an ED25519 key");
    }

    if(!*ed_ctx)
        rc = ossl_key_from_openssh(session, (void **)ed_ctx, "ssh-ed25519",
                                   NULL, NULL, NULL,
                                   filename, blob, blob_len, passphrase);

    return rc;
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

    *ed_ctx = ctx;

    return 0;
}
#endif /* LIBSSH2_ED25519 */

#if LIBSSH2_MLKEM

int ssh2_mlkem_new(LIBSSH2_SESSION *session, int mlkem_size,
                   unsigned char **out_public_key,
                   unsigned char **out_private_key)
{
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    unsigned char *priv = NULL, *pub = NULL;
    const char *evp_name;
    size_t privLen, actualPrivLen, pubLen, actualPubLen;
    int rc = -1;

    switch(mlkem_size) {
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
        if(!priv)
            goto clean_exit;

        actualPrivLen = privLen;
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

        actualPubLen = pubLen;
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

int ssh2_mlkem_get_sk(unsigned char *out_shared_key, int mlkem_size,
                      uint8_t *private_key, uint8_t *server_ciphertext)
{
    int rc = -1;
    EVP_PKEY *client_key = NULL;
    EVP_PKEY_CTX *client_key_ctx = NULL;
    size_t out_len = 0;
    const char *evp_name;
    size_t privLen, ciphertextLen;

    switch(mlkem_size) {
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

    return rc == 1 ? 0 : -1;
}

#endif

#if LIBSSH2_RSA
int ssh2_rsa_sha2_sign(ssh2_rsa_ctx *rsa, LIBSSH2_SESSION *session,
                       const unsigned char *hash, size_t hash_len,
                       unsigned char **signature, size_t *signature_len)
{
    int ret = -1;
    unsigned char *sig = NULL;

#ifdef USE_OPENSSL_3
    size_t sig_len = 0;
    BIGNUM *n = NULL;
    const EVP_MD *md = NULL;

    if(EVP_PKEY_get_bn_param(rsa, OSSL_PKEY_PARAM_RSA_N, &n) > 0) {
        sig_len = BN_num_bytes(n);
        BN_clear_free(n);
    }

    if(sig_len > 0)
        sig = SSH2_ALLOC(session, sig_len);
#else
    unsigned int sig_len = 0;

    sig_len = RSA_size(rsa);
    sig = SSH2_ALLOC(session, sig_len);
#endif
    if(!sig)
        return -1;

#ifdef USE_OPENSSL_3
    if(hash_len == SSH2_SHA1_DIG_LEN)
        md = EVP_sha1();
    else if(hash_len == SSH2_SHA256_DIG_LEN)
        md = EVP_sha256();
    else if(hash_len == SSH2_SHA512_DIG_LEN)
        md = EVP_sha512();
    else
        ssh2_err(session, LIBSSH2_ERROR_PROTO,
                 "Unsupported hash digest length");

    if(md) {
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(rsa, NULL);
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
    if(hash_len == SSH2_SHA1_DIG_LEN)
        ret = RSA_sign(NID_sha1,
                       hash, (unsigned int)hash_len, sig, &sig_len, rsa);
    else if(hash_len == SSH2_SHA256_DIG_LEN)
        ret = RSA_sign(NID_sha256,
                       hash, (unsigned int)hash_len, sig, &sig_len, rsa);
    else if(hash_len == SSH2_SHA512_DIG_LEN)
        ret = RSA_sign(NID_sha512,
                       hash, (unsigned int)hash_len, sig, &sig_len, rsa);
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
int ssh2_rsa_sha1_sign(ssh2_rsa_ctx *rsa, LIBSSH2_SESSION *session,
                       const unsigned char *hash, size_t hash_len,
                       unsigned char **signature, size_t *signature_len)
{
    return ssh2_rsa_sha2_sign(rsa, session, hash, hash_len,
                              signature, signature_len);
}
#endif
#endif

#if LIBSSH2_DSA
int ssh2_dsa_sha1_sign(ssh2_dsa_ctx *dsa,
                       const unsigned char *hash, size_t hash_len,
                       unsigned char *signature)
{
    DSA_SIG *sig = NULL;
    const BIGNUM *r;
    const BIGNUM *s;
    int r_len, s_len;

#ifdef USE_OPENSSL_3
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(dsa, NULL);
    unsigned char *buf = NULL;
    size_t sig_len = 0;
    int size = 0;

    if(EVP_PKEY_get_int_param(dsa, OSSL_PKEY_PARAM_MAX_SIZE, &size) > 0) {
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

    sig = DSA_do_sign(hash, SSH2_SHA1_DIG_LEN, dsa);
#endif
    if(!sig)
        return -1;

    DSA_SIG_get0(sig, &r, &s);

    r_len = BN_num_bytes(r);
    if(r_len < 1 || r_len > SSH2_SHA1_DIG_LEN) {
        DSA_SIG_free(sig);
        return -1;
    }
    s_len = BN_num_bytes(s);
    if(s_len < 1 || s_len > SSH2_SHA1_DIG_LEN) {
        DSA_SIG_free(sig);
        return -1;
    }

    memset(signature, 0, SSH2_SHA1_DIG_LEN * 2);

    BN_bn2bin(r, signature + (SSH2_SHA1_DIG_LEN - r_len));
    BN_bn2bin(s, signature + SSH2_SHA1_DIG_LEN + (SSH2_SHA1_DIG_LEN - s_len));

    DSA_SIG_free(sig);

    return 0;
}
#endif /* LIBSSH2_DSA */

#if LIBSSH2_ECDSA

int ssh2_ecdsa_sign(ssh2_ecdsa_ctx *ec_ctx, LIBSSH2_SESSION *session,
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

    ECDSA_SIG_get0(sig, &pr, &ps);

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

static int ossl_ecdsa_evp_to_pubkey(LIBSSH2_SESSION *session, char **method,
                                    unsigned char **pubkeydata,
                                    size_t *pubkeydata_len,
                                    int is_sk,
                                    EVP_PKEY *pk)
{
    int rc = 0;
    char *method_buf = NULL;
    unsigned char *p;
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
        method_buf_len = sizeof("sk-ecdsa-sha2-nistp256@openssh.com") - 1;
    else
        method_buf_len = sizeof("ecdsa-sha2-nistp256") - 1;

    method_buf = SSH2_ALLOC(session, method_buf_len + 1);
    if(!method_buf)
        return ssh2_err(session, LIBSSH2_ERROR_ALLOC, "out of memory");

    if(is_sk)
        memcpy(method_buf, "sk-ecdsa-sha2-nistp256@openssh.com",
               method_buf_len + 1);
    else if(type == SSH2_EC_CURVE_NISTP256)
        memcpy(method_buf, "ecdsa-sha2-nistp256", method_buf_len + 1);
    else if(type == SSH2_EC_CURVE_NISTP384)
        memcpy(method_buf, "ecdsa-sha2-nistp384", method_buf_len + 1);
    else if(type == SSH2_EC_CURVE_NISTP521)
        memcpy(method_buf, "ecdsa-sha2-nistp521", method_buf_len + 1);
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
    key = p = SSH2_ALLOC(session, key_len);
    if(!key) {
        rc = -1;
        goto clean_exit;
    }

    /* Key type */
    ssh2_store_str(&p, method_buf, method_buf_len);

    /* Name domain */
    if(is_sk)
        ssh2_store_str(&p, "nistp256", sizeof("nistp256") - 1);
    else
        ssh2_store_str(&p, method_buf + sizeof("ecdsa-sha2-") - 1,
                           sizeof("nistp256") - 1);

    /* Public key */
    ssh2_store_str(&p, octal_value, octal_len);

    *method = method_buf;

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
                                             char **method,
                                             unsigned char **pubkeydata,
                                             size_t *pubkeydata_len,
                                             ssh2_ecdsa_ctx **ec_ctx)
{
    int rc = 0;
    size_t curvelen, exponentlen, pointlen;
    unsigned char *curve, *exponent, *point_buf;
    ssh2_ecdsa_ctx *ctx = NULL;

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

    memcpy(group_name, n, strlen(n) + 1);
    ossl_swap_bytes(exponent, exponentlen);

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                 group_name, 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                                  point_buf, pointlen);
    params[2] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_PRIV_KEY, exponent,
                                        exponentlen);
    params[3] = OSSL_PARAM_construct_end();

    if(EVP_PKEY_fromdata_init(fromdata_ctx) <= 0)
        goto fail;

    rc = EVP_PKEY_fromdata(fromdata_ctx, &ctx, EVP_PKEY_KEYPAIR, params);
    rc = rc != 1;

    if(group_name)
        OPENSSL_clear_free(group_name, strlen(n) + 1);
#else
    rc = ssh2_ecdsa_curve_name_with_octal_new(&ctx, point_buf, pointlen,
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
    rc = (EC_KEY_set_private_key(ctx, bn_exponent) != 1);
    BN_free(bn_exponent);
#endif

    if(rc == 0 && ctx && pubkeydata && method) {
#ifdef USE_OPENSSL_3
        EVP_PKEY *pk = ctx;
#else
        EVP_PKEY *pk = EVP_PKEY_new();
        EVP_PKEY_set1_EC_KEY(pk, ctx);
#endif

        rc = ossl_ecdsa_evp_to_pubkey(session, method,
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
        *ec_ctx = ctx;
    else
        ssh2_ecdsa_free(ctx);

    return rc;

fail:
#ifdef USE_OPENSSL_3
    if(fromdata_ctx)
        EVP_PKEY_CTX_free(fromdata_ctx);
#endif

    if(ctx)
        ssh2_ecdsa_free(ctx);

    return rc;
}

static int ossl_ecdsa_sk_openssh_priv_to_pubkey(
    LIBSSH2_SESSION *session,
    struct string_buf *decrypted,
    char **method,
    unsigned char **pubkeydata,
    size_t *pubkeydata_len,
    unsigned char *flags,
    const char **application,
    const unsigned char **key_handle,
    size_t *key_handle_len,
    ssh2_ecdsa_ctx **ec_ctx)
{
    int rc = 0;
    size_t curvelen, pointlen, key_len, app_len;
    unsigned char *curve, *point_buf, *p, *key = NULL, *app;
    ssh2_ecdsa_ctx *ctx = NULL;

    ssh2_deb((session, LIBSSH2_TRACE_AUTH, "Extracting ECDSA-SK public key"));

    if(ssh2_get_string(decrypted, &curve, &curvelen) || curvelen == 0) {
        ssh2_err(session, LIBSSH2_ERROR_PROTO, "ECDSA no curve");
        return -1;
    }

    if(ssh2_get_string(decrypted, &point_buf, &pointlen)) {
        ssh2_err(session, LIBSSH2_ERROR_PROTO, "ECDSA no point");
        return -1;
    }

    rc = ssh2_ecdsa_curve_name_with_octal_new(&ctx, point_buf, pointlen,
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

    if(key_handle && key_handle_len) {
        unsigned char *handle = NULL;
        if(ssh2_get_string(decrypted, &handle, key_handle_len)) {
            ssh2_err(session, LIBSSH2_ERROR_PROTO, "No SK key_handle.");
            goto fail;
        }

        if(*key_handle_len > 0) {
            *key_handle = SSH2_ALLOC(session, *key_handle_len);
            if(*key_handle)
                memcpy(SSH2_UNCONST(*key_handle), handle, *key_handle_len);
        }
    }

    if(rc == 0 && ctx && pubkeydata && method) {
#ifdef USE_OPENSSL_3
        EVP_PKEY *pk = ctx;
#else
        EVP_PKEY *pk = EVP_PKEY_new();
        EVP_PKEY_set1_EC_KEY(pk, ctx);
#endif

        rc = ossl_ecdsa_evp_to_pubkey(session, method,
                                      pubkeydata, pubkeydata_len, 1, pk);

#ifndef USE_OPENSSL_3
        if(pk)
            EVP_PKEY_free(pk);
#endif
    }

    if(rc == 0 && pubkeydata) {
        key_len = *pubkeydata_len + app_len + 4;
        key = p = SSH2_ALLOC(session, key_len);
        if(!key) {
            rc = -1;
            goto fail;
        }

        p += *pubkeydata_len;

        memcpy(key, *pubkeydata, *pubkeydata_len);
        ssh2_store_str(&p, app, app_len);

        if(application && app_len > 0) {
            *application = SSH2_ALLOC(session, app_len + 1);
            if(!*application) {
                ssh2_err(session, LIBSSH2_ERROR_ALLOC,
                         "Unable to allocate memory for ECDSA application");
                rc = -1;
                goto fail;
            }
            ssh2_explicit_zero(SSH2_UNCONST(*application), app_len + 1);
            memcpy(SSH2_UNCONST(*application), app, app_len);
        }

        SSH2_FREE(session, *pubkeydata);
        *pubkeydata_len = key_len;
        *pubkeydata = key;
    }

    if(ec_ctx)
        *ec_ctx = ctx;
    else
        ssh2_ecdsa_free(ctx);

    return rc;

fail:
    if(ctx)
        ssh2_ecdsa_free(ctx);

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

    return rc;
}

int ssh2_ecdsa_new_priv(ssh2_ecdsa_ctx **ec_ctx,
                        LIBSSH2_SESSION *session,
                        const char *filename,
                        const char *blob, size_t blob_len,
                        const char *passphrase)
{
    int rc = 0;
    BIO *bp;

    OSSL_INIT_IF_NEEDED();

    *ec_ctx = NULL;

    if(filename)
        bp = BIO_new_file(filename, "r");
    else
        bp = BIO_new_mem_buf(blob, (int)blob_len);
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
        rc = ossl_key_from_openssh(session, (void **)ec_ctx, "ssh-ecdsa",
                                   NULL, NULL, NULL,
                                   filename, blob, blob_len, passphrase);

    return rc;
}

/*
 * Creates a local private key based on input curve
 * and returns octal value and octal length
 */
int ssh2_ecdsa_create_key(ssh2_ec_key **ec_ctx, LIBSSH2_SESSION *session,
                          unsigned char **out_public_key_octal,
                          size_t *out_public_key_octal_len,
                          ssh2_curve_type curve)
{
    int ret = 1;
    size_t octal_len = 0;
    unsigned char octal_value[EC_MAX_POINT_LEN];
    ssh2_ec_key *private_key = NULL;

#ifdef USE_OPENSSL_3
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if(ctx &&
       EVP_PKEY_keygen_init(ctx) > 0 &&
       EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, curve) > 0) {
        ret = EVP_PKEY_keygen(ctx, &private_key);
    }

    if(ret <= 0)
        goto clean_exit;

    if(ec_ctx)
        *ec_ctx = private_key;

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

    private_key = EC_KEY_new_by_curve_name(curve);
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

    if(ec_ctx)
        *ec_ctx = private_key;

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

    return ret == 1 ? 0 : -1;
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

int ssh2_ed25519_sign(ssh2_ed25519_ctx *ed_ctx, LIBSSH2_SESSION *session,
                      uint8_t **out_sig, size_t *out_sig_len,
                      const uint8_t *message, size_t message_len)
{
    int rc = -1;
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    size_t sig_len = 0;
    unsigned char *sig = NULL;

    if(md_ctx) {
        if(EVP_DigestSignInit(md_ctx, NULL, NULL, NULL, ed_ctx) != 1)
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

    return rc == 1 ? 0 : -1;
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

    return rc == 1 ? 0 : -1;
}

int ssh2_ed25519_verify(ssh2_ed25519_ctx *ed_ctx, LIBSSH2_SESSION *session,
                        const uint8_t *s, size_t s_len,
                        const uint8_t *m, size_t m_len)
{
    int ret = -1;

    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if(!md_ctx) {
        ssh2_deb((session, LIBSSH2_TRACE_KEX,
                  "ssh2_ed25519_verify(): EVP_MD_CTX_new() failed"));
        return -1;
    }

    ret = EVP_DigestVerifyInit(md_ctx, NULL, NULL, NULL, ed_ctx);
    if(ret != 1) {
        ssh2_deb((session, LIBSSH2_TRACE_KEX,
                  "ssh2_ed25519_verify(): EVP_DigestVerifyInit()->%d", ret));
        goto clean_exit;
    }

    (void)session;
#ifdef LIBSSH2_DEBUG_MLKEM
    ssh2_deb((session, LIBSSH2_TRACE_KEX,
              "ssh2_ed25519_verify(%p, %lu, %p, %lu)",
              (const void *)s, (unsigned long)s_len,
              (const void *)m, (unsigned long)m_len));
#endif

    ret = EVP_DigestVerify(md_ctx, s, s_len, m, m_len);
    if(ret != 1)
        ssh2_deb((session, LIBSSH2_TRACE_KEX,
                  "ssh2_ed25519_verify(): EVP_DigestVerify()->%d (ossl: %lu)",
                  ret, ret ? ERR_peek_last_error() : 0));

clean_exit:

    EVP_MD_CTX_free(md_ctx);

    return ret == 1 ? 0 : -1;
}

#endif /* LIBSSH2_ED25519 */

static int ossl_key_from_openssh(LIBSSH2_SESSION *session,
                                 void **key_ctx,
                                 const char *want_method,
                                 char **method,
                                 unsigned char **pubkeydata,
                                 size_t *pubkeydata_len,
                                 const char *privkeyfile,
                                 const char *privkeyblob,
                                 size_t privkeyblob_len,
                                 const char *passphrase)
{
    int rc;
    char *buf = NULL;
    struct string_buf *decrypted = NULL;
#if LIBSSH2_ECDSA
    ssh2_curve_type type;
#endif

    if(key_ctx)
        *key_ctx = NULL;

    if(!session)
        return LIBSSH2_ERROR_BAD_USE;

    if(want_method && strlen(want_method) < 7)
        return ssh2_err(session, LIBSSH2_ERROR_PROTO, "type is invalid");

    OSSL_INIT_IF_NEEDED();

    rc = ssh2_openssh_pem_parse(session,
                                privkeyfile, privkeyblob, privkeyblob_len,
                                passphrase, &decrypted);
    if(rc)
        return rc;

    /* We have a new key file, now try and parse it using supported types */
    rc = ssh2_get_string(decrypted, (unsigned char **)&buf, NULL);
    if(rc || !buf) {
        rc = ssh2_err(session, LIBSSH2_ERROR_PROTO,
                      "Public key type in decrypted key data not found");
        goto cleanup;
    }

    rc = LIBSSH2_ERROR_FILE;

    /* Avoid unused variable warnings when all branches below are disabled */
    (void)method;
    (void)pubkeydata;
    (void)pubkeydata_len;

#if LIBSSH2_ED25519
    if(!strcmp("ssh-ed25519", buf) &&
       (!want_method || !strcmp("ssh-ed25519", want_method)))
        rc = ossl_ed25519_openssh_priv_to_pubkey(session, decrypted,
                                                 method,
                                                 pubkeydata, pubkeydata_len,
                                                 (ssh2_ed25519_ctx **)key_ctx);

    if(!strcmp("sk-ssh-ed25519@openssh.com", buf) &&
       (!want_method || !strcmp("sk-ssh-ed25519@openssh.com", want_method)))
        rc = ossl_ed25519_sk_openssh_priv_to_pubkey(session, decrypted,
                                                    method,
                                                    pubkeydata, pubkeydata_len,
                                                    NULL, NULL, NULL, NULL,
                                                 (ssh2_ed25519_ctx **)key_ctx);
#endif
#if LIBSSH2_RSA
    if(!strcmp("ssh-rsa", buf) &&
       (!want_method || !strcmp("ssh-rsa", want_method)))
        rc = ossl_rsa_openssh_priv_to_pubkey(session, decrypted,
                                             method,
                                             pubkeydata, pubkeydata_len,
                                             (ssh2_rsa_ctx **)key_ctx);
#endif
#if LIBSSH2_DSA
    if(!strcmp("ssh-dss", buf) &&
       (!want_method || !strcmp("ssh-dss", want_method)))
        rc = ossl_dsa_openssh_priv_to_pubkey(session, decrypted,
                                             method,
                                             pubkeydata, pubkeydata_len,
                                             (ssh2_dsa_ctx **)key_ctx);
#endif
#if LIBSSH2_ECDSA
    if(!strcmp("sk-ecdsa-sha2-nistp256@openssh.com", buf))
        rc = ossl_ecdsa_sk_openssh_priv_to_pubkey(session, decrypted,
                                                  method,
                                                  pubkeydata, pubkeydata_len,
                                                  NULL, NULL, NULL, NULL,
                                                  (ssh2_ecdsa_ctx **)key_ctx);
    else if(ossl_ecdsa_curve_type_from_name(buf, &type) == 0 &&
            (!want_method || !strcmp("ssh-ecdsa", want_method)))
        rc = ossl_ecdsa_openssh_priv_to_pubkey(session, type, decrypted,
                                               method,
                                               pubkeydata, pubkeydata_len,
                                               (ssh2_ecdsa_ctx **)key_ctx);
#endif

    if(rc == LIBSSH2_ERROR_FILE)
        rc = ssh2_err(session, LIBSSH2_ERROR_FILE,
                      "Unable to extract public key from private key: "
                      "invalid/unrecognized private key format");

cleanup:

    if(decrypted)
        ssh2_string_buf_free(session, decrypted);

    return rc;
}

int ssh2_sk_pubkey(LIBSSH2_SESSION *session, char **method,
                   unsigned char **pubkeydata, size_t *pubkeydata_len,
                   int *algorithm, unsigned char *flags,
                   const char **application,
                   const unsigned char **key_handle, size_t *key_handle_len,
                   const char *privkeyfile,
                   const char *privkeyblob, size_t privkeyblob_len,
                   const char *passphrase)
{
    int rc;
    char *buf = NULL;
    struct string_buf *decrypted = NULL;

    if(!session)
        return LIBSSH2_ERROR_BAD_USE;

    ssh2_deb((session, LIBSSH2_TRACE_AUTH,
              "Computing public key from private key."));

    OSSL_INIT_IF_NEEDED();

    rc = ssh2_openssh_pem_parse(session,
                                privkeyfile, privkeyblob, privkeyblob_len,
                                passphrase, &decrypted);
    if(rc)
        return rc;

    /* We have a new key file, now try and parse it using supported types */
    rc = ssh2_get_string(decrypted, (unsigned char **)&buf, NULL);
    if(rc || !buf) {
        rc = ssh2_err(session, LIBSSH2_ERROR_PROTO,
                      "Public key type in decrypted key data not found");
        goto cleanup;
    }

    rc = LIBSSH2_ERROR_FILE;

    /* Avoid unused variable warnings when all branches below are disabled */
    (void)method;
    (void)pubkeydata;
    (void)pubkeydata_len;
    (void)algorithm;
    (void)flags;
    (void)application;
    (void)key_handle;
    (void)key_handle_len;

#if LIBSSH2_ED25519
    if(!strcmp("sk-ssh-ed25519@openssh.com", buf)) {
        *algorithm = LIBSSH2_HOSTKEY_TYPE_ED25519;
        rc = ossl_ed25519_sk_openssh_priv_to_pubkey(session, decrypted, method,
                                                    pubkeydata,
                                                    pubkeydata_len,
                                                    flags, application,
                                                    key_handle,
                                                    key_handle_len,
                                                    NULL);
    }
#endif
#if LIBSSH2_ECDSA
    if(!strcmp("sk-ecdsa-sha2-nistp256@openssh.com", buf)) {
        *algorithm = LIBSSH2_HOSTKEY_TYPE_ECDSA_256;
        rc = ossl_ecdsa_sk_openssh_priv_to_pubkey(session, decrypted, method,
                                                  pubkeydata,
                                                  pubkeydata_len,
                                                  flags, application,
                                                  key_handle,
                                                  key_handle_len,
                                                  NULL);
    }
#endif

    if(rc == LIBSSH2_ERROR_FILE)
        rc = ssh2_err(session, LIBSSH2_ERROR_FILE,
                      "Unable to extract public key from private key: "
                      "invalid/unrecognized private key format");

cleanup:

    if(decrypted)
        ssh2_string_buf_free(session, decrypted);

    return rc;
}

#ifdef USE_OPENSSL_3
#define HAVE_SSLERROR_BAD_DECRYPT
#endif

int ssh2_pub_privkey(LIBSSH2_SESSION *session, char **method,
                     unsigned char **pubkeydata, size_t *pubkeydata_len,
                     const char *privkeyfile,
                     const char *privkeyblob, size_t privkeyblob_len,
                     const char *passphrase)
{
    int rc;
    BIO *bp;
    EVP_PKEY *pk;
    int pktype;
#ifdef HAVE_SSLERROR_BAD_DECRYPT
    unsigned long sslError;
#endif

    OSSL_INIT_IF_NEEDED();

    if(privkeyfile) {
        ssh2_deb((session, LIBSSH2_TRACE_AUTH,
                  "Computing public key from private key file: %s",
                  privkeyfile));

        bp = BIO_new_file(privkeyfile, "r");
        if(!bp)
            return ssh2_err(session, LIBSSH2_ERROR_FILE,
                            "Unable to open private key file");
    }
    else {
        ssh2_deb((session, LIBSSH2_TRACE_AUTH,
                  "Computing public key from private key."));

        bp = BIO_new_mem_buf(privkeyblob, (int)privkeyblob_len);
        if(!bp)
            return ssh2_err(session, LIBSSH2_ERROR_ALLOC,
                            "Unable to allocate memory when computing "
                            "public key");
    }

    (void)BIO_reset(bp);
    pk = PEM_read_bio_PrivateKey(bp, NULL, NULL, SSH2_UNCONST(passphrase));
#ifdef HAVE_SSLERROR_BAD_DECRYPT
    sslError = ERR_get_error();
#endif
    BIO_free(bp);

    if(!pk) {
        /* Try OpenSSH format */
        if(!ossl_key_from_openssh(session, NULL, NULL, method,
                                  pubkeydata, pubkeydata_len,
                                  privkeyfile,
                                  privkeyblob, privkeyblob_len,
                                  passphrase))
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
                        "Unable to extract public key from private key: "
                        "Unsupported private key format");
    }

    pktype = EVP_PKEY_id(pk);

    switch(pktype) {
#if LIBSSH2_ED25519
    case EVP_PKEY_ED25519:
        rc = ossl_ed25519_evp_to_pubkey(session, method,
                                        pubkeydata, pubkeydata_len, pk);
        break;
#endif /* LIBSSH2_ED25519 */
#if LIBSSH2_RSA
    case EVP_PKEY_RSA:
        rc = ossl_rsa_evp_to_pubkey(session, method,
                                    pubkeydata, pubkeydata_len, pk);
        break;
#endif /* LIBSSH2_RSA */
#if LIBSSH2_DSA
    case EVP_PKEY_DSA:
        rc = ossl_dsa_evp_to_pubkey(session, method,
                                    pubkeydata, pubkeydata_len, pk);
        break;
#endif /* LIBSSH2_DSA */
#if LIBSSH2_ECDSA
    case EVP_PKEY_EC:
        rc = ossl_ecdsa_evp_to_pubkey(session, method,
                                      pubkeydata, pubkeydata_len, 0, pk);
        break;
#endif /* LIBSSH2_ECDSA */
    default:
        rc = ssh2_err(session, LIBSSH2_ERROR_FILE,
                      "Unable to extract public key from private key: "
                      "Unsupported private key format");
        break;
    }

    EVP_PKEY_free(pk);
    return rc;
}

void ssh2_dh_init(ssh2_dh_ctx *dhctx)
{
    *dhctx = BN_new(); /* Random from client */
}

int ssh2_dh_key_pair(ssh2_dh_ctx *dhctx, ssh2_bn *pub, ssh2_bn *g,
                     ssh2_bn *p, int group_order, ssh2_bn_ctx *bnctx)
{
    if(group_order <= 0)
        return -1;

    /* Generate x and e */
    if(!BN_rand(*dhctx, (group_order * 8) - 1, 0, -1) ||
       !BN_mod_exp(pub, g, *dhctx, p, bnctx))
        return -1;
    return 0;
}

int ssh2_dh_validate(ssh2_bn *f, ssh2_bn *p)
{
    BIGNUM *tmp;
    int n, i, bits_set;

    if(BN_cmp(f, BN_value_one()) != 1)
        return -1;  /* f <= 1 */

    tmp = BN_new();
    if(!tmp)
        return -4;
    if(!BN_sub(tmp, p, BN_value_one())) {
        BN_clear_free(tmp);
        return -4;
    }
    if(BN_cmp(f, tmp) != -1) {
        BN_clear_free(tmp);
        return -2;  /* f >= p - 1 (== f > p - 2) */
    }
    BN_clear_free(tmp);

    for(i = 0, n = BN_num_bits(f), bits_set = 0; i < n; ++i)
        if(BN_is_bit_set(f, i))
            ++bits_set;

    if(bits_set < 4)
        return -3;

    return 0;
}

int ssh2_dh_secret(ssh2_dh_ctx *dhctx, ssh2_bn *secret, ssh2_bn *f,
                   ssh2_bn *p, ssh2_bn_ctx *bnctx)
{
    if(ssh2_dh_validate(f, p))  /* Verify if parameters are valid */
        return -1;

    /* Compute the shared secret */
    if(!BN_mod_exp(secret, f, *dhctx, p, bnctx))
        return -1;
    return 0;
}

void ssh2_dh_dtor(ssh2_dh_ctx *dhctx)
{
    BN_clear_free(*dhctx);
    *dhctx = NULL;
}

#endif /* LIBSSH2_OPENSSL || LIBSSH2_WOLFSSL */
