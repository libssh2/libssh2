/* Copyright (C) Simon Josefsson
 * Copyright (C) The Written Word, Inc.
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

#ifdef LIBSSH2_LIBGCRYPT

int ssh2_hash_init(ssh2_hash_ctx *ctx, ssh2_hash_alg alg)
{
    return gcry_md_open(ctx, alg, 0) == GPG_ERR_NO_ERROR;
}

int ssh2_hash_update(ssh2_hash_ctx *ctx, const void *input, size_t input_len)
{
    gcry_md_write(*ctx, input, input_len);
    return 1;
}

int ssh2_hash_final(ssh2_hash_ctx *ctx, void *digest, size_t digest_len)
{
    int ret = ssh2_hmac_final(ctx, digest, digest_len);
    gcry_md_close(*ctx);
    return ret;
}

int ssh2_hmac_ctx_init(ssh2_hmac_ctx *ctx)
{
    *ctx = NULL;
    return 1;
}

int ssh2_hmac_init(ssh2_hmac_ctx *ctx, ssh2_hmac_alg alg,
                   void *key, size_t key_len)
{
    gcry_error_t err;
    err = gcry_md_open(ctx, alg, GCRY_MD_FLAG_HMAC);
    if(gcry_err_code(err) != GPG_ERR_NO_ERROR)
        return 0;
    err = gcry_md_setkey(*ctx, key, key_len);
    if(gcry_err_code(err) != GPG_ERR_NO_ERROR)
        return 0;
    return 1;
}

int ssh2_hmac_update(ssh2_hmac_ctx *ctx, const void *input, size_t input_len)
{
    gcry_md_write(*ctx, input, input_len);
    return 1;
}

int ssh2_hmac_final(ssh2_hmac_ctx *ctx, void *mac, size_t mac_len)
{
    int ret = 0;
    unsigned int actual_len = gcry_md_get_algo_dlen(gcry_md_get_algo(*ctx));
    if(mac_len >= actual_len) {
        unsigned char *res = gcry_md_read(*ctx, 0);
        if(res) {
            memcpy(mac, res, actual_len);
            ret = 1;
        }
    }
    return ret;
}

void ssh2_hmac_cleanup(ssh2_hmac_ctx *ctx)
{
    gcry_md_close(*ctx);
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
    int rc;

    (void)e1data;
    (void)e1len;
    (void)e2data;
    (void)e2len;

    if(ddata)
        rc = gcry_sexp_build(rsa, NULL,
                 "(private-key(rsa(n%b)(e%b)(d%b)(q%b)(p%b)(u%b)))",
                 (int)nlen, ndata, (int)elen, edata, (int)dlen, ddata,
                 (int)plen, pdata, (int)qlen, qdata, (int)coefflen, coeffdata);
    else
        rc = gcry_sexp_build(rsa, NULL, "(public-key(rsa(n%b)(e%b)))",
                             (int)nlen, ndata, (int)elen, edata);

    if(rc) {
        *rsa = NULL;
        return -1;
    }

    return 0;
}

int ssh2_rsa_sha2_verify(ssh2_rsa_ctx *rsa,
                         size_t hash_len,
                         const unsigned char *sig, size_t sig_len,
                         const unsigned char *m, size_t m_len)
{
    unsigned char *hash;
    int ret;
    const char *algo = NULL;
    gcry_sexp_t s_hash = NULL;
    gcry_sexp_t s_sig = NULL;

    hash = malloc(hash_len);
    if(!hash)
        return -1;

    if(hash_len == SSH2_SHA1_DIG_LEN) {
        gcry_md_hash_buffer(GCRY_MD_SHA1, hash, m, m_len);
        algo = "sha1";
        ret = 0;
    }
    else if(hash_len == SSH2_SHA256_DIG_LEN) {
        gcry_md_hash_buffer(GCRY_MD_SHA256, hash, m, m_len);
        algo = "sha256";
        ret = 0;
    }
    else if(hash_len == SSH2_SHA512_DIG_LEN) {
        gcry_md_hash_buffer(GCRY_MD_SHA512, hash, m, m_len);
        algo = "sha512";
        ret = 0;
    }
    else
        ret = 1;

    if(ret) {
        ret = -1;
        goto out;
    }

    if(gcry_sexp_build(&s_hash, NULL,
                       "(data (flags pkcs1) (hash %s %b))",
                       algo, hash_len, hash)) {
        ret = -1;
        goto out;
    }

    if(gcry_sexp_build(&s_sig, NULL, "(sig-val(rsa(s %b)))", sig_len, sig)) {
        ret = -1;
        goto out;
    }

    ret = (gcry_pk_verify(s_sig, s_hash, rsa) == 0) ? 0 : -1;

out:
    if(s_sig)
        gcry_sexp_release(s_sig);
    if(s_hash)
        gcry_sexp_release(s_hash);
    if(hash)
        free(hash);

    return ret;
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
#endif

#if LIBSSH2_DSA
int ssh2_dsa_new(ssh2_dsa_ctx **dsa,
                 const unsigned char *pdata, size_t plen,
                 const unsigned char *qdata, size_t qlen,
                 const unsigned char *gdata, size_t glen,
                 const unsigned char *ydata, size_t ylen,
                 const unsigned char *xdata, size_t xlen)
{
    int rc;

    if(xlen)
        rc = gcry_sexp_build(dsa, NULL,
                             "(private-key(dsa(p%b)(q%b)(g%b)(y%b)(x%b)))",
                             (int)plen, pdata, (int)qlen, qdata,
                             (int)glen, gdata, (int)ylen, ydata,
                             (int)xlen, xdata);
    else
        rc = gcry_sexp_build(dsa, NULL,
                             "(public-key(dsa(p%b)(q%b)(g%b)(y%b)))",
                             (int)plen, pdata, (int)qlen, qdata,
                             (int)glen, gdata, (int)ylen, ydata);

    if(rc) {
        *dsa = NULL;
        return -1;
    }

    return 0;
}
#endif

#if LIBSSH2_RSA
int ssh2_rsa_new_priv(ssh2_rsa_ctx **rsa,
                      LIBSSH2_SESSION *session,
                      const char *filename,
                      const char *blob, size_t blob_len,
                      const char *passphrase)
{
    FILE *fp;
    unsigned char *data, *save_data;
    size_t datalen;
    int ret;
    unsigned char *n, *e, *d, *p, *q, *e1, *e2, *coeff;
    unsigned int nlen, elen, dlen, plen, qlen, e1len, e2len, coefflen;

    if(filename) {
        fp = ssh2_fopen(filename, "rb");
        if(!fp)
            return -1;
        ret = ssh2_pem_parse_FILE(session, PEM_RSA_HEADER, PEM_RSA_FOOTER,
                                  fp, passphrase,
                                  &data, &datalen);
        fclose(fp);
    }
    else
        ret = ssh2_pem_parse_blob(session, PEM_RSA_HEADER, PEM_RSA_FOOTER,
                                  blob, blob_len, passphrase,
                                  &data, &datalen);
    if(ret)
        return -1;

    save_data = data;

    if(ssh2_pem_decode_sequence(&data, &datalen)) {
        ret = -1;
        goto fail;
    }

    /* First read Version field (should be 0). */
    ret = ssh2_pem_decode_integer(&data, &datalen, &n, &nlen);
    if(ret || (nlen != 1 && *n != '\0')) {
        ret = -1;
        goto fail;
    }

    ret = ssh2_pem_decode_integer(&data, &datalen, &n, &nlen);
    if(ret) {
        ret = -1;
        goto fail;
    }

    ret = ssh2_pem_decode_integer(&data, &datalen, &e, &elen);
    if(ret) {
        ret = -1;
        goto fail;
    }

    ret = ssh2_pem_decode_integer(&data, &datalen, &d, &dlen);
    if(ret) {
        ret = -1;
        goto fail;
    }

    ret = ssh2_pem_decode_integer(&data, &datalen, &p, &plen);
    if(ret) {
        ret = -1;
        goto fail;
    }

    ret = ssh2_pem_decode_integer(&data, &datalen, &q, &qlen);
    if(ret) {
        ret = -1;
        goto fail;
    }

    ret = ssh2_pem_decode_integer(&data, &datalen, &e1, &e1len);
    if(ret) {
        ret = -1;
        goto fail;
    }

    ret = ssh2_pem_decode_integer(&data, &datalen, &e2, &e2len);
    if(ret) {
        ret = -1;
        goto fail;
    }

    ret = ssh2_pem_decode_integer(&data, &datalen, &coeff, &coefflen);
    if(ret) {
        ret = -1;
        goto fail;
    }

    if(ssh2_rsa_new(rsa, e, elen, n, nlen, d, dlen, p, plen,
                    q, qlen, e1, e1len, e2, e2len, coeff, coefflen)) {
        ret = -1;
        goto fail;
    }

    ret = 0;

fail:
    SSH2_FREE(session, save_data);
    return ret;
}
#endif

#if LIBSSH2_DSA
int ssh2_dsa_new_priv(ssh2_dsa_ctx **dsa,
                      LIBSSH2_SESSION *session,
                      const char *filename,
                      const char *blob, size_t blob_len,
                      const char *passphrase)
{
    FILE *fp;
    unsigned char *data, *save_data;
    size_t datalen;
    int ret;
    unsigned char *p, *q, *g, *y, *x;
    unsigned int plen, qlen, glen, ylen, xlen;

    if(filename) {
        fp = ssh2_fopen(filename, "rb");
        if(!fp)
            return -1;

        ret = ssh2_pem_parse_FILE(session, PEM_DSA_HEADER, PEM_DSA_FOOTER,
                                  fp, passphrase,
                                  &data, &datalen);
        fclose(fp);
    }
    else
        ret = ssh2_pem_parse_blob(session, PEM_DSA_HEADER, PEM_DSA_FOOTER,
                                  blob, blob_len, passphrase,
                                  &data, &datalen);
    if(ret)
        return -1;

    save_data = data;

    if(ssh2_pem_decode_sequence(&data, &datalen)) {
        ret = -1;
        goto fail;
    }

    /* First read Version field (should be 0). */
    ret = ssh2_pem_decode_integer(&data, &datalen, &p, &plen);
    if(ret || (plen != 1 && *p != '\0')) {
        ret = -1;
        goto fail;
    }

    ret = ssh2_pem_decode_integer(&data, &datalen, &p, &plen);
    if(ret) {
        ret = -1;
        goto fail;
    }

    ret = ssh2_pem_decode_integer(&data, &datalen, &q, &qlen);
    if(ret) {
        ret = -1;
        goto fail;
    }

    ret = ssh2_pem_decode_integer(&data, &datalen, &g, &glen);
    if(ret) {
        ret = -1;
        goto fail;
    }

    ret = ssh2_pem_decode_integer(&data, &datalen, &y, &ylen);
    if(ret) {
        ret = -1;
        goto fail;
    }

    ret = ssh2_pem_decode_integer(&data, &datalen, &x, &xlen);
    if(ret) {
        ret = -1;
        goto fail;
    }

    if(datalen) {
        ret = -1;
        goto fail;
    }

    if(ssh2_dsa_new(dsa, p, plen, q, qlen, g, glen, y, ylen, x, xlen)) {
        ret = -1;
        goto fail;
    }

    ret = 0;

fail:
    SSH2_FREE(session, save_data);
    return ret;
}
#endif

#if LIBSSH2_RSA
int ssh2_rsa_sha2_sign(ssh2_rsa_ctx *rsa, LIBSSH2_SESSION *session,
                       const unsigned char *hash, size_t hash_len,
                       unsigned char **signature, size_t *signature_len)
{
    const char *algo;
    gcry_sexp_t s_tmp = NULL;
    gcry_sexp_t s_sig = NULL;
    gcry_error_t err;
    const char *s;
    size_t size;
    unsigned char *out_sig;
    int ret = -1;

    if(hash_len == SSH2_SHA1_DIG_LEN)
        algo = "sha1";
    else if(hash_len == SSH2_SHA256_DIG_LEN)
        algo = "sha256";
    else if(hash_len == SSH2_SHA512_DIG_LEN)
        algo = "sha512";
    else {
        ssh2_err(session, LIBSSH2_ERROR_PROTO,
                 "Unsupported hash digest length");
        return -1;
    }

    if(gcry_sexp_build(&s_tmp, NULL,
                       "(data (flags pkcs1) (hash %s %b))",
                       algo, hash_len, hash))
        return -1;

    err = gcry_pk_sign(&s_sig, s_tmp, rsa);
    gcry_sexp_release(s_tmp);
    if(err)
        return -1;

    s_tmp = gcry_sexp_find_token(s_sig, "s", 0);
    if(!s_tmp)
        goto out;

    s = gcry_sexp_nth_data(s_tmp, 1, &size);
    if(!s)
        goto out;

    if(size && s[0] == '\0') {
        ++s;
        --size;
    }

    out_sig = SSH2_ALLOC(session, size);
    if(!out_sig)
        goto out;
    memcpy(out_sig, s, size);

    *signature = out_sig;
    *signature_len = size;
    ret = 0;

out:
    if(s_tmp)
        gcry_sexp_release(s_tmp);
    if(s_sig)
        gcry_sexp_release(s_sig);

    return ret;
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
    unsigned char zhash[SSH2_SHA1_DIG_LEN + 1];
    gcry_sexp_t sig_sexp;
    gcry_sexp_t data;
    int ret;
    const char *tmp;
    size_t size;

    if(hash_len != SSH2_SHA1_DIG_LEN)
        return -1;

    memcpy(zhash + 1, hash, hash_len);
    zhash[0] = 0;

    if(gcry_sexp_build(&data, NULL, "(data (value %b))",
                       (int)(hash_len + 1), zhash))
        return -1;

    ret = gcry_pk_sign(&sig_sexp, data, dsa);

    gcry_sexp_release(data);

    if(ret)
        return -1;

    memset(signature, 0, 40);

    /* Extract R. */

    data = gcry_sexp_find_token(sig_sexp, "r", 0);
    if(!data)
        goto err;

    tmp = gcry_sexp_nth_data(data, 1, &size);
    if(!tmp)
        goto err;

    if(tmp[0] == '\0') {
        tmp++;
        size--;
    }

    if(size < 1 || size > 20)
        goto err;

    memcpy(signature + (20 - size), tmp, size);

    gcry_sexp_release(data);

    /* Extract S. */

    data = gcry_sexp_find_token(sig_sexp, "s", 0);
    if(!data)
        goto err;

    tmp = gcry_sexp_nth_data(data, 1, &size);
    if(!tmp)
        goto err;

    if(tmp[0] == '\0') {
        tmp++;
        size--;
    }

    if(size < 1 || size > 20)
        goto err;

    memcpy(signature + 20 + (20 - size), tmp, size);
    goto out;

err:
    ret = -1;

out:
    if(sig_sexp)
        gcry_sexp_release(sig_sexp);
    if(data)
        gcry_sexp_release(data);
    return ret;
}

int ssh2_dsa_sha1_verify(ssh2_dsa_ctx *dsa,
                         const unsigned char *sig,
                         const unsigned char *m, size_t m_len)
{
    unsigned char hash[SSH2_SHA1_DIG_LEN + 1];
    gcry_sexp_t s_sig, s_hash;
    int rc = -1;

    gcry_md_hash_buffer(GCRY_MD_SHA1, hash + 1, m, m_len);

    hash[0] = 0;

    if(gcry_sexp_build(&s_hash, NULL, "(data(flags raw)(value %b))",
                       SSH2_SHA1_DIG_LEN + 1, hash))
        return -1;

    if(gcry_sexp_build(&s_sig, NULL, "(sig-val(dsa(r %b)(s %b)))",
                       20, sig, 20, sig + 20)) {
        gcry_sexp_release(s_hash);
        return -1;
    }

    rc = gcry_pk_verify(s_sig, s_hash, dsa);
    gcry_sexp_release(s_sig);
    gcry_sexp_release(s_hash);

    return rc == 0 ? 0 : -1;
}
#endif

int ssh2_cipher_init(ssh2_cipher_ctx *ctx, SSH2_CIPHER_T(algo),
                     unsigned char *iv, unsigned char *secret, int encrypt)
{
    int ret;
    int cipher = LGCR_CIPHER(algo);
    int mode = LGCR_MODE(algo);
    size_t keylen = gcry_cipher_get_algo_keylen(cipher);

    (void)encrypt;

    ret = gcry_cipher_open(ctx, cipher, mode, 0);
    if(ret)
        return -1;

    ret = gcry_cipher_setkey(*ctx, secret, keylen);
    if(ret) {
        gcry_cipher_close(*ctx);
        return -1;
    }

    if(mode != GCRY_CIPHER_MODE_STREAM) {
        size_t blklen = gcry_cipher_get_algo_blklen(cipher);
        if(mode == GCRY_CIPHER_MODE_CTR)
            ret = gcry_cipher_setctr(*ctx, iv, blklen);
        else
            ret = gcry_cipher_setiv(*ctx, iv, blklen);
        if(ret) {
            gcry_cipher_close(*ctx);
            return -1;
        }
    }

    return 0;
}

int ssh2_cipher_crypt(ssh2_cipher_ctx *ctx,
                      SSH2_CIPHER_T(algo),
                      int encrypt, unsigned char *block, size_t blocksize,
                      int firstlast)
{
    int ret;

    (void)algo;
    (void)firstlast;

    if(encrypt)
        ret = gcry_cipher_encrypt(*ctx, block, blocksize, block, blocksize);
    else
        ret = gcry_cipher_decrypt(*ctx, block, blocksize, block, blocksize);
    return ret;
}

int ssh2_pub_privkey(LIBSSH2_SESSION *session,
                     char **method,
                     unsigned char **pubkeydata, size_t *pubkeydata_len,
                     const char *privatekey,
                     const char *privkeyblob, size_t privkeyblob_len,
                     const char *passphrase)
{
    (void)method;
    (void)pubkeydata;
    (void)pubkeydata_len;
    (void)privatekey;
    (void)privkeyblob;
    (void)privkeyblob_len;
    (void)passphrase;

    return ssh2_err(session, LIBSSH2_ERROR_METHOD_NOT_SUPPORTED,
                    "Unable to extract public key from private key: "
                    "Method unimplemented in libgcrypt backend");
}

void ssh2_dh_init(ssh2_dh_ctx *dhctx)
{
    *dhctx = gcry_mpi_new(0);                   /* Random from client */
}

int ssh2_dh_key_pair(ssh2_dh_ctx *dhctx, ssh2_bn *pub, ssh2_bn *g,
                     ssh2_bn *p, int group_order, ssh2_bn_ctx *bnctx)
{
    (void)bnctx;

    if(group_order <= 0)
        return -1;

    /* Generate x and e */
    gcry_mpi_randomize(*dhctx, (group_order * 8) - 1, GCRY_VERY_STRONG_RANDOM);
    gcry_mpi_powm(pub, g, *dhctx, p);
    return 0;
}

int ssh2_dh_is_valid(ssh2_bn *f, ssh2_bn *p)
{
    gcry_mpi_t tmp;
    unsigned int n, i, bits_set;

    if(gcry_mpi_cmp_ui(f, 1) <= 0)
        return -1;  /* f <= 1 */

    tmp = gcry_mpi_new(0);
    if(!tmp)
        return -4;
    gcry_mpi_sub_ui(tmp, p, 1);
    if(gcry_mpi_cmp(f, tmp) >= 0) {
        gcry_mpi_release(tmp);
        return -2;  /* f >= p - 1 (== f > p - 2) */
    }
    gcry_mpi_release(tmp);

    for(i = 0, n = gcry_mpi_get_nbits(f), bits_set = 0; i < n; ++i)
        if(gcry_mpi_test_bit(f, i))
            ++bits_set;

    if(bits_set < 4)
        return -3;

    return 0;
}

int ssh2_dh_secret(ssh2_dh_ctx *dhctx, ssh2_bn *secret, ssh2_bn *f,
                   ssh2_bn *p, ssh2_bn_ctx *bnctx)
{
    (void)bnctx;

    if(ssh2_dh_is_valid(f, p))  /* Verify if parameters are valid */
        return -1;

    /* Compute the shared secret */
    gcry_mpi_powm(secret, f, *dhctx, p);
    return 0;
}

void ssh2_dh_dtor(ssh2_dh_ctx *dhctx)
{
    gcry_mpi_release(*dhctx);
    *dhctx = NULL;
}

#endif /* LIBSSH2_LIBGCRYPT */
