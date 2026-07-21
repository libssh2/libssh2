/* Copyright (C) Art <https://github.com/wildart>
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

#ifdef LIBSSH2_MBEDTLS

#include <stdlib.h>

/*******************************************************************/
/*
 * mbedTLS backend: Global context handles
 */

#if MBEDTLS_VERSION_NUMBER < 0x04000000
static mbedtls_entropy_context mbed_entropy;
static mbedtls_ctr_drbg_context mbed_ctr_drbg;
#endif

/*******************************************************************/
/*
 * mbedTLS backend: Generic functions
 */

void ssh2_crypto_init(void)
{
    (void)psa_crypto_init();

#if MBEDTLS_VERSION_NUMBER < 0x04000000
    mbedtls_entropy_init(&mbed_entropy);
    mbedtls_ctr_drbg_init(&mbed_ctr_drbg);

    if(mbedtls_ctr_drbg_seed(&mbed_ctr_drbg,
                             mbedtls_entropy_func,
                             &mbed_entropy, NULL, 0))
        mbedtls_ctr_drbg_free(&mbed_ctr_drbg);
#endif
}

void ssh2_crypto_exit(void)
{
    mbedtls_psa_crypto_free();

#if MBEDTLS_VERSION_NUMBER < 0x04000000
    mbedtls_ctr_drbg_free(&mbed_ctr_drbg);
    mbedtls_entropy_free(&mbed_entropy);
#endif
}

int ssh2_random(unsigned char *buf, size_t len)
{
    return psa_generate_random(buf, len) == PSA_SUCCESS ? 0 : -1;
}

static void mbed_zero_free(void *buf, size_t len)
{
    if(!buf)
        return;

    if(len > 0)
        ssh2_explicit_zero(buf, len);

    mbedtls_free(buf);
}

int ssh2_cipher_init(ssh2_cipher_ctx *ctx, SSH2_CIPHER_T(algo),
                     unsigned char *iv, unsigned char *secret, int encrypt)
{
    const mbedtls_cipher_info_t *cipher_info;
    mbedtls_operation_t op;
    int ret;

    if(!ctx)
        return -1;

    op = encrypt ? MBEDTLS_ENCRYPT : MBEDTLS_DECRYPT;

    cipher_info = mbedtls_cipher_info_from_type(algo);
    if(!cipher_info)
        return -1;

    mbedtls_cipher_init(ctx);
    ret = mbedtls_cipher_setup(ctx, cipher_info);

    /* libssh2 computes and adds SSH packet padding itself, so for CBC
       tell mbedTLS to expect no padding on the cipher layer. Only call
       set_padding_mode for CBC ciphers since other modes (CTR, stream)
       are not applicable and causes an error. */
    if(!ret &&
       (algo == MBEDTLS_CIPHER_AES_128_CBC ||
        algo == MBEDTLS_CIPHER_AES_192_CBC ||
        algo == MBEDTLS_CIPHER_AES_256_CBC
#if LIBSSH2_3DES
        || algo == MBEDTLS_CIPHER_DES_EDE3_CBC
#endif
       )
      ) {
        ret = mbedtls_cipher_set_padding_mode(ctx, MBEDTLS_PADDING_NONE);
    }

    if(!ret)
        ret = mbedtls_cipher_setkey(ctx,
                  secret,
                  (int)mbedtls_cipher_info_get_key_bitlen(cipher_info), op);

    if(!ret)
        ret = mbedtls_cipher_set_iv(ctx, iv,
                  mbedtls_cipher_info_get_iv_size(cipher_info));

    return ret == 0 ? 0 : -1;
}

int ssh2_cipher_crypt(ssh2_cipher_ctx *ctx, SSH2_CIPHER_T(algo),
                      int encrypt, unsigned char *block, size_t blocksize,
                      int firstlast)
{
    int ret;
    unsigned char *output;
    size_t osize;

    (void)encrypt;
    (void)algo;
    (void)firstlast;

    osize = blocksize + mbedtls_cipher_get_block_size(ctx);

    output = mbedtls_calloc(osize, sizeof(char));
    if(output) {
        size_t olen = 0, finish_olen = 0;

        ret = mbedtls_cipher_reset(ctx);

        if(!ret)
            ret = mbedtls_cipher_update(ctx, block, blocksize, output, &olen);

        if(!ret)
            ret = mbedtls_cipher_finish(ctx, output + olen, &finish_olen);

        if(!ret) {
            olen += finish_olen;
            memcpy(block, output, olen);
        }

        mbed_zero_free(output, osize);
    }
    else
        ret = -1;

    return ret == 0 ? 0 : -1;
}

int ssh2_hash_init(ssh2_hash_ctx *ctx, ssh2_hash_alg alg)
{
    *ctx = psa_hash_operation_init();
    return psa_hash_setup(ctx, alg) == PSA_SUCCESS;
}

int ssh2_hash_final(ssh2_hash_ctx *ctx, void *digest, size_t digest_len)
{
    size_t actual_len;
    return psa_hash_finish(ctx, digest, digest_len,
                           &actual_len) == PSA_SUCCESS;
}

int ssh2_hmac_ctx_init(ssh2_hmac_ctx *ctx)
{
    ctx->mac = psa_mac_operation_init();
    ctx->key_id = PSA_KEY_ID_NULL;
    return 1;
}

int ssh2_hmac_init(ssh2_hmac_ctx *ctx, ssh2_hmac_alg alg,
                   void *key, size_t key_len)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_algorithm_t alg_hmac = PSA_ALG_HMAC(alg);

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attributes, alg_hmac);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_HMAC);

    if(psa_import_key(&attributes, key, key_len, &ctx->key_id) != PSA_SUCCESS)
        return 0;

    if(psa_mac_sign_setup(&ctx->mac, ctx->key_id, alg_hmac) != PSA_SUCCESS) {
        ssh2_hmac_cleanup(ctx);
        return 0;
    }

    return 1;
}

int ssh2_hmac_final(ssh2_hmac_ctx *ctx, void *mac, size_t mac_len)
{
    size_t actual_len;
    return psa_mac_sign_finish(&ctx->mac, mac, mac_len,
                               &actual_len) == PSA_SUCCESS;
}

void ssh2_hmac_cleanup(ssh2_hmac_ctx *ctx)
{
    (void)psa_mac_abort(&ctx->mac);
    psa_destroy_key(ctx->key_id);
    ctx->key_id = PSA_KEY_ID_NULL;
}

/*******************************************************************/
/*
 * mbedTLS backend: BigNumber functions
 */

ssh2_bn *ssh2_bn_init(void)
{
    ssh2_bn *bignum;

    bignum = mbedtls_calloc(1, sizeof(ssh2_bn));
    if(bignum)
        mbedtls_mpi_init(bignum);

    return bignum;
}

void ssh2_bn_free(ssh2_bn *bn)
{
    if(bn) {
        mbedtls_mpi_free(bn);
        mbedtls_free(bn);
    }
}

static int mbed_bn_random(ssh2_bn *bn, int bits, int top, int bottom)
{
    size_t len;
    size_t i;

    if(!bn || bits <= 0)
        return -1;

    len = (bits + 7) >> 3;
    if(mbedtls_mpi_fill_random(bn, len,
                               mbedtls_ctr_drbg_random, &mbed_ctr_drbg))
        return -1;

    /* Zero unused bits above the most significant bit */
    for(i = (len * 8) - 1; (size_t)bits <= i; --i)
        if(mbedtls_mpi_set_bit(bn, i, 0))
            return -1;

    /* If `top` is -1, the most significant bit of the random number can be
       zero.  If top is 0, the most significant bit of the random number is
       set to 1, and if top is 1, the two most significant bits of the number
       is set to 1, so that the product of two such random numbers always
       have 2 * bits length. */
    if(top >= 0)
        for(i = 0; i <= (size_t)top; ++i)
            if(mbedtls_mpi_set_bit(bn, bits - i - 1, 1))
                return -1;

    /* make odd by setting first bit in least significant byte */
    if(bottom && mbedtls_mpi_set_bit(bn, 0, 1))
        return -1;

    return 0;
}

/*******************************************************************/
/*
 * mbedTLS backend: RSA functions
 */

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
    int ret;
    ssh2_rsa_ctx *ctx;

    ctx = mbedtls_calloc(1, sizeof(ssh2_rsa_ctx));
    if(!ctx)
        return -1;

    mbedtls_rsa_init(ctx);

    ret = 0;
    if(mbedtls_mpi_read_binary(&(ctx->MBEDTLS_PRIVATE(E)), edata, elen) ||
       mbedtls_mpi_read_binary(&(ctx->MBEDTLS_PRIVATE(N)), ndata, nlen))
        ret = -1;

    if(!ret)
        ctx->MBEDTLS_PRIVATE(len) =
            mbedtls_mpi_size(&(ctx->MBEDTLS_PRIVATE(N)));

    if(!ret && ddata) {
        if(mbedtls_mpi_read_binary(&(ctx->MBEDTLS_PRIVATE(D)),
                                   ddata, dlen) ||
           mbedtls_mpi_read_binary(&(ctx->MBEDTLS_PRIVATE(P)),
                                   pdata, plen) ||
           mbedtls_mpi_read_binary(&(ctx->MBEDTLS_PRIVATE(Q)),
                                   qdata, qlen) ||
           mbedtls_mpi_read_binary(&(ctx->MBEDTLS_PRIVATE(DP)),
                                   e1data, e1len) ||
           mbedtls_mpi_read_binary(&(ctx->MBEDTLS_PRIVATE(DQ)),
                                   e2data, e2len) ||
           mbedtls_mpi_read_binary(&(ctx->MBEDTLS_PRIVATE(QP)),
                                   coeffdata, coefflen)) {
            ret = -1;
        }
        else
            ret = mbedtls_rsa_check_privkey(ctx);
    }
    else if(!ret)
        ret = mbedtls_rsa_check_pubkey(ctx);

    if(ret && ctx) {
        ssh2_rsa_free(ctx);
        ctx = NULL;
    }
    *rsa = ctx;
    return ret;
}

int ssh2_rsa_new_priv_from_file(ssh2_rsa_ctx **rsa,
                                LIBSSH2_SESSION *session,
                                const char *filename,
                                const char *passphrase)
{
    int ret;
    mbedtls_pk_context pkey;
    mbedtls_rsa_context *pk_rsa;

    (void)session;

    *rsa = mbedtls_calloc(1, sizeof(ssh2_rsa_ctx));
    if(!*rsa)
        return -1;

    mbedtls_rsa_init(*rsa);
    mbedtls_pk_init(&pkey);

    ret = mbedtls_pk_parse_keyfile(&pkey, filename, passphrase,
                                   mbedtls_ctr_drbg_random, &mbed_ctr_drbg);
    if(ret || mbedtls_pk_get_type(&pkey) != MBEDTLS_PK_RSA) {
        mbedtls_pk_free(&pkey);
        ssh2_rsa_free(*rsa);
        *rsa = NULL;
        return -1;
    }

    pk_rsa = mbedtls_pk_rsa(pkey);
    mbedtls_rsa_copy(*rsa, pk_rsa);
    mbedtls_pk_free(&pkey);

    return 0;
}

int ssh2_rsa_new_priv_from_blob(ssh2_rsa_ctx **rsa,
                                LIBSSH2_SESSION *session,
                                const char *blob, size_t blob_len,
                                const char *passphrase)
{
    int ret;
    mbedtls_pk_context pkey;
    mbedtls_rsa_context *pk_rsa;
    unsigned char *data_nullterm;

    (void)session;

    *rsa = mbedtls_calloc(1, sizeof(ssh2_rsa_ctx));
    if(!*rsa)
        return -1;

    mbedtls_rsa_init(*rsa);

    /* mbedtls checks in "mbedtls/pkparse.c:1184" if "key[keylen - 1] != '\0'"
       private-key from memory fails if the last byte is not a null byte */
    data_nullterm = mbedtls_calloc(blob_len + 1, 1);
    if(!data_nullterm) {
        ssh2_rsa_free(*rsa);
        *rsa = NULL;
        return -1;
    }

    memcpy(data_nullterm, blob, blob_len);
    data_nullterm[blob_len] = 0;

    mbedtls_pk_init(&pkey);

    ret = mbedtls_pk_parse_key(&pkey, data_nullterm, blob_len + 1,
                               (const unsigned char *)passphrase,
                               passphrase ? strlen(passphrase) : 0,
                               mbedtls_ctr_drbg_random, &mbed_ctr_drbg);
    mbed_zero_free(data_nullterm, blob_len + 1);

    if(ret || mbedtls_pk_get_type(&pkey) != MBEDTLS_PK_RSA) {
        mbedtls_pk_free(&pkey);
        ssh2_rsa_free(*rsa);
        *rsa = NULL;
        return -1;
    }

    pk_rsa = mbedtls_pk_rsa(pkey);
    mbedtls_rsa_copy(*rsa, pk_rsa);
    mbedtls_pk_free(&pkey);

    return 0;
}

int ssh2_rsa_sha2_verify(ssh2_rsa_ctx *rsa, size_t hash_len,
                         const unsigned char *sig, size_t sig_len,
                         const unsigned char *m, size_t m_len)
{
    int ret;
    size_t actual_len;
    mbedtls_md_type_t md_type;
    unsigned char *hash;

    if(sig_len < mbedtls_rsa_get_len(rsa))
        return -1;

    hash = malloc(hash_len);
    if(!hash)
        return -1;

    if(hash_len == SSH2_SHA1_DIG_LEN) {
        ret = psa_hash_compute(PSA_ALG_SHA_1, m, m_len, hash, hash_len,
                               &actual_len) == PSA_SUCCESS ? 0 : -1;
        md_type = MBEDTLS_MD_SHA1;
    }
    else if(hash_len == SSH2_SHA256_DIG_LEN) {
        ret = psa_hash_compute(PSA_ALG_SHA_256, m, m_len, hash, hash_len,
                               &actual_len) == PSA_SUCCESS ? 0 : -1;
        md_type = MBEDTLS_MD_SHA256;
    }
    else if(hash_len == SSH2_SHA512_DIG_LEN) {
        ret = psa_hash_compute(PSA_ALG_SHA_512, m, m_len, hash, hash_len,
                               &actual_len) == PSA_SUCCESS ? 0 : -1;
        md_type = MBEDTLS_MD_SHA512;
    }
    else {
        free(hash);
        return -1; /* unsupported digest */
    }

    if(ret) {
        free(hash);
        return -1; /* failure */
    }

    ret = mbedtls_rsa_pkcs1_verify(rsa,
                                   md_type, (unsigned int)hash_len,
                                   hash, sig);
    free(hash);

    return ret == 0 ? 0 : -1;
}

int ssh2_rsa_sha1_verify(ssh2_rsa_ctx *rsa,
                         const unsigned char *sig, size_t sig_len,
                         const unsigned char *m, size_t m_len)
{
    return ssh2_rsa_sha2_verify(rsa, SSH2_SHA1_DIG_LEN,
                                sig, sig_len, m, m_len);
}

int ssh2_rsa_sha2_sign(ssh2_rsa_ctx *rsa, LIBSSH2_SESSION *session,
                       const unsigned char *hash, size_t hash_len,
                       unsigned char **signature, size_t *signature_len)
{
    int ret;
    unsigned char *sig;
    size_t sig_len;
    mbedtls_md_type_t md_type;

    sig_len = mbedtls_rsa_get_len(rsa);
    sig = SSH2_ALLOC(session, sig_len);
    if(!sig)
        return -1;

    ret = 0;
    if(hash_len == SSH2_SHA1_DIG_LEN)
        md_type = MBEDTLS_MD_SHA1;
    else if(hash_len == SSH2_SHA256_DIG_LEN)
        md_type = MBEDTLS_MD_SHA256;
    else if(hash_len == SSH2_SHA512_DIG_LEN)
        md_type = MBEDTLS_MD_SHA512;
    else {
        ssh2_err(session, LIBSSH2_ERROR_PROTO,
                 "Unsupported hash digest length");
        md_type = MBEDTLS_MD_NONE;
        ret = -1;
    }
    if(ret == 0)
        ret = mbedtls_rsa_pkcs1_sign(rsa,
                                     mbedtls_ctr_drbg_random, &mbed_ctr_drbg,
                                     md_type, (unsigned int)hash_len,
                                     hash, sig);
    if(ret) {
        SSH2_FREE(session, sig);
        return -1;
    }

    *signature = sig;
    *signature_len = sig_len;

    return ret == 0 ? 0 : -1;
}

int ssh2_rsa_sha1_sign(ssh2_rsa_ctx *rsa, LIBSSH2_SESSION *session,
                       const unsigned char *hash, size_t hash_len,
                       unsigned char **signature, size_t *signature_len)
{
    return ssh2_rsa_sha2_sign(rsa, session, hash, hash_len,
                              signature, signature_len);
}

void ssh2_rsa_free(ssh2_rsa_ctx *rsa)
{
    mbedtls_rsa_free(rsa);
    mbedtls_free(rsa);
}

static unsigned char *mbed_gen_publickey_from_rsa(LIBSSH2_SESSION *session,
                                                  mbedtls_rsa_context *rsa,
                                                  size_t *keylen)
{
    uint32_t e_bytes, n_bytes;
    uint32_t len;
    unsigned char *key;
    unsigned char *p;

    e_bytes = (uint32_t)mbedtls_mpi_size(&rsa->MBEDTLS_PRIVATE(E));
    n_bytes = (uint32_t)mbedtls_mpi_size(&rsa->MBEDTLS_PRIVATE(N)) + 1;

    /* Key form is "ssh-rsa" + e + n. */
    len = 4 + (uint32_t)sizeof("ssh-rsa") - 1 + 4 + e_bytes + 4 + n_bytes;

    key = SSH2_ALLOC(session, len);
    if(!key)
        return NULL;

    /* Process key encoding. */
    p = key;

    ssh2_htonu32(p, sizeof("ssh-rsa") - 1); /* Key type. */
    p += 4;
    /* NOLINTNEXTLINE(bugprone-not-null-terminated-result) */
    memcpy(p, "ssh-rsa", sizeof("ssh-rsa") - 1);
    p += sizeof("ssh-rsa") - 1;

    ssh2_htonu32(p, e_bytes);
    p += 4;
    mbedtls_mpi_write_binary(&rsa->MBEDTLS_PRIVATE(E), p, e_bytes);
    p += e_bytes; /* Increment write index after writing to buffer */

    ssh2_htonu32(p, n_bytes);
    p += 4;
    mbedtls_mpi_write_binary(&rsa->MBEDTLS_PRIVATE(N), p, n_bytes);
    p += n_bytes; /* Increment write index after writing to buffer */

    *keylen = (size_t)(p - key);
    return key;
}

static int mbed_pub_priv_key(LIBSSH2_SESSION *session,
                             char **method, size_t *method_len,
                             unsigned char **pubkeydata,
                             size_t *pubkeydata_len,
                             mbedtls_pk_context *pkey)
{
    char *method_buf = NULL;
    unsigned char *key = NULL;
    size_t keylen = 0, method_buf_len = 0;
    int ret;
    mbedtls_rsa_context *rsa;

    if(mbedtls_pk_get_type(pkey) != MBEDTLS_PK_RSA) {
        mbedtls_pk_free(pkey);
        return ssh2_err(session, LIBSSH2_ERROR_FILE, "Key type not supported");
    }

    ret = 0;

    /* write method */
    method_buf_len = sizeof("ssh-rsa") - 1;
    method_buf = SSH2_ALLOC(session, method_buf_len);
    if(method_buf)
        memcpy(method_buf, "ssh-rsa", method_buf_len);
    else
        ret = -1;

    rsa = mbedtls_pk_rsa(*pkey);
    key = mbed_gen_publickey_from_rsa(session, rsa, &keylen);
    if(!key)
        ret = -1;

    /* write output */
    if(ret) {
        if(method_buf)
            SSH2_FREE(session, method_buf);
        if(key)
            SSH2_FREE(session, key);
    }
    else {
        *method = method_buf;
        *method_len = method_buf_len;
        *pubkeydata = key;
        *pubkeydata_len = keylen;
    }

    return ret;
}

int ssh2_pub_privkey_file(LIBSSH2_SESSION *session,
                          char **method, size_t *method_len,
                          unsigned char **pubkeydata, size_t *pubkeydata_len,
                          const char *privatekey,
                          const char *passphrase)
{
    mbedtls_pk_context pkey;
    char buf[1024];
    int ret;

    mbedtls_pk_init(&pkey);
    ret = mbedtls_pk_parse_keyfile(&pkey, privatekey, passphrase,
                                   mbedtls_ctr_drbg_random, &mbed_ctr_drbg);
    if(ret) {
        mbedtls_strerror(ret, (char *)buf, sizeof(buf));
        mbedtls_pk_free(&pkey);
        return ssh2_err_flags(session, LIBSSH2_ERROR_FILE, buf,
                              SSH2_ERR_FLAG_DUP);
    }

    ret = mbed_pub_priv_key(session, method, method_len,
                            pubkeydata, pubkeydata_len, &pkey);

    mbedtls_pk_free(&pkey);

    return ret;
}

int ssh2_pub_privkey_blob(LIBSSH2_SESSION *session,
                          char **method, size_t *method_len,
                          unsigned char **pubkeydata, size_t *pubkeydata_len,
                          const char *privkeyblob, size_t privkeyblob_len,
                          const char *passphrase)
{
    mbedtls_pk_context pkey;
    char buf[1024];
    int ret;
    unsigned char *data_nullterm;

    /* mbedtls checks in "mbedtls/pkparse.c:1184" if "key[keylen - 1] != '\0'"
       private-key from memory fails if the last byte is not a null byte */
    data_nullterm = mbedtls_calloc(privkeyblob_len + 1, 1);
    if(!data_nullterm)
        return -1;

    memcpy(data_nullterm, privkeyblob, privkeyblob_len);
    data_nullterm[privkeyblob_len] = 0;

    mbedtls_pk_init(&pkey);

    ret = mbedtls_pk_parse_key(&pkey, data_nullterm, privkeyblob_len + 1,
                               (const unsigned char *)passphrase,
                               passphrase ? strlen(passphrase) : 0,
                               mbedtls_ctr_drbg_random, &mbed_ctr_drbg);
    mbed_zero_free(data_nullterm, privkeyblob_len + 1);

    if(ret) {
        mbedtls_strerror(ret, (char *)buf, sizeof(buf));
        mbedtls_pk_free(&pkey);
        return ssh2_err_flags(session, LIBSSH2_ERROR_FILE, buf,
                              SSH2_ERR_FLAG_DUP);
    }

    ret = mbed_pub_priv_key(session, method, method_len,
                            pubkeydata, pubkeydata_len, &pkey);

    mbedtls_pk_free(&pkey);

    return ret;
}

/*******************************************************************/
/*
 * mbedTLS backend: Diffie-Hellman functions
 */

void ssh2_dh_init(ssh2_dh_ctx *dhctx)
{
    *dhctx = ssh2_bn_init(); /* Random from client */
}

int ssh2_dh_key_pair(ssh2_dh_ctx *dhctx, ssh2_bn *pub, ssh2_bn *g,
                     ssh2_bn *p, int group_order, ssh2_bn_ctx *bnctx)
{
    (void)bnctx;

    if(group_order <= 0)
        return -1;

    /* Generate x and e */
    if(mbed_bn_random(*dhctx, (group_order * 8) - 1, 0, -1) ||
       mbedtls_mpi_exp_mod(pub, g, *dhctx, p, NULL))
        return -1;
    return 0;
}

int ssh2_dh_is_valid(ssh2_bn *f, ssh2_bn *p)
{
    mbedtls_mpi one, tmp;
    size_t n, i, bits_set;

    /* Verify if valid */
    mbedtls_mpi_init(&one);
    if(mbedtls_mpi_lset(&one, 1)) {
        mbedtls_mpi_free(&one);
        return -4;
    }
    if(mbedtls_mpi_cmp_mpi(f, &one) != 1) {
        mbedtls_mpi_free(&one);
        return -1;  /* f <= 1 */
    }

    mbedtls_mpi_init(&tmp);
    if(mbedtls_mpi_copy(&tmp, p) ||  /* tmp = p */
       mbedtls_mpi_sub_int(&tmp, &tmp, 2)) {  /* tmp -= 2 */
        mbedtls_mpi_free(&tmp);
        mbedtls_mpi_free(&one);
        return -5;
    }
    if(mbedtls_mpi_cmp_mpi(f, &tmp) == 1) {
        mbedtls_mpi_free(&tmp);
        mbedtls_mpi_free(&one);
        return -2;  /* f >= p - 1 (== f > p - 2) */
    }

    mbedtls_mpi_free(&tmp);
    mbedtls_mpi_free(&one);

    for(i = 0, n = mbedtls_mpi_bitlen(f), bits_set = 0; i < n; ++i)
        if(mbedtls_mpi_get_bit(f, i))
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
    if(mbedtls_mpi_exp_mod(secret, f, *dhctx, p, NULL))
        return -1;
    return 0;
}

void ssh2_dh_dtor(ssh2_dh_ctx *dhctx)
{
    ssh2_bn_free(*dhctx);
    *dhctx = NULL;
}

#if LIBSSH2_ECDSA

/*******************************************************************/
/*
 * mbedTLS backend: ECDSA functions
 */

/*
 * Creates a local private key based on input curve
 * and returns octal value and octal length
 */
int ssh2_ecdsa_create_key(ssh2_ec_key **ec_ctx, LIBSSH2_SESSION *session,
                          unsigned char **out_public_key_octal,
                          size_t *out_public_key_octal_len,
                          ssh2_curve_type curve)
{
    size_t plen = 0;

    *ec_ctx = mbedtls_calloc(1, sizeof(mbedtls_ecp_keypair));
    if(!*ec_ctx)
        goto failed;

    mbedtls_ecdsa_init(*ec_ctx);

    if(mbedtls_ecdsa_genkey(*ec_ctx, (mbedtls_ecp_group_id)curve,
                            mbedtls_ctr_drbg_random, &mbed_ctr_drbg))
        goto failed;

    plen = 2 * mbedtls_mpi_size(
        &(*ec_ctx)->MBEDTLS_PRIVATE(grp).P) + 1;

    *out_public_key_octal = SSH2_ALLOC(session, plen);
    if(!*out_public_key_octal)
        goto failed;

    if(mbedtls_ecp_point_write_binary(
          &(*ec_ctx)->MBEDTLS_PRIVATE(grp),
          &(*ec_ctx)->MBEDTLS_PRIVATE(Q),
          MBEDTLS_ECP_PF_UNCOMPRESSED,
          out_public_key_octal_len, *out_public_key_octal, plen) == 0)
        return 0;

failed:

    ssh2_ecdsa_free(*ec_ctx);
    *ec_ctx = NULL;
    if(*out_public_key_octal) {
        ssh2_explicit_zero(*out_public_key_octal, plen);
        SSH2_SAFEFREE(session, *out_public_key_octal);
    }

    return -1;
}

/*
 * Creates a new public key given an octal string, length and type
 */
int ssh2_ecdsa_curve_name_with_octal_new(
    ssh2_ecdsa_ctx **ec_ctx,
    const unsigned char *publickey_encoded, size_t publickey_encoded_len,
    ssh2_curve_type curve)
{
    *ec_ctx = mbedtls_calloc(1, sizeof(mbedtls_ecp_keypair));
    if(!*ec_ctx)
        goto failed;

    mbedtls_ecdsa_init(*ec_ctx);

    if(mbedtls_ecp_group_load(&(*ec_ctx)->MBEDTLS_PRIVATE(grp),
                              (mbedtls_ecp_group_id)curve))
        goto failed;

    if(mbedtls_ecp_point_read_binary(&(*ec_ctx)->MBEDTLS_PRIVATE(grp),
                                     &(*ec_ctx)->MBEDTLS_PRIVATE(Q),
                                     publickey_encoded, publickey_encoded_len))
        goto failed;

    if(mbedtls_ecp_check_pubkey(&(*ec_ctx)->MBEDTLS_PRIVATE(grp),
                                &(*ec_ctx)->MBEDTLS_PRIVATE(Q)) == 0)
        return 0;

failed:

    ssh2_ecdsa_free(*ec_ctx);
    *ec_ctx = NULL;

    return -1;
}

/*
 * Computes the shared secret K given a local private key,
 * remote public key and length
 */
int ssh2_ecdh_gen_k(ssh2_bn **k,
                    ssh2_ec_key *private_key,
                    const unsigned char *server_public_key,
                    size_t server_public_key_len)
{
    mbedtls_ecp_point pubkey;
    int rc = 0;

    if(!*k)
        return -1;

    mbedtls_ecp_point_init(&pubkey);

    if(mbedtls_ecp_point_read_binary(&private_key->MBEDTLS_PRIVATE(grp),
                                     &pubkey,
                                     server_public_key,
                                     server_public_key_len)) {
        rc = -1;
        goto cleanup;
    }

    if(mbedtls_ecdh_compute_shared(&private_key->MBEDTLS_PRIVATE(grp), *k,
                                   &pubkey,
                                   &private_key->MBEDTLS_PRIVATE(d),
                                   mbedtls_ctr_drbg_random, &mbed_ctr_drbg)) {
        rc = -1;
        goto cleanup;
    }

    if(mbedtls_ecp_check_privkey(&private_key->MBEDTLS_PRIVATE(grp), *k))
        rc = -1;

cleanup:

    mbedtls_ecp_point_free(&pubkey);

    return rc;
}

/*
 * Verifies the ECDSA signature of a hashed message
 */
int ssh2_ecdsa_verify(ssh2_ecdsa_ctx *ec_ctx,
                      const unsigned char *r, size_t r_len,
                      const unsigned char *s, size_t s_len,
                      const unsigned char *m, size_t m_len)
{
    mbedtls_mpi pr, ps;
    size_t actual_len;
    int rc = -1;

    mbedtls_mpi_init(&pr);
    mbedtls_mpi_init(&ps);

    if(mbedtls_mpi_read_binary(&pr, r, r_len))
        goto cleanup;

    if(mbedtls_mpi_read_binary(&ps, s, s_len))
        goto cleanup;

    switch(ssh2_ecdsa_get_curve_type(ec_ctx)) {
    case SSH2_EC_CURVE_NISTP256: {
        unsigned char hsh[SSH2_SHA256_DIG_LEN];
        if(psa_hash_compute(PSA_ALG_SHA_256, m, m_len, hsh, sizeof(hsh),
                            &actual_len) == PSA_SUCCESS)
            rc = mbedtls_ecdsa_verify(&ec_ctx->MBEDTLS_PRIVATE(grp),
                                      hsh, sizeof(hsh),
                                      &ec_ctx->MBEDTLS_PRIVATE(Q), &pr, &ps);
        break;
    }
    case SSH2_EC_CURVE_NISTP384: {
        unsigned char hsh[SSH2_SHA384_DIG_LEN];
        if(psa_hash_compute(PSA_ALG_SHA_384, m, m_len, hsh, sizeof(hsh),
                            &actual_len) == PSA_SUCCESS)
            rc = mbedtls_ecdsa_verify(&ec_ctx->MBEDTLS_PRIVATE(grp),
                                      hsh, sizeof(hsh),
                                      &ec_ctx->MBEDTLS_PRIVATE(Q), &pr, &ps);
        break;
    }
    case SSH2_EC_CURVE_NISTP521: {
        unsigned char hsh[SSH2_SHA512_DIG_LEN];
        if(psa_hash_compute(PSA_ALG_SHA_512, m, m_len, hsh, sizeof(hsh),
                            &actual_len) == PSA_SUCCESS)
            rc = mbedtls_ecdsa_verify(&ec_ctx->MBEDTLS_PRIVATE(grp),
                                      hsh, sizeof(hsh),
                                      &ec_ctx->MBEDTLS_PRIVATE(Q), &pr, &ps);
        break;
    }
    default:
        rc = -1;
    }

cleanup:

    mbedtls_mpi_free(&pr);
    mbedtls_mpi_free(&ps);

    return rc == 0 ? 0 : -1;
}

static int mbed_parse_eckey(ssh2_ecdsa_ctx **ctx, mbedtls_pk_context *pkey,
                            const unsigned char *data, size_t data_len,
                            const char *passphrase)
{
    if(mbedtls_pk_parse_key(pkey, data, data_len,
                            (const unsigned char *)passphrase,
                            passphrase ? strlen(passphrase) : 0,
                            mbedtls_ctr_drbg_random, &mbed_ctr_drbg))
        goto failed;

    if(mbedtls_pk_get_type(pkey) != MBEDTLS_PK_ECKEY)
        goto failed;

    *ctx = mbedtls_calloc(1, sizeof(ssh2_ecdsa_ctx));
    if(!*ctx)
        goto failed;

    mbedtls_ecdsa_init(*ctx);

    if(mbedtls_ecdsa_from_keypair(*ctx, mbedtls_pk_ec(*pkey)) == 0)
        return 0;

failed:

    ssh2_ecdsa_free(*ctx);
    *ctx = NULL;

    return -1;
}

/*
 * returns key curve type that maps to ssh2_curve_type
 */
ssh2_curve_type ssh2_ecdsa_get_curve_type(ssh2_ecdsa_ctx *ec_ctx)
{
    return (ssh2_curve_type)ec_ctx->MBEDTLS_PRIVATE(grp).id;
}

/*
 * returns 0 for success, key curve type that maps to ssh2_curve_type
 */
static int mbed_ecdsa_curve_type_from_name(const char *name,
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

static int mbed_parse_openssh_key(ssh2_ecdsa_ctx **ctx,
                                  LIBSSH2_SESSION *session,
                                  const char *data, size_t data_len,
                                  const char *passphrase)
{
    ssh2_curve_type type;
    unsigned char *name = NULL;
    struct string_buf *decrypted = NULL;
    size_t curvelen, exponentlen, pointlen;
    unsigned char *curve, *exponent, *point_buf;

    if(ssh2_openssh_pem_parse_blob(session, data, data_len,
                                   passphrase, &decrypted))
        goto failed;

    if(ssh2_get_string(decrypted, &name, NULL))
        goto failed;

    if(mbed_ecdsa_curve_type_from_name((const char *)name, &type))
        goto failed;

    if(ssh2_get_string(decrypted, &curve, &curvelen))
        goto failed;

    if(ssh2_get_string(decrypted, &point_buf, &pointlen))
        goto failed;

    if(ssh2_get_bignum_bytes(decrypted, &exponent, &exponentlen))
        goto failed;

    *ctx = mbedtls_calloc(1, sizeof(ssh2_ecdsa_ctx));
    if(!*ctx)
        goto failed;

    mbedtls_ecdsa_init(*ctx);

    if(mbedtls_ecp_group_load(&(*ctx)->MBEDTLS_PRIVATE(grp),
                              (mbedtls_ecp_group_id)type))
        goto failed;

    if(mbedtls_mpi_read_binary(&(*ctx)->MBEDTLS_PRIVATE(d),
                               exponent, exponentlen))
        goto failed;

    if(mbedtls_ecp_mul(&(*ctx)->MBEDTLS_PRIVATE(grp),
                       &(*ctx)->MBEDTLS_PRIVATE(Q),
                       &(*ctx)->MBEDTLS_PRIVATE(d),
                       &(*ctx)->MBEDTLS_PRIVATE(grp).G,
                       mbedtls_ctr_drbg_random, &mbed_ctr_drbg))
        goto failed;

    if(mbedtls_ecp_check_privkey(&(*ctx)->MBEDTLS_PRIVATE(grp),
                                 &(*ctx)->MBEDTLS_PRIVATE(d)) == 0)
        goto cleanup;

failed:

    ssh2_ecdsa_free(*ctx);
    *ctx = NULL;

cleanup:

    if(decrypted)
        ssh2_string_buf_free(session, decrypted);

    return *ctx ? 0 : -1;
}

/*
 * Creates a new private key given a file path and password
 */
int ssh2_ecdsa_new_priv_from_file(ssh2_ecdsa_ctx **ec_ctx,
                                  LIBSSH2_SESSION *session,
                                  const char *filename,
                                  const char *passphrase)
{
    mbedtls_pk_context pkey;
    char *data = NULL;
    size_t data_len = 0;
    FILE *fp = NULL;
    long file_size;

    mbedtls_pk_init(&pkey);

    fp = ssh2_fopen(filename, "rb");
    if(!fp)
        goto cleanup;
    if(fseek(fp, 0, SEEK_END))
        goto cleanup;
    file_size = ftell(fp);
    if(file_size < 0 || file_size > (1024 * 1024))
        goto cleanup;
    if(fseek(fp, 0, SEEK_SET))
        goto cleanup;
    data_len = (size_t)file_size;
    if(data_len == 0)
        goto cleanup;
    data = SSH2_ALLOC(session, data_len + 1);
    if(!data)
        goto cleanup;
    if(fread(data, 1, data_len, fp) != data_len)
        goto cleanup;

    data[data_len] = 0;  /* for mbedtls_pk_parse_key() */
    if(mbed_parse_eckey(ec_ctx, &pkey, data, data_len + 1, passphrase) == 0)
        goto cleanup;

    mbed_parse_openssh_key(ec_ctx, session, data, data_len, passphrase);

cleanup:

    if(fp)
        fclose(fp);
    if(data) {
        ssh2_explicit_zero(data, data_len + 1);
        SSH2_FREE(session, data);
    }

    mbedtls_pk_free(&pkey);

    return *ec_ctx ? 0 : -1;
}

/*
 * Creates a new private key given a file data and password
 */
int ssh2_ecdsa_new_priv_from_blob(ssh2_ecdsa_ctx **ec_ctx,
                                  LIBSSH2_SESSION *session,
                                  const char *blob, size_t blob_len,
                                  const char *passphrase)
{
    char *data_nullterm;
    mbedtls_pk_context pkey;

    (void)session;

    mbedtls_pk_init(&pkey);

    data_nullterm = mbedtls_calloc(1, blob_len + 1);
    if(!data_nullterm)
        goto cleanup;

    memcpy(data_nullterm, blob, blob_len);
    data_nullterm[blob_len] = 0;

    if(mbed_parse_eckey(ec_ctx, &pkey, data_nullterm, blob_len + 1,
                        passphrase) == 0)
        goto cleanup;

    mbed_parse_openssh_key(ec_ctx, session, data_nullterm, blob_len + 1,
                           passphrase);

cleanup:

    mbedtls_pk_free(&pkey);

    mbed_zero_free(data_nullterm, blob_len + 1);

    return *ec_ctx ? 0 : -1;
}

static unsigned char *mbed_write_bn(unsigned char *buf,
                                    const mbedtls_mpi *bn, size_t bn_size)
{
    unsigned char *p = buf;
    uint32_t bn_bytes = (uint32_t)bn_size;

    p += 4;  /* Left space for bn size which is written below. */

    *p = 0;
    mbedtls_mpi_write_binary(bn, p + 1, bn_bytes - 1);

    if(!(p[1] & 0x80))
        memmove(p, p + 1, --bn_bytes);

    ssh2_htonu32(p - 4, bn_bytes);

    return p + bn_bytes;
}

/*
 * Computes the ECDSA signature of a previously-hashed message
 */
int ssh2_ecdsa_sign(ssh2_ecdsa_ctx *ec_ctx, LIBSSH2_SESSION *session,
                    const unsigned char *hash, size_t hash_len,
                    unsigned char **signature, size_t *signature_len)
{
    size_t r_len, s_len, tmp_sign_len = 0;
    unsigned char *sp, *tmp_sign = NULL;
    mbedtls_mpi pr, ps;

    mbedtls_mpi_init(&pr);
    mbedtls_mpi_init(&ps);

    if(mbedtls_ecdsa_sign(&ec_ctx->MBEDTLS_PRIVATE(grp), &pr, &ps,
                          &ec_ctx->MBEDTLS_PRIVATE(d),
                          hash, hash_len,
                          mbedtls_ctr_drbg_random, &mbed_ctr_drbg))
        goto cleanup;

    r_len = mbedtls_mpi_size(&pr) + 1;
    s_len = mbedtls_mpi_size(&ps) + 1;
    tmp_sign_len = r_len + s_len + 8;

    tmp_sign = SSH2_CALLOC(session, tmp_sign_len);
    if(!tmp_sign)
        goto cleanup;

    sp = tmp_sign;
    sp = mbed_write_bn(sp, &pr, r_len);
    sp = mbed_write_bn(sp, &ps, s_len);

    *signature_len = (size_t)(sp - tmp_sign);

    *signature = SSH2_CALLOC(session, *signature_len);
    if(!*signature)
        goto cleanup;

    memcpy(*signature, tmp_sign, *signature_len);

cleanup:

    mbedtls_mpi_free(&pr);
    mbedtls_mpi_free(&ps);

    mbed_zero_free(tmp_sign, tmp_sign_len);

    return *signature ? 0 : -1;
}

void ssh2_ecdsa_free(ssh2_ecdsa_ctx *ec_ctx)
{
    mbedtls_ecdsa_free(ec_ctx);
    mbedtls_free(ec_ctx);
}
#endif /* LIBSSH2_ECDSA */

#endif /* LIBSSH2_MBEDTLS */
