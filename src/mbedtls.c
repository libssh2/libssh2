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
#define MBEDTLS_PK_PARSE_KEY(a, b, c, d, e) mbedtls_pk_parse_key(a, b, c, d, \
    e, mbedtls_ctr_drbg_random, &mbed_ctr_drbg)
#define MBEDTLS_PK_PARSE_KEYFILE(a, b, c)   mbedtls_pk_parse_keyfile(a, b, c, \
    mbedtls_ctr_drbg_random, &mbed_ctr_drbg)
#else
#define MBEDTLS_PK_PARSE_KEY(a, b, c, d, e) mbedtls_pk_parse_key(a, b, c, d, e)
#define MBEDTLS_PK_PARSE_KEYFILE(a, b, c)   mbedtls_pk_parse_keyfile(a, b, c)
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

    if(mbedtls_ctr_drbg_seed(&mbed_ctr_drbg, mbedtls_entropy_func,
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

int ssh2_cipher_init(ssh2_cipher_ctx *ctx, SSH2_CIPHER_T(algo),
                     unsigned char *iv, unsigned char *secret, int encrypt)
{
    const mbedtls_cipher_info_t *cipher_info;
    mbedtls_operation_t op;
    int ret;

    if(!ctx)
        return -1;

    memset(ctx, 0, sizeof(*ctx));

#if LIBSSH2_AES_GCM
    /* Check if this is a GCM algorithm */
    if(algo == MBEDTLS_CIPHER_AES_128_GCM ||
       algo == MBEDTLS_CIPHER_AES_256_GCM) {
        unsigned int keybits;

        ctx->is_aesgcm = 1;

        /* Store the initial IV (will be incremented per packet) */
        memcpy(ctx->u.gcm.iv, iv, sizeof(ctx->u.gcm.iv));

        /* Initialize GCM context */
        mbedtls_gcm_init(&ctx->u.gcm.ctx);

        /* Set key length based on algorithm */
        if(algo == MBEDTLS_CIPHER_AES_128_GCM)
            keybits = 128;
        else /* MBEDTLS_CIPHER_AES_256_GCM */
            keybits = 256;

        /* Setup GCM with AES cipher and key */
        if(mbedtls_gcm_setkey(&ctx->u.gcm.ctx, MBEDTLS_CIPHER_ID_AES,
                              secret, keybits)) {
            mbedtls_gcm_free(&ctx->u.gcm.ctx);
            return -1;
        }

        return 0;
    }
#endif

    /* Non-GCM algorithms: use cipher API */
    op = encrypt ? MBEDTLS_ENCRYPT : MBEDTLS_DECRYPT;

    cipher_info = mbedtls_cipher_info_from_type(algo);
    if(!cipher_info)
        return -1;

    mbedtls_cipher_init(&ctx->u.cipher);
    ret = mbedtls_cipher_setup(&ctx->u.cipher, cipher_info);

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
<<<<<<< HEAD
      ) {
        ret = mbedtls_cipher_set_padding_mode(&ctx->u.cipher,
                                              MBEDTLS_PADDING_NONE);
    }
||||||| parent of 88102d08f (mbedtls: try adding 4.x support)
      ) {
        ret = mbedtls_cipher_set_padding_mode(ctx, MBEDTLS_PADDING_NONE);
    }
=======
      )
        ret = mbedtls_cipher_set_padding_mode(ctx, MBEDTLS_PADDING_NONE);
>>>>>>> 88102d08f (mbedtls: try adding 4.x support)

    if(!ret)
<<<<<<< HEAD
        ret = mbedtls_cipher_setkey(&ctx->u.cipher, secret,
||||||| parent of 88102d08f (mbedtls: try adding 4.x support)
        ret = mbedtls_cipher_setkey(ctx,
                  secret,
=======
        ret = mbedtls_cipher_setkey(ctx, secret,
>>>>>>> 88102d08f (mbedtls: try adding 4.x support)
                  (int)mbedtls_cipher_info_get_key_bitlen(cipher_info), op);

    if(!ret)
        ret = mbedtls_cipher_set_iv(&ctx->u.cipher, iv,
                  mbedtls_cipher_info_get_iv_size(cipher_info));

    if(ret)
        mbedtls_cipher_free(&ctx->u.cipher);

    return ret == 0 ? 0 : -1;
}

int ssh2_cipher_crypt(ssh2_cipher_ctx *ctx, SSH2_CIPHER_T(algo),
                      int encrypt, unsigned char *block, size_t blocksize,
                      int firstlast)
{
    int ret;
    unsigned char *output;
    size_t osize, olen, finish_olen;

    if(!ctx)
        return -1;

    (void)algo;

#if LIBSSH2_AES_GCM
    if(ctx->is_aesgcm) {
        unsigned char buf[32];
        unsigned char tag[16];  /* GCM authentication tag */
        const int authlen = sizeof(tag);
        const int aadlen = IS_FIRST(firstlast) ? 4 : 0;
        const int authenticationtag = IS_LAST(firstlast) ? authlen : 0;
        size_t cryptlen; /* length of encrypt */

        if(blocksize > sizeof(buf) ||
           blocksize < (size_t)(aadlen + authenticationtag))
            return -1;

        cryptlen = blocksize - aadlen - authenticationtag;

        /* First block: start GCM operation */
        if(IS_FIRST(firstlast)) {
            if(mbedtls_gcm_starts(&ctx->u.gcm.ctx,
                                  encrypt ? MBEDTLS_GCM_ENCRYPT
                                          : MBEDTLS_GCM_DECRYPT,
                                  ctx->u.gcm.iv, sizeof(ctx->u.gcm.iv)))
                return -1;

            /* Process AAD (Additional Authenticated Data) */
            if(aadlen && mbedtls_gcm_update_ad(&ctx->u.gcm.ctx, block, aadlen))
                return -1;
        }

        /* Process payload */
        if(cryptlen > 0) {
            olen = 0;
            if(mbedtls_gcm_update(&ctx->u.gcm.ctx,
                                  block + aadlen, cryptlen,
                                  buf, cryptlen, &olen))
                return -1;
            memcpy(block + aadlen, buf, olen);
        }

        ret = 0;

        /* Last block: finalize and handle authentication tag */
        if(IS_LAST(firstlast)) {
            unsigned char finish_buf[16];
            int i;

            finish_olen = 0;
            if(mbedtls_gcm_finish(&ctx->u.gcm.ctx,
                                  finish_buf, sizeof(finish_buf),
                                  &finish_olen, tag, authlen))
                return -1;

            if(encrypt)
                memcpy(block + blocksize - authlen, tag, authlen);
            else if(ssh2_timingsafe_bcmp(tag, block + blocksize - authlen,
                                         authlen))
                ret = -1;  /* GCM auth failed */

            /* Increment IV for next packet */
            for(i = 11; i >= 4; i--)
                if(++ctx->u.gcm.iv[i])
                    break;
        }

        return ret;
    }
#else
    (void)encrypt;
    (void)algo;
    (void)firstlast;
#endif

    /* Non-GCM algorithms: use standard cipher API */
    osize = blocksize + mbedtls_cipher_get_block_size(&ctx->u.cipher);

    output = mbedtls_calloc(osize, sizeof(char));
    if(output) {
<<<<<<< HEAD
        olen = 0;
        finish_olen = 0;

        ret = mbedtls_cipher_reset(&ctx->u.cipher);
||||||| parent of 88102d08f (mbedtls: try adding 4.x support)
        size_t olen = 0, finish_olen = 0;

        ret = mbedtls_cipher_reset(ctx);

=======
        size_t olen = 0, finish_olen = 0;

        ret = mbedtls_cipher_reset(ctx);
>>>>>>> 88102d08f (mbedtls: try adding 4.x support)
        if(!ret)
<<<<<<< HEAD
            ret = mbedtls_cipher_update(&ctx->u.cipher, block,
                                        blocksize, output, &olen);
||||||| parent of 88102d08f (mbedtls: try adding 4.x support)
            ret = mbedtls_cipher_update(ctx, block, blocksize, output, &olen);

=======
            ret = mbedtls_cipher_update(ctx, block, blocksize, output, &olen);
>>>>>>> 88102d08f (mbedtls: try adding 4.x support)
        if(!ret)
<<<<<<< HEAD
            ret = mbedtls_cipher_finish(&ctx->u.cipher,
                                        output + olen, &finish_olen);
||||||| parent of 88102d08f (mbedtls: try adding 4.x support)
            ret = mbedtls_cipher_finish(ctx, output + olen, &finish_olen);

=======
            ret = mbedtls_cipher_finish(ctx, output + olen, &finish_olen);
>>>>>>> 88102d08f (mbedtls: try adding 4.x support)
        if(!ret) {
            olen += finish_olen;
            memcpy(block, output, olen);
        }

        if(osize)
            ssh2_explicit_zero(output, osize * sizeof(char));
        mbedtls_free(output);
    }
    else
        ret = -1;

    return ret == 0 ? 0 : -1;
}

void ssh2_cipher_dtor(ssh2_cipher_ctx *ctx)
{
    if(!ctx)
        return;

#if LIBSSH2_AES_GCM
    if(ctx->is_aesgcm) {
        mbedtls_gcm_free(&ctx->u.gcm.ctx);
        return;
    }
#endif

    mbedtls_cipher_free(&ctx->u.cipher);
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
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_algorithm_t alg_hmac = PSA_ALG_HMAC(alg);

    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attr, alg_hmac);
    psa_set_key_type(&attr, PSA_KEY_TYPE_HMAC);

    if(psa_import_key(&attr, key, key_len, &ctx->key_id) != PSA_SUCCESS)
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

int ssh2_bn_from_bin(ssh2_bn **bn, const unsigned char *bin, size_t len)
{
    if(!bn || !bin || !len)
        return -1;

    if(!*bn) {
        *bn = ssh2_bn_init();
        if(!*bn)
            return -1;
    }

    return mbedtls_mpi_read_binary(*bn, bin, len);
}

static int mbed_bn_random(ssh2_bn *bn, int bits, int top, int bottom)
{
    uint8_t *buf;
    size_t len;
    size_t i;

    if(!bn || bits <= 0)
        return -1;

    len = (bits + 7) >> 3;

    buf = mbedtls_calloc(1, len);
    if(!buf)
        return -1;

    if(psa_generate_random(buf, len) != PSA_SUCCESS) {
        mbedtls_free(buf);
        return -1;
    }

    mbedtls_mpi_read_binary(bn, buf, len);
    mbedtls_free(buf);

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

#if LIBSSH2_RSA
int ssh2_rsa_new(ssh2_rsa_ctx **rsa, LIBSSH2_SESSION *session,
                 const unsigned char *edata, size_t elen,
                 const unsigned char *ndata, size_t nlen,
                 const unsigned char *ddata, size_t dlen,
                 const unsigned char *pdata, size_t plen,
                 const unsigned char *qdata, size_t qlen,
                 const unsigned char *e1data, size_t e1len,
                 const unsigned char *e2data, size_t e2len,
                 const unsigned char *coeffdata, size_t coefflen)
{
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    mbedtls_mpi mpi;

<<<<<<< HEAD
    ctx = SSH2_CALLOC(session, sizeof(ssh2_rsa_ctx));
    if(!ctx)
        return -1;
||||||| parent of 88102d08f (mbedtls: try adding 4.x support)
    ctx = mbedtls_calloc(1, sizeof(ssh2_rsa_ctx));
    if(!ctx)
        return -1;
=======
    unsigned char buf[PSA_EXPORT_KEY_PAIR_MAX_SIZE];
    unsigned char *start = buf;
    unsigned char *p = buf + sizeof(buf); /* write backwards ending at p */
>>>>>>> 88102d08f (mbedtls: try adding 4.x support)

    mbedtls_mpi_init(&mpi);

    *rsa = mbedtls_calloc(1, sizeof(*rsa));
    if(!*rsa)
        goto failed;

    **rsa = PSA_KEY_ID_NULL;

    if(ddata)
        if(mbedtls_mpi_read_binary(&mpi, coeffdata, coefflen) != 0 ||
           mbedtls_asn1_write_mpi(&p, start, &mpi) < 0 ||
           mbedtls_mpi_read_binary(&mpi, e2data, e2len) != 0 ||
           mbedtls_asn1_write_mpi(&p, start, &mpi) < 0 ||
           mbedtls_mpi_read_binary(&mpi, e1data, e1len) != 0 ||
           mbedtls_asn1_write_mpi(&p, start, &mpi) < 0 ||
           mbedtls_mpi_read_binary(&mpi, qdata, qlen) != 0 ||
           mbedtls_asn1_write_mpi(&p, start, &mpi) < 0 ||
           mbedtls_mpi_read_binary(&mpi, pdata, plen) != 0 ||
           mbedtls_asn1_write_mpi(&p, start, &mpi) < 0 ||
           mbedtls_mpi_read_binary(&mpi, ddata, dlen) != 0 ||
           mbedtls_asn1_write_mpi(&p, start, &mpi) < 0)
            goto failed;

    if(mbedtls_mpi_read_binary(&mpi, edata, elen) != 0 ||
       mbedtls_asn1_write_mpi(&p, start, &mpi) < 0 ||
       mbedtls_mpi_read_binary(&mpi, ndata, nlen) != 0 ||
       mbedtls_asn1_write_mpi(&p, start, &mpi) < 0 ||
       (ddata && mbedtls_asn1_write_int(&p, start, 0) < 0))
        goto failed;

    mbedtls_mpi_free(&mpi);

    /* Wrap all content into a SEQUENCE with header tag + content length */
    if(mbedtls_asn1_write_len(&p, start, buf + sizeof(buf) - p) < 0 ||
       mbedtls_asn1_write_tag(&p, start, 0x30) < 0)
        goto failed;

    psa_set_key_usage_flags(&attr, ddata ? PSA_KEY_USAGE_SIGN_HASH
                                         : PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_type(&attr, ddata ? PSA_KEY_TYPE_RSA_KEY_PAIR
                                  : PSA_KEY_TYPE_RSA_PUBLIC_KEY);
    if(psa_import_key(&attr, p, buf + sizeof(buf) - p, *rsa) == PSA_SUCCESS)
        return 0;

failed:

    if(*rsa) {
        ssh2_rsa_free(*rsa);
        *rsa = NULL;
    }

<<<<<<< HEAD
    if(ret && ctx) {
        ssh2_rsa_free(ctx, session);
        ctx = NULL;
    }
    *rsa = ctx;
    return ret;
||||||| parent of 88102d08f (mbedtls: try adding 4.x support)
    if(ret && ctx) {
        ssh2_rsa_free(ctx);
        ctx = NULL;
    }
    *rsa = ctx;
    return ret;
=======
    mbedtls_mpi_free(&mpi);

    return -1;
>>>>>>> 88102d08f (mbedtls: try adding 4.x support)
}

int ssh2_rsa_new_priv(ssh2_rsa_ctx **rsa,
                      LIBSSH2_SESSION *session,
                      const char *filename,
                      const char *blob, size_t blob_len,
                      const char *passphrase)
{
    int ret = -1;
    mbedtls_pk_context pkey;
<<<<<<< HEAD
    mbedtls_rsa_context *pk_rsa;
    unsigned char *data_nullterm = NULL;

||||||| parent of 88102d08f (mbedtls: try adding 4.x support)
    mbedtls_rsa_context *pk_rsa;

=======
>>>>>>> 88102d08f (mbedtls: try adding 4.x support)
    (void)session;

<<<<<<< HEAD
    *rsa = SSH2_CALLOC(session, sizeof(ssh2_rsa_ctx));
||||||| parent of 88102d08f (mbedtls: try adding 4.x support)
    *rsa = mbedtls_calloc(1, sizeof(ssh2_rsa_ctx));
=======
    *rsa = mbedtls_calloc(1, sizeof(*rsa));
>>>>>>> 88102d08f (mbedtls: try adding 4.x support)
    if(!*rsa)
        goto failed;

    **rsa = PSA_KEY_ID_NULL;

<<<<<<< HEAD
    mbedtls_rsa_init(*rsa);

    if(!filename) {
        /* mbedTLS checks in "mbedtls/pkparse.c:1184"
               if "key[keylen - 1] != '\0'"
           private-key from memory fails if the last byte is not a null byte */
        data_nullterm = SSH2_CALLOC(session, blob_len + 1);
        if(!data_nullterm) {
            ssh2_rsa_free(*rsa, session);
            *rsa = NULL;
            return -1;
        }

        memcpy(data_nullterm, blob, blob_len);
        data_nullterm[blob_len] = '\0';
    }

||||||| parent of 88102d08f (mbedtls: try adding 4.x support)
    mbedtls_rsa_init(*rsa);
=======
>>>>>>> 88102d08f (mbedtls: try adding 4.x support)
    mbedtls_pk_init(&pkey);
<<<<<<< HEAD

    if(!filename) {
        ret = mbedtls_pk_parse_key(&pkey, data_nullterm, blob_len + 1,
                                   (const unsigned char *)passphrase,
                                   passphrase ? strlen(passphrase) : 0,
                                   mbedtls_ctr_drbg_random, &mbed_ctr_drbg);
        ssh2_zero_free(session, data_nullterm, blob_len + 1);
    }
    else
        ret = mbedtls_pk_parse_keyfile(&pkey, filename, passphrase,
                                       mbedtls_ctr_drbg_random,
                                       &mbed_ctr_drbg);

    if(ret || mbedtls_pk_get_type(&pkey) != MBEDTLS_PK_RSA) {
        mbedtls_pk_free(&pkey);
        ssh2_rsa_free(*rsa, session);
        *rsa = NULL;
        return -1;
||||||| parent of 88102d08f (mbedtls: try adding 4.x support)

    ret = mbedtls_pk_parse_keyfile(&pkey, filename, (const char *)passphrase,
                                   mbedtls_ctr_drbg_random, &mbed_ctr_drbg);
    if(ret || mbedtls_pk_get_type(&pkey) != MBEDTLS_PK_RSA) {
        mbedtls_pk_free(&pkey);
        ssh2_rsa_free(*rsa);
        *rsa = NULL;
        return -1;
=======
    ret = MBEDTLS_PK_PARSE_KEYFILE(&pkey, filename, (const char *)passphrase);
    if(!ret) {
        psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
        psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_HASH);
        psa_set_key_type(&attr, PSA_KEY_TYPE_RSA_KEY_PAIR);
        if(mbedtls_pk_import_into_psa(&pkey, &attr, *rsa))
            ret = -1;
>>>>>>> 88102d08f (mbedtls: try adding 4.x support)
    }

    mbedtls_pk_free(&pkey);

failed:

    if(ret && *rsa) {
        ssh2_rsa_free(*rsa);
        *rsa = NULL;
    }

    return ret;
}

<<<<<<< HEAD
int ssh2_rsa_sha2_verify(ssh2_rsa_ctx *rsa, LIBSSH2_SESSION *session,
                         size_t hash_len,
||||||| parent of 88102d08f (mbedtls: try adding 4.x support)
int ssh2_rsa_new_private_frommemory(ssh2_rsa_ctx **rsa,
                                    LIBSSH2_SESSION *session,
                                    const char *blob, size_t blob_len,
                                    const unsigned char *passphrase)
{
    int ret;
    mbedtls_pk_context pkey;
    mbedtls_rsa_context *pk_rsa;
    unsigned char *data_nullterm;
    size_t pwd_len;

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

    pwd_len = passphrase ? strlen((const char *)passphrase) : 0;
    ret = mbedtls_pk_parse_key(&pkey, data_nullterm, blob_len + 1,
                               passphrase, pwd_len,
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
=======
int ssh2_rsa_new_private_frommemory(ssh2_rsa_ctx **rsa,
                                    LIBSSH2_SESSION *session,
                                    const char *blob, size_t blob_len,
                                    const unsigned char *passphrase)
{
    int ret = -1;
    mbedtls_pk_context pkey;
    unsigned char *data_nullterm;
    size_t pwd_len;
    (void)session;

    *rsa = mbedtls_calloc(1, sizeof(*rsa));
    if(!*rsa)
        goto failed;

    **rsa = PSA_KEY_ID_NULL;

    /* mbedtls checks in "mbedtls/pkparse.c:1184" if "key[keylen - 1] != '\0'"
       private-key from memory fails if the last byte is not a null byte */
    data_nullterm = mbedtls_calloc(blob_len + 1, 1);
    if(!data_nullterm)
        goto failed;
    memcpy(data_nullterm, blob, blob_len);
    data_nullterm[blob_len] = 0;

    pwd_len = passphrase ? strlen((const char *)passphrase) : 0;

    mbedtls_pk_init(&pkey);
    ret = MBEDTLS_PK_PARSE_KEY(&pkey, data_nullterm, blob_len + 1,
                               passphrase, pwd_len);
    mbed_zero_free(data_nullterm, blob_len + 1);

    if(!ret) {
        psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
        psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_HASH);
        psa_set_key_type(&attr, PSA_KEY_TYPE_RSA_KEY_PAIR);
        if(mbedtls_pk_import_into_psa(&pkey, &attr, *rsa))
            ret = -1;
    }

    mbedtls_pk_free(&pkey);

failed:

    if(ret && *rsa) {
        ssh2_rsa_free(*rsa);
        *rsa = NULL;
    }

    return ret;
}

int ssh2_rsa_sha2_verify(ssh2_rsa_ctx *rsa, size_t hash_len,
>>>>>>> 88102d08f (mbedtls: try adding 4.x support)
                         const unsigned char *sig, size_t sig_len,
                         const unsigned char *m, size_t m_len)
{
    ssh2_hash_alg hash_alg;

<<<<<<< HEAD
    if(sig_len < mbedtls_rsa_get_len(rsa))
        return -1;

    hash = SSH2_ALLOC(session, hash_len);
    if(!hash)
        return -1;

#if LIBSSH2_RSA_SHA1
    if(hash_len == SSH2_SHA1_DIG_LEN) {
        ret = psa_hash_compute(PSA_ALG_SHA_1, m, m_len, hash, hash_len,
                               &actual_len) == PSA_SUCCESS ? 0 : -1;
        md_type = MBEDTLS_MD_SHA1;
    }
    else
#endif
    if(hash_len == SSH2_SHA256_DIG_LEN) {
        ret = psa_hash_compute(PSA_ALG_SHA_256, m, m_len, hash, hash_len,
                               &actual_len) == PSA_SUCCESS ? 0 : -1;
        md_type = MBEDTLS_MD_SHA256;
    }
    else if(hash_len == SSH2_SHA512_DIG_LEN) {
        ret = psa_hash_compute(PSA_ALG_SHA_512, m, m_len, hash, hash_len,
                               &actual_len) == PSA_SUCCESS ? 0 : -1;
        md_type = MBEDTLS_MD_SHA512;
    }
||||||| parent of 88102d08f (mbedtls: try adding 4.x support)
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
=======
    if(hash_len == SSH2_SHA1_DIG_LEN)
        hash_alg = SSH2_SHA1_ALG;
    else if(hash_len == SSH2_SHA256_DIG_LEN)
        hash_alg = SSH2_SHA256_ALG;
    else if(hash_len == SSH2_SHA512_DIG_LEN)
        hash_alg = SSH2_SHA512_ALG;
>>>>>>> 88102d08f (mbedtls: try adding 4.x support)
    else {
<<<<<<< HEAD
        SSH2_FREE(session, hash);
||||||| parent of 88102d08f (mbedtls: try adding 4.x support)
        free(hash);
=======
>>>>>>> 88102d08f (mbedtls: try adding 4.x support)
        return -1; /* unsupported digest */
    }

<<<<<<< HEAD
    if(ret) {
        SSH2_FREE(session, hash);
        return -1; /* failure */
    }
||||||| parent of 88102d08f (mbedtls: try adding 4.x support)
    if(ret) {
        free(hash);
        return -1; /* failure */
    }
=======
    if(psa_verify_message(*rsa, PSA_ALG_RSA_PKCS1V15_SIGN(hash_alg),
                          m, m_len, sig, sig_len) != PSA_SUCCESS)
        return -1;
>>>>>>> 88102d08f (mbedtls: try adding 4.x support)

<<<<<<< HEAD
    ret = mbedtls_rsa_pkcs1_verify(rsa,
                                   md_type, (unsigned int)hash_len,
                                   hash, sig);
    SSH2_FREE(session, hash);

    return ret == 0 ? 0 : -1;
||||||| parent of 88102d08f (mbedtls: try adding 4.x support)
    ret = mbedtls_rsa_pkcs1_verify(rsa,
                                   md_type, (unsigned int)hash_len,
                                   hash, sig);
    free(hash);

    return ret == 0 ? 0 : -1;
=======
    return 0;
>>>>>>> 88102d08f (mbedtls: try adding 4.x support)
}

int ssh2_rsa_sha2_sign(ssh2_rsa_ctx *rsa, LIBSSH2_SESSION *session,
                       const unsigned char *hash, size_t hash_len,
                       unsigned char **signature, size_t *signature_len)
{
    size_t sig_len = PSA_SIGNATURE_MAX_SIZE;
    ssh2_hash_alg hash_alg;

<<<<<<< HEAD
    sig_len = mbedtls_rsa_get_len(rsa);
    sig = SSH2_ALLOC(session, sig_len);
    if(!sig)
        return -1;

    ret = 0;
#if LIBSSH2_RSA_SHA1
||||||| parent of 88102d08f (mbedtls: try adding 4.x support)
    sig_len = mbedtls_rsa_get_len(rsa);
    sig = SSH2_ALLOC(session, sig_len);
    if(!sig)
        return -1;

    ret = 0;
=======
>>>>>>> 88102d08f (mbedtls: try adding 4.x support)
    if(hash_len == SSH2_SHA1_DIG_LEN)
<<<<<<< HEAD
        md_type = MBEDTLS_MD_SHA1;
    else
#endif
    if(hash_len == SSH2_SHA256_DIG_LEN)
        md_type = MBEDTLS_MD_SHA256;
||||||| parent of 88102d08f (mbedtls: try adding 4.x support)
        md_type = MBEDTLS_MD_SHA1;
    else if(hash_len == SSH2_SHA256_DIG_LEN)
        md_type = MBEDTLS_MD_SHA256;
=======
        hash_alg = SSH2_SHA1_ALG;
    else if(hash_len == SSH2_SHA256_DIG_LEN)
        hash_alg = SSH2_SHA256_ALG;
>>>>>>> 88102d08f (mbedtls: try adding 4.x support)
    else if(hash_len == SSH2_SHA512_DIG_LEN)
        hash_alg = SSH2_SHA512_ALG;
    else {
        ssh2_err(session, LIBSSH2_ERROR_PROTO,
                 "Unsupported hash digest length");
        return -1;
    }

    *signature = SSH2_ALLOC(session, sig_len);
    if(!*signature)
        return -1;

    if(psa_sign_hash(*rsa, PSA_ALG_RSA_PKCS1V15_SIGN(hash_alg), hash, hash_len,
                     *signature, sig_len, signature_len) != PSA_SUCCESS) {
        SSH2_SAFEFREE(session, *signature);
        return -1;
    }

    /* FIXME: convert to wire format */

    return 0;
}

#if LIBSSH2_RSA_SHA1
int ssh2_rsa_sha1_verify(ssh2_rsa_ctx *rsa, LIBSSH2_SESSION *session,
                         const unsigned char *sig, size_t sig_len,
                         const unsigned char *m, size_t m_len)
{
    return ssh2_rsa_sha2_verify(rsa, session, SSH2_SHA1_DIG_LEN,
                                sig, sig_len, m, m_len);
}

int ssh2_rsa_sha1_sign(ssh2_rsa_ctx *rsa, LIBSSH2_SESSION *session,
                       const unsigned char *hash, size_t hash_len,
                       unsigned char **signature, size_t *signature_len)
{
    return ssh2_rsa_sha2_sign(rsa, session, hash, hash_len,
                              signature, signature_len);
}
#endif

void ssh2_rsa_free(ssh2_rsa_ctx *rsa, LIBSSH2_SESSION *session)
{
<<<<<<< HEAD
    if(rsa) {
        mbedtls_rsa_free(rsa);
        SSH2_FREE(session, rsa);
    }
||||||| parent of 88102d08f (mbedtls: try adding 4.x support)
    mbedtls_rsa_free(rsa);
    mbedtls_free(rsa);
=======
    psa_destroy_key(*rsa);
    mbedtls_free(rsa);
>>>>>>> 88102d08f (mbedtls: try adding 4.x support)
}

<<<<<<< HEAD
static unsigned char *mbed_gen_publickey_from_rsa(LIBSSH2_SESSION *session,
                                                  mbedtls_rsa_context *rsa,
                                                  size_t *keylen)
{
    static const char method_name[] = "ssh-rsa";
    uint32_t e_bytes, n_bytes;
    uint32_t len;
    unsigned char *key;
    unsigned char *p;

    e_bytes = (uint32_t)mbedtls_mpi_size(&rsa->MBEDTLS_PRIVATE(E));
    n_bytes = (uint32_t)mbedtls_mpi_size(&rsa->MBEDTLS_PRIVATE(N)) + 1;

    /* Key form is "ssh-rsa" + e + n. */
    len = 4 + (uint32_t)sizeof(method_name) - 1 + 4 + e_bytes + 4 + n_bytes;

    key = SSH2_ALLOC(session, len);
    if(!key)
        return NULL;

    /* Process key encoding. */
    p = key;

    ssh2_htonu32(p, sizeof(method_name) - 1); /* Key type. */
    p += 4;
    memcpy(p, method_name, sizeof(method_name) - 1);
    p += sizeof(method_name) - 1;

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
#endif /* LIBSSH2_RSA */

static int mbed_pub_priv_key(LIBSSH2_SESSION *session, char **method,
||||||| parent of 88102d08f (mbedtls: try adding 4.x support)
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
    len = 4 + 7 + 4 + e_bytes + 4 + n_bytes;

    key = SSH2_ALLOC(session, len);
    if(!key)
        return NULL;

    /* Process key encoding. */
    p = key;

    ssh2_htonu32(p, 7); /* Key type. */
    p += 4;
    /* NOLINTNEXTLINE(bugprone-not-null-terminated-result) */
    memcpy(p, "ssh-rsa", 7);
    p += 7;

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
                             unsigned char **method,
                             size_t *method_len,
=======
static int mbed_pub_priv_key(LIBSSH2_SESSION *session,
                             unsigned char **method,
                             size_t *method_len,
>>>>>>> 88102d08f (mbedtls: try adding 4.x support)
                             unsigned char **pubkeydata,
                             size_t *pubkeydata_len,
                             const mbedtls_pk_context *pkey)
{
<<<<<<< HEAD
    char *method_buf = NULL;
    unsigned char *key = NULL;
    size_t keylen = 0;
    int ret = 0;
||||||| parent of 88102d08f (mbedtls: try adding 4.x support)
    unsigned char *key = NULL, *mth = NULL;
    size_t keylen = 0, mthlen = 0;
    int ret;
    mbedtls_rsa_context *rsa;
=======
    int ret = -1;
    ssh2_rsa_ctx rsa = PSA_KEY_ID_NULL;
    unsigned char *pubkey = NULL, *mth = NULL;
    size_t pubkey_size, pubkey_len, mth_len;
>>>>>>> 88102d08f (mbedtls: try adding 4.x support)

<<<<<<< HEAD
    (void)pkey;

#if LIBSSH2_RSA
    if(mbedtls_pk_get_type(pkey) == MBEDTLS_PK_RSA) {
        mbedtls_rsa_context *rsa;
        size_t method_buf_len;

        /* write method */
        method_buf_len = sizeof("ssh-rsa") - 1;
        method_buf = SSH2_ALLOC(session, method_buf_len + 1);
        if(method_buf)
            memcpy(method_buf, "ssh-rsa", method_buf_len + 1);
        else
            ret = -1;

        rsa = mbedtls_pk_rsa(*pkey);
        key = mbed_gen_publickey_from_rsa(session, rsa, &keylen);
        if(!key)
            ret = -1;
    }
    else
#endif
        ret = ssh2_err(session, LIBSSH2_ERROR_FILE, "Key type not supported");
||||||| parent of 88102d08f (mbedtls: try adding 4.x support)
    if(mbedtls_pk_get_type(pkey) != MBEDTLS_PK_RSA) {
        mbedtls_pk_free(pkey);
        return ssh2_err(session, LIBSSH2_ERROR_FILE, "Key type not supported");
    }

    ret = 0;

    /* write method */
    mthlen = 7;
    mth = SSH2_ALLOC(session, mthlen);
    if(mth)
        memcpy(mth, "ssh-rsa", mthlen);
    else
        ret = -1;

    rsa = mbedtls_pk_rsa(*pkey);
    key = mbed_gen_publickey_from_rsa(session, rsa, &keylen);
    if(!key)
        ret = -1;
=======
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_type(&attr, PSA_KEY_TYPE_RSA_KEY_PAIR);
    if(mbedtls_pk_import_into_psa(pkey, &attr, &rsa))
        goto cleanup;

    /* write method */
    mth_len = sizeof("ssh-rsa") - 1;
    mth = SSH2_ALLOC(session, mth_len);
    if(!mth)
        goto cleanup;
    memcpy(mth, "ssh-rsa", mth_len);

    pubkey_size = PSA_EXPORT_PUBLIC_KEY_MAX_SIZE;
    pubkey = SSH2_ALLOC(session, pubkey_size);
    if(!pubkey)
        goto cleanup;
    pubkey_len = 0;
    if(psa_export_public_key(rsa, pubkey, pubkey_size,
                             &pubkey_len) == PSA_SUCCESS) {
        ret = 0;
        *method = mth;
        *method_len = mth_len;
        *pubkeydata = pubkey;
        *pubkeydata_len = pubkey_len;
    }

cleanup:
>>>>>>> 88102d08f (mbedtls: try adding 4.x support)

    if(ret) {
<<<<<<< HEAD
        if(method_buf)
            SSH2_FREE(session, method_buf);
        if(key)
            SSH2_FREE(session, key);
    }
    else {
        *method = method_buf;
        *pubkeydata = key;
        *pubkeydata_len = keylen;
||||||| parent of 88102d08f (mbedtls: try adding 4.x support)
        if(mth)
            SSH2_FREE(session, mth);
        if(key)
            SSH2_FREE(session, key);
    }
    else {
        *method = mth;
        *method_len = mthlen;
        *pubkeydata = key;
        *pubkeydata_len = keylen;
=======
        if(pubkey)
            SSH2_FREE(session, pubkey);
        if(mth)
            SSH2_FREE(session, mth);
>>>>>>> 88102d08f (mbedtls: try adding 4.x support)
    }

    psa_destroy_key(rsa);

    return ret;
}

int ssh2_pub_privkey(LIBSSH2_SESSION *session, char **method,
                     unsigned char **pubkeydata, size_t *pubkeydata_len,
                     const char *privkeyfile,
                     const char *privkeyblob, size_t privkeyblob_len,
                     const char *passphrase)
{
    mbedtls_pk_context pkey;
    int ret;
    unsigned char *data_nullterm = NULL;

    if(!privkeyfile) {
        /* mbedTLS checks in "mbedtls/pkparse.c:1184"
               if "key[keylen - 1] != '\0'"
           private-key from memory fails if the last byte is not a null byte */
        data_nullterm = SSH2_CALLOC(session, privkeyblob_len + 1);
        if(!data_nullterm)
            return -1;

        memcpy(data_nullterm, privkeyblob, privkeyblob_len);
        data_nullterm[privkeyblob_len] = '\0';
    }

    mbedtls_pk_init(&pkey);
<<<<<<< HEAD

    if(!privkeyfile) {
        ret = mbedtls_pk_parse_key(&pkey, data_nullterm, privkeyblob_len + 1,
                                   (const unsigned char *)passphrase,
                                   passphrase ? strlen(passphrase) : 0,
                                   mbedtls_ctr_drbg_random, &mbed_ctr_drbg);
        ssh2_zero_free(session, data_nullterm, privkeyblob_len + 1);
    }
    else
        ret = mbedtls_pk_parse_keyfile(&pkey, privkeyfile, passphrase,
                                       mbedtls_ctr_drbg_random,
                                       &mbed_ctr_drbg);
||||||| parent of 88102d08f (mbedtls: try adding 4.x support)
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

int ssh2_pub_priv_keyfilememory(LIBSSH2_SESSION *session,
                                unsigned char **method,
                                size_t *method_len,
                                unsigned char **pubkeydata,
                                size_t *pubkeydata_len,
                                const char *privatekeydata,
                                size_t privatekeydata_len,
                                const char *passphrase)
{
    mbedtls_pk_context pkey;
    char buf[1024];
    int ret;
    unsigned char *data_nullterm;
    size_t pwd_len;

    /* mbedtls checks in "mbedtls/pkparse.c:1184" if "key[keylen - 1] != '\0'"
       private-key from memory fails if the last byte is not a null byte */
    data_nullterm = mbedtls_calloc(privatekeydata_len + 1, 1);
    if(!data_nullterm)
        return -1;

    memcpy(data_nullterm, privatekeydata, privatekeydata_len);
    data_nullterm[privatekeydata_len] = 0;

    mbedtls_pk_init(&pkey);

    pwd_len = passphrase ? strlen((const char *)passphrase) : 0;
    ret = mbedtls_pk_parse_key(&pkey, data_nullterm, privatekeydata_len + 1,
                               (const unsigned char *)passphrase, pwd_len,
                               mbedtls_ctr_drbg_random, &mbed_ctr_drbg);
    mbed_zero_free(data_nullterm, privatekeydata_len + 1);
=======
    if(MBEDTLS_PK_PARSE_KEYFILE(&pkey, privatekey, passphrase))
        ret = ssh2_err(session, LIBSSH2_ERROR_FILE,
                       "Failed parsing private key file");
    else
        ret = mbed_pub_priv_key(session, method, method_len,
                                pubkeydata, pubkeydata_len, &pkey);

    mbedtls_pk_free(&pkey);

    return ret;
}

int ssh2_pub_priv_keyfilememory(LIBSSH2_SESSION *session,
                                unsigned char **method,
                                size_t *method_len,
                                unsigned char **pubkeydata,
                                size_t *pubkeydata_len,
                                const char *privatekeydata,
                                size_t privatekeydata_len,
                                const char *passphrase)
{
    int ret;
    mbedtls_pk_context pkey;
    unsigned char *data_nullterm;
    size_t pwd_len;

    /* mbedtls checks in "mbedtls/pkparse.c:1184" if "key[keylen - 1] != '\0'"
       private-key from memory fails if the last byte is not a null byte */
    data_nullterm = mbedtls_calloc(privatekeydata_len + 1, 1);
    if(!data_nullterm)
        return -1;

    memcpy(data_nullterm, privatekeydata, privatekeydata_len);
    data_nullterm[privatekeydata_len] = 0;

    mbedtls_pk_init(&pkey);

    pwd_len = passphrase ? strlen((const char *)passphrase) : 0;
    ret = MBEDTLS_PK_PARSE_KEY(&pkey, data_nullterm, privatekeydata_len + 1,
                               (const unsigned char *)passphrase, pwd_len);
    mbed_zero_free(data_nullterm, privatekeydata_len + 1);
>>>>>>> 88102d08f (mbedtls: try adding 4.x support)

<<<<<<< HEAD
    if(ret) {
        mbedtls_strerror(ret, (char *)buf, sizeof(buf));
        mbedtls_pk_free(&pkey);
        return ssh2_err_flags(session, LIBSSH2_ERROR_FILE, buf,
                              SSH2_ERR_FLAG_DUP);
    }

    ret = mbed_pub_priv_key(session, method,
                            pubkeydata, pubkeydata_len, &pkey);
||||||| parent of 88102d08f (mbedtls: try adding 4.x support)
    if(ret) {
        mbedtls_strerror(ret, (char *)buf, sizeof(buf));
        mbedtls_pk_free(&pkey);
        return ssh2_err_flags(session, LIBSSH2_ERROR_FILE, buf,
                              SSH2_ERR_FLAG_DUP);
    }

    ret = mbed_pub_priv_key(session, method, method_len,
                            pubkeydata, pubkeydata_len, &pkey);
=======
    if(ret)
        ret = ssh2_err(session, LIBSSH2_ERROR_FILE,
                       "Failed parsing private key blob");
    else
        ret = mbed_pub_priv_key(session, method, method_len,
                                pubkeydata, pubkeydata_len, &pkey);
>>>>>>> 88102d08f (mbedtls: try adding 4.x support)

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

int ssh2_dh_key_pair(ssh2_dh_ctx *dhctx, ssh2_bn *pub, const ssh2_bn *g,
                     const ssh2_bn *p, int group_order, ssh2_bn_ctx *bnctx)
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

int ssh2_dh_validate(const ssh2_bn *f, const ssh2_bn *p)
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

int ssh2_dh_secret(ssh2_dh_ctx *dhctx, ssh2_bn *secret,
                   const ssh2_bn *f, const ssh2_bn *p, ssh2_bn_ctx *bnctx)
{
    (void)bnctx;

    if(ssh2_dh_validate(f, p))  /* Verify if parameters are valid */
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
    size_t plen;
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;

<<<<<<< HEAD
    *ec_ctx = SSH2_CALLOC(session, sizeof(mbedtls_ecp_keypair));
||||||| parent of 88102d08f (mbedtls: try adding 4.x support)
    *ec_ctx = mbedtls_calloc(1, sizeof(mbedtls_ecp_keypair));
=======
    *ec_ctx = mbedtls_calloc(1, sizeof(*ec_ctx));
>>>>>>> 88102d08f (mbedtls: try adding 4.x support)
    if(!*ec_ctx)
        goto failed;

    **ec_ctx = PSA_KEY_ID_NULL;

    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
    psa_set_key_type(&attr,
                     PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, (size_t)curve);
    if(psa_generate_key(&attr, *ec_ctx) != PSA_SUCCESS)
        goto failed;

    plen = PSA_EXPORT_KEY_OUTPUT_SIZE(PSA_KEY_TYPE_PUBLIC_KEY_OF_KEY_PAIR(
               PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1)),
               (size_t)curve);
    *out_public_key_octal = SSH2_ALLOC(session, plen);
    if(!*out_public_key_octal)
        goto failed;

    if(psa_export_public_key(**ec_ctx, *out_public_key_octal, plen,
                             out_public_key_octal_len) == PSA_SUCCESS)
        return 0;

failed:

<<<<<<< HEAD
    ssh2_ecdsa_free(*ec_ctx, session);
    *ec_ctx = NULL;

    ssh2_zero_free(session, *out_public_key_octal, plen);
    *out_public_key_octal = NULL;
||||||| parent of 88102d08f (mbedtls: try adding 4.x support)
    ssh2_ecdsa_free(*ec_ctx);
    *ec_ctx = NULL;
    if(*out_public_key_octal) {
        ssh2_explicit_zero(*out_public_key_octal, plen);
        SSH2_SAFEFREE(session, *out_public_key_octal);
    }
=======
    if(*ec_ctx) {
        ssh2_ecdsa_free(*ec_ctx);
        *ec_ctx = NULL;
    }
    if(*out_public_key_octal)
        SSH2_SAFEFREE(session, *out_public_key_octal);
>>>>>>> 88102d08f (mbedtls: try adding 4.x support)

    return -1;
}

/*
 * Creates a new public key given an octal string, length and type
 */
int ssh2_ecdsa_curve_name_with_octal_new(
    ssh2_ecdsa_ctx **ec_ctx, LIBSSH2_SESSION *session,
    const unsigned char *publickey_encoded, size_t publickey_encoded_len,
    ssh2_curve_type curve)
{
<<<<<<< HEAD
    (void)session;

    *ec_ctx = SSH2_CALLOC(session, sizeof(mbedtls_ecp_keypair));
||||||| parent of 88102d08f (mbedtls: try adding 4.x support)
    *ec_ctx = mbedtls_calloc(1, sizeof(mbedtls_ecp_keypair));
=======
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;

    *ec_ctx = mbedtls_calloc(1, sizeof(*ec_ctx));
>>>>>>> 88102d08f (mbedtls: try adding 4.x support)
    if(!*ec_ctx)
        goto failed;

    **ec_ctx = PSA_KEY_ID_NULL;

    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_type(&attr,
                     PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, (size_t)curve);
    if(psa_import_key(&attr, publickey_encoded, publickey_encoded_len,
                      *ec_ctx) == PSA_SUCCESS)
        return 0;

failed:

<<<<<<< HEAD
    ssh2_ecdsa_free(*ec_ctx, session);
    *ec_ctx = NULL;
||||||| parent of 88102d08f (mbedtls: try adding 4.x support)
    ssh2_ecdsa_free(*ec_ctx);
    *ec_ctx = NULL;
=======
    if(*ec_ctx) {
        ssh2_ecdsa_free(*ec_ctx);
        *ec_ctx = NULL;
    }
>>>>>>> 88102d08f (mbedtls: try adding 4.x support)

    return -1;
}

/*
 * Computes the shared secret K given a local private key,
 * remote public key and length
 */
int ssh2_ecdh_gen_k(ssh2_bn **k, LIBSSH2_SESSION *session,
                    ssh2_ec_key *private_key,
                    const unsigned char *server_public_key,
                    size_t server_public_key_len)
{
    uint8_t shared_k[PSA_RAW_KEY_AGREEMENT_OUTPUT_MAX_SIZE];
    size_t shared_k_len;
    psa_status_t ps;
    int ms;

    (void)session;

    if(!*k)
        return -1;

    ps = psa_raw_key_agreement(PSA_ALG_ECDH, *private_key,
                               server_public_key, server_public_key_len,
                               shared_k, sizeof(shared_k),
                               &shared_k_len);
    if(ps != PSA_SUCCESS) {
        ssh2_deb((session, LIBSSH2_TRACE_ERROR,
                  "ssh2_ecdh_gen_k(): psa_raw_key_agreement()->|%d|", ps));
        return -1;
    }

    ms = mbedtls_mpi_read_binary(*k, shared_k, shared_k_len);
    if(ms == 0)
        return 0;

    ssh2_deb((session, LIBSSH2_TRACE_ERROR,
              "ssh2_ecdh_gen_k(): mbedtls_mpi_read_binary()->|%d| "
              "shared_k_len=|%lu|", ms, (unsigned long)shared_k_len));

    return -1;
}

/*
 * Verifies the ECDSA signature of a hashed message
 */
int ssh2_ecdsa_verify(ssh2_ecdsa_ctx *ec_ctx, LIBSSH2_SESSION *session,
                      const unsigned char *r, size_t r_len,
                      const unsigned char *s, size_t s_len,
                      const unsigned char *m, size_t m_len)
{
<<<<<<< HEAD
    mbedtls_mpi pr, ps;
    size_t actual_len;
    int rc = -1;

    (void)session;

    mbedtls_mpi_init(&pr);
    mbedtls_mpi_init(&ps);

    if(mbedtls_mpi_read_binary(&pr, r, r_len))
        goto cleanup;

    if(mbedtls_mpi_read_binary(&ps, s, s_len))
        goto cleanup;
||||||| parent of 88102d08f (mbedtls: try adding 4.x support)
    mbedtls_mpi pr, ps;
    size_t actual_len;
    int rc = -1;

    mbedtls_mpi_init(&pr);
    mbedtls_mpi_init(&ps);

    if(mbedtls_mpi_read_binary(&pr, r, r_len))
        goto cleanup;

    if(mbedtls_mpi_read_binary(&ps, s, s_len))
        goto cleanup;
=======
    ssh2_hash_alg hash_alg;
>>>>>>> 88102d08f (mbedtls: try adding 4.x support)

    switch(ssh2_ecdsa_get_curve_type(ec_ctx)) {
    case SSH2_EC_CURVE_NISTP256:
        hash_alg = SSH2_SHA256_ALG;
        break;
    case SSH2_EC_CURVE_NISTP384:
        hash_alg = SSH2_SHA384_ALG;
        break;
    case SSH2_EC_CURVE_NISTP521:
        hash_alg = SSH2_SHA512_ALG;
        break;
    default:
        return -1;
    }

    /* FIXME: use r */
    (void)r;
    (void)r_len;

    if(psa_verify_message(*ec_ctx, PSA_ALG_ECDSA(hash_alg),
                          m, m_len, s, s_len) != PSA_SUCCESS)
        return -1;

    return 0;
}

<<<<<<< HEAD
||||||| parent of 88102d08f (mbedtls: try adding 4.x support)
static int mbed_parse_eckey(ssh2_ecdsa_ctx **ctx, mbedtls_pk_context *pkey,
                            const unsigned char *data, size_t data_len,
                            const unsigned char *pwd)
{
    size_t pwd_len;

    pwd_len = pwd ? strlen((const char *)pwd) : 0;

    if(mbedtls_pk_parse_key(pkey, data, data_len, pwd, pwd_len,
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

=======
static int mbed_parse_eckey(ssh2_ecdsa_ctx **ec_ctx, mbedtls_pk_context *pkey,
                            const unsigned char *data, size_t data_len,
                            const unsigned char *pwd)
{
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    size_t pwd_len = pwd ? strlen((const char *)pwd) : 0;

    *ec_ctx = mbedtls_calloc(1, sizeof(*ec_ctx));
    if(!*ec_ctx)
        goto failed;

    **ec_ctx = PSA_KEY_ID_NULL;

    if(MBEDTLS_PK_PARSE_KEY(pkey, data, data_len, pwd, pwd_len))
        goto failed;

    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_HASH);
    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    if(!mbedtls_pk_import_into_psa(pkey, &attr, *ec_ctx))
        return 0;

failed:

    if(*ec_ctx) {
        ssh2_ecdsa_free(*ec_ctx);
        *ec_ctx = NULL;
    }

    return -1;
}

>>>>>>> 88102d08f (mbedtls: try adding 4.x support)
/*
 * returns key curve type that maps to ssh2_curve_type
 */
ssh2_curve_type ssh2_ecdsa_get_curve_type(const ssh2_ecdsa_ctx *ec_ctx)
{
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;

    if(psa_get_key_attributes(*ec_ctx, &attr) == PSA_SUCCESS) {
        size_t bits = psa_get_key_bits(&attr);
        psa_reset_key_attributes(&attr);

        if(bits == 256)
            return SSH2_EC_CURVE_NISTP256;
        else if(bits == 384)
            return SSH2_EC_CURVE_NISTP384;
        else if(bits == 521)
            return SSH2_EC_CURVE_NISTP521;
    }

    return SSH2_EC_CURVE_NONE;
}

<<<<<<< HEAD
static int mbed_parse_openssh_key(ssh2_ecdsa_ctx **ctx,
||||||| parent of 88102d08f (mbedtls: try adding 4.x support)
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
=======
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

static int mbed_parse_openssh_key(ssh2_ecdsa_ctx **ec_ctx,
>>>>>>> 88102d08f (mbedtls: try adding 4.x support)
                                  LIBSSH2_SESSION *session,
                                  const char *data, size_t data_len,
                                  const char *passphrase)
{
<<<<<<< HEAD
||||||| parent of 88102d08f (mbedtls: try adding 4.x support)
    ssh2_curve_type type;
    unsigned char *name = NULL;
=======
    int ret = -1;
    ssh2_curve_type type;
    unsigned char *name = NULL;
>>>>>>> 88102d08f (mbedtls: try adding 4.x support)
    struct string_buf *decrypted = NULL;
<<<<<<< HEAD
    char *name = NULL;
    unsigned char *curvebuf, *exponent, *pointbuf;
    size_t name_len, curvebuf_len, exponent_len, pointbuf_len;
    ssh2_curve_type curve;
||||||| parent of 88102d08f (mbedtls: try adding 4.x support)
    size_t curvelen, exponentlen, pointlen;
    unsigned char *curve, *exponent, *point_buf;
=======
    size_t curvelen, exponentlen, pointlen;
    unsigned char *curve, *exponent, *point_buf;
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;

    *ec_ctx = mbedtls_calloc(1, sizeof(*ec_ctx));
    if(!*ec_ctx)
        goto cleanup;

    **ec_ctx = PSA_KEY_ID_NULL;
>>>>>>> 88102d08f (mbedtls: try adding 4.x support)

<<<<<<< HEAD
    if(ssh2_openssh_pem_parse(session, NULL, data, data_len,
                              passphrase, &decrypted))
        goto failed;

    if(ssh2_get_chars(decrypted, &name, &name_len))
        goto failed;

    if(ssh2_pem_ecdsa_curve_type_from_name(name, name_len, &curve))
        goto failed;

    if(ssh2_get_string(decrypted, &curvebuf, &curvebuf_len))
        goto failed;

    if(ssh2_get_string(decrypted, &pointbuf, &pointbuf_len))
        goto failed;

    if(ssh2_get_bignum_bytes(decrypted, &exponent, &exponent_len))
        goto failed;

    *ctx = SSH2_CALLOC(session, sizeof(ssh2_ecdsa_ctx));
    if(!*ctx)
        goto failed;

    mbedtls_ecdsa_init(*ctx);

    if(mbedtls_ecp_group_load(&(*ctx)->MBEDTLS_PRIVATE(grp),
                              (mbedtls_ecp_group_id)curve))
        goto failed;

    if(mbedtls_mpi_read_binary(&(*ctx)->MBEDTLS_PRIVATE(d),
                               exponent, exponent_len))
        goto failed;

    if(mbedtls_ecp_mul(&(*ctx)->MBEDTLS_PRIVATE(grp),
                       &(*ctx)->MBEDTLS_PRIVATE(Q),
                       &(*ctx)->MBEDTLS_PRIVATE(d),
                       &(*ctx)->MBEDTLS_PRIVATE(grp).G,
                       mbedtls_ctr_drbg_random, &mbed_ctr_drbg))
        goto failed;

    if(mbedtls_ecp_check_privkey(&(*ctx)->MBEDTLS_PRIVATE(grp),
                                 &(*ctx)->MBEDTLS_PRIVATE(d)) == 0)
||||||| parent of 88102d08f (mbedtls: try adding 4.x support)
    if(ssh2_openssh_pem_parse_memory(session, pwd,
                                     (const char *)data, data_len,
                                     &decrypted))
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
=======
    if(ssh2_openssh_pem_parse_memory(session, pwd,
                                     (const char *)data, data_len,
                                     &decrypted))
>>>>>>> 88102d08f (mbedtls: try adding 4.x support)
        goto cleanup;

    if(ssh2_get_string(decrypted, &name, NULL))
        goto cleanup;
    if(mbed_ecdsa_curve_type_from_name((const char *)name, &type))
        goto cleanup;
    if(ssh2_get_string(decrypted, &curve, &curvelen))
        goto cleanup;
    if(ssh2_get_string(decrypted, &point_buf, &pointlen))
        goto cleanup;
    if(ssh2_get_bignum_bytes(decrypted, &exponent, &exponentlen))
        goto cleanup;

<<<<<<< HEAD
    ssh2_ecdsa_free(*ctx, session);
    *ctx = NULL;
||||||| parent of 88102d08f (mbedtls: try adding 4.x support)
    ssh2_ecdsa_free(*ctx);
    *ctx = NULL;
=======
    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, (size_t)type);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_HASH);
    if(psa_import_key(&attr, exponent, exponentlen, *ec_ctx) == PSA_SUCCESS)
        ret = 0;
    psa_reset_key_attributes(&attr);
>>>>>>> 88102d08f (mbedtls: try adding 4.x support)

cleanup:

    if(decrypted)
        ssh2_string_buf_free(session, decrypted);

    if(ret && *ec_ctx) {
        ssh2_ecdsa_free(*ec_ctx);
        *ec_ctx = NULL;
    }

    return ret;
}

/*
 * Creates a new private key given a file/blob and password
 */
int ssh2_ecdsa_new_priv(ssh2_ecdsa_ctx **ec_ctx,
                        LIBSSH2_SESSION *session,
                        const char *filename,
                        const char *blob, size_t blob_len,
                        const char *passphrase)
{
    mbedtls_pk_context pkey;
    char *data_nullterm = NULL;
    size_t data_len = 0;

    mbedtls_pk_init(&pkey);

    if(filename) {
        if(ssh2_file_to_blob(session, filename, &data_nullterm, &data_len))
            goto cleanup;
    }
    else {
        data_len = blob_len;
        data_nullterm = SSH2_ALLOC(session, data_len + 1);
        if(!data_nullterm)
            goto cleanup;
        memcpy(data_nullterm, blob, blob_len);
        data_nullterm[blob_len] = '\0';  /* for mbedtls_pk_parse_key() */
    }

    /* try mbedTLS parser */

    if(mbedtls_pk_parse_key(&pkey,
                            (const unsigned char *)data_nullterm, data_len + 1,
                            (const unsigned char *)passphrase,
                            passphrase ? strlen(passphrase) : 0,
                            mbedtls_ctr_drbg_random, &mbed_ctr_drbg) == 0 &&
       mbedtls_pk_get_type(&pkey) == MBEDTLS_PK_ECKEY) {

        *ec_ctx = SSH2_CALLOC(session, sizeof(ssh2_ecdsa_ctx));
        if(*ec_ctx) {
            mbedtls_ecdsa_init(*ec_ctx);

            if(mbedtls_ecdsa_from_keypair(*ec_ctx, mbedtls_pk_ec(pkey)) == 0)
                goto cleanup;  /* success */
        }

        ssh2_ecdsa_free(*ec_ctx, session);
        *ec_ctx = NULL;
    }

    /* try local parser */

    mbed_parse_openssh_key(ec_ctx, session, data_nullterm, data_len,
                           passphrase);

cleanup:

    ssh2_zero_free(session, data_nullterm, data_len + 1);

    mbedtls_pk_free(&pkey);

    return *ec_ctx ? 0 : -1;
}

/*
 * Computes the ECDSA signature of a previously-hashed message
 */
int ssh2_ecdsa_sign(ssh2_ecdsa_ctx *ec_ctx, LIBSSH2_SESSION *session,
                    const unsigned char *hash, size_t hash_len,
                    unsigned char **signature, size_t *signature_len)
{
    size_t sig_len = PSA_SIGNATURE_MAX_SIZE;
    ssh2_hash_alg hash_alg;

    if(hash_len == SSH2_SHA1_DIG_LEN)
        hash_alg = SSH2_SHA1_ALG;
    else if(hash_len == SSH2_SHA256_DIG_LEN)
        hash_alg = SSH2_SHA256_ALG;
    else if(hash_len == SSH2_SHA512_DIG_LEN)
        hash_alg = SSH2_SHA512_ALG;
    else {
        ssh2_err(session, LIBSSH2_ERROR_PROTO,
                 "Unsupported hash digest length");
        return -1;
    }

    *signature = SSH2_ALLOC(session, sig_len);
    if(!*signature)
        return -1;

    if(psa_sign_hash(*ec_ctx, PSA_ALG_ECDSA(hash_alg), hash, hash_len,
                     *signature, sig_len, signature_len) != PSA_SUCCESS) {
        SSH2_SAFEFREE(session, *signature);
        return -1;
    }

    /* FIXME: convert to wire format */

<<<<<<< HEAD
    mbedtls_mpi_free(&pr);
    mbedtls_mpi_free(&ps);

    ssh2_zero_free(session, tmp_sign, tmp_sign_len);

    return *signature ? 0 : -1;
||||||| parent of 88102d08f (mbedtls: try adding 4.x support)
    mbedtls_mpi_free(&pr);
    mbedtls_mpi_free(&ps);

    mbed_zero_free(tmp_sign, tmp_sign_len);

    return *signature ? 0 : -1;
=======
    return 0;
>>>>>>> 88102d08f (mbedtls: try adding 4.x support)
}

void ssh2_ecdsa_free(ssh2_ecdsa_ctx *ec_ctx, LIBSSH2_SESSION *session)
{
<<<<<<< HEAD
    if(ec_ctx) {
        mbedtls_ecdsa_free(ec_ctx);
        SSH2_FREE(session, ec_ctx);
    }
||||||| parent of 88102d08f (mbedtls: try adding 4.x support)
    mbedtls_ecdsa_free(ec_ctx);
    mbedtls_free(ec_ctx);
=======
    psa_destroy_key(*ec_ctx);
    mbedtls_free(ec_ctx);
>>>>>>> 88102d08f (mbedtls: try adding 4.x support)
}
#endif /* LIBSSH2_ECDSA */

#endif /* LIBSSH2_MBEDTLS */
