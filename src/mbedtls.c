#include "libssh2_priv.h"

#ifdef LIBSSH2_MBEDTLS /* compile only if we build with mbedtls */

/*******************************************************************/
/*
 * mbedTLS backend: Generic functions
 */

void
_libssh2_mbedtls_init(void)
{
    int ret;

    mbedtls_entropy_init(&_libssh2_mbedtls_entropy);
    mbedtls_ctr_drbg_init(&_libssh2_mbedtls_ctr_drbg);

    ret = mbedtls_ctr_drbg_seed(&_libssh2_mbedtls_ctr_drbg,
                                mbedtls_entropy_func,
                                &_libssh2_mbedtls_entropy, NULL, 0);
    if (ret != 0)
        mbedtls_ctr_drbg_free(&_libssh2_mbedtls_ctr_drbg);
}

void
_libssh2_mbedtls_free(void)
{
    mbedtls_ctr_drbg_free(&_libssh2_mbedtls_ctr_drbg);
    mbedtls_entropy_free(&_libssh2_mbedtls_entropy);
}

int
_libssh2_mbedtls_random(unsigned char *buf, int len)
{
    int ret;
    ret = mbedtls_ctr_drbg_random(&_libssh2_mbedtls_ctr_drbg, buf, len);
    return ret == 0 ? 0 : -1;
}


int
_libssh2_mbedtls_cipher_init(_libssh2_cipher_ctx *ctx,
                            _libssh2_cipher_type(algo),
                            unsigned char *iv,
                            unsigned char *secret,
                            int encrypt)
{
    // mbedtls_cipher_init(ctx);
    // const mbedtls_cipher_info_t *mbedtls_cipher_info_from_type( const mbedtls_cipher_type_t cipher_type );
    // int mbedtls_cipher_setup( mbedtls_cipher_context_t *ctx, const mbedtls_cipher_info_t *cipher_info );
    // int mbedtls_cipher_setkey( mbedtls_cipher_context_t *ctx, const unsigned char *key,
    //                int key_bitlen, const mbedtls_operation_t operation );
    // int mbedtls_cipher_set_iv( mbedtls_cipher_context_t *ctx,
    //                const unsigned char *iv, size_t iv_len );
    return 0;
}

int
_libssh2_mbedtls_cipher_crypt(_libssh2_cipher_ctx *ctx,
                             _libssh2_cipher_type(algo),
                             int encrypt,
                             unsigned char *block,
                             size_t blocklen)
{
    return 0;
}

void
_libssh2_mbedtls_cipher_dtor(_libssh2_cipher_ctx *ctx)
{
    mbedtls_cipher_free(ctx);
}



int
_libssh2_mbedtls_hash_init(mbedtls_md_context_t *ctx,
                          mbedtls_md_type_t mdtype, unsigned long hashlen,
                          unsigned char *key, unsigned long keylen)
{
    // if (key == NULL) no HMAC
    return 0;
}

int
_libssh2_mbedtls_hash_final(mbedtls_md_context_t *ctx,
                            unsigned char *hash)
{
    int ret;
    ret = mbedtls_md_finish(ctx, hash);
    mbedtls_md_free(ctx);
    return ret == 0 ? 0 : -1;
}

int
_libssh2_mbedtls_hash(unsigned char *data, unsigned long datalen,
                      mbedtls_md_type_t mdtype,
                      unsigned char *hash, unsigned long hashlen)
{
    return 0;
}

/*******************************************************************/
/*
 * mbedTLS backend: BigNumber functions
 */

_libssh2_bn *
_libssh2_mbedtls_bignum_init(void)
{
    _libssh2_bn *bignum;

    bignum = (_libssh2_bn *)malloc(sizeof(_libssh2_bn));
    if (bignum) {
        mbedtls_mpi_init(bignum);
    }

    return bignum;
}


/*******************************************************************/
/*
 * mbedTLS backend: RSA functions
 */

// static void *rsa_alloc_wrap( void )
// {
//     void *ctx = mbedtls_calloc( 1, sizeof( mbedtls_rsa_context ) );

//     if( ctx != NULL )
//         mbedtls_rsa_init( (mbedtls_rsa_context *) ctx, 0, 0 );

//     return( ctx );
// }

// static int rsa_sign_wrap( void *ctx, mbedtls_md_type_t md_alg,
//                    const unsigned char *hash, size_t hash_len,
//                    unsigned char *sig, size_t *sig_len,
//                    int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
// {
//     *sig_len = ((mbedtls_rsa_context *) ctx)->len;

//     return( mbedtls_rsa_pkcs1_sign( (mbedtls_rsa_context *) ctx, f_rng, p_rng, MBEDTLS_RSA_PRIVATE,
//                 md_alg, (unsigned int) hash_len, hash, sig ) );
// }


int
_libssh2_mbedtls_rsa_new(libssh2_rsa_ctx **rsa,
                        const unsigned char *edata,
                        unsigned long elen,
                        const unsigned char *ndata,
                        unsigned long nlen,
                        const unsigned char *ddata,
                        unsigned long dlen,
                        const unsigned char *pdata,
                        unsigned long plen,
                        const unsigned char *qdata,
                        unsigned long qlen,
                        const unsigned char *e1data,
                        unsigned long e1len,
                        const unsigned char *e2data,
                        unsigned long e2len,
                        const unsigned char *coeffdata,
                        unsigned long coefflen)
{
    int ret = 0;
    return (ret == 1) ? 0 : -1;
}

int
_libssh2_mbedtls_rsa_new_private(libssh2_rsa_ctx **rsa,
                                LIBSSH2_SESSION *session,
                                const char *filename,
                                const unsigned char *passphrase)
{
    int ret = 0;
    return (ret == 1) ? 0 : -1;
}

int
_libssh2_mbedtls_rsa_new_private_frommemory(libssh2_rsa_ctx **rsa,
                                           LIBSSH2_SESSION *session,
                                           const char *filedata,
                                           size_t filedata_len,
                                           unsigned const char *passphrase)
{
    int ret = 0;
    return (ret == 1) ? 0 : -1;
}

int
_libssh2_mbedtls_rsa_sha1_verify(libssh2_rsa_ctx *rsa,
                                const unsigned char *sig,
                                unsigned long sig_len,
                                const unsigned char *m,
                                unsigned long m_len)
{
    int ret = 0;
    return (ret == 1) ? 0 : -1;
}

int
_libssh2_mbedtls_rsa_sha1_sign(LIBSSH2_SESSION *session,
                              libssh2_rsa_ctx *rsa,
                              const unsigned char *hash,
                              size_t hash_len,
                              unsigned char **signature,
                              size_t *signature_len)
{
    int ret = 0;
    return (ret == 1) ? 0 : -1;
}

void
_libssh2_mbedtls_rsa_free(libssh2_rsa_ctx *ctx)
{
    mbedtls_rsa_free(ctx);
    mbedtls_free(ctx);
}

int
_libssh2_mbedtls_pub_priv_keyfile(LIBSSH2_SESSION *session,
                                 unsigned char **method,
                                 size_t *method_len,
                                 unsigned char **pubkeydata,
                                 size_t *pubkeydata_len,
                                 const char *privatekey,
                                 const char *passphrase)
{
    int ret = 0;
    return (ret == 1) ? 0 : -1;
}

int
_libssh2_mbedtls_pub_priv_keyfilememory(LIBSSH2_SESSION *session,
                                       unsigned char **method,
                                       size_t *method_len,
                                       unsigned char **pubkeydata,
                                       size_t *pubkeydata_len,
                                       const char *privatekeydata,
                                       size_t privatekeydata_len,
                                       const char *passphrase)
{
    int ret = 0;
    return (ret == 1) ? 0 : -1;
}

void _libssh2_init_aes_ctr(void)
{
    /* no implementation */
}
#endif /* LIBSSH2_MBEDTLS */
