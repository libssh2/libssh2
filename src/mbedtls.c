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

/*
int
_libssh2_rsa_new(libssh2_rsa_ctx ** rsa,
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
                 const unsigned char *coeffdata, unsigned long coefflen)
{
    int ret = 0;
    (void) e1data;
    (void) e1len;
    (void) e2data;
    (void) e2len;

    // if (ddata) {
    //     rc = gcry_sexp_build
    //         (rsa, NULL,
    //          "(private-key(rsa(n%b)(e%b)(d%b)(q%b)(p%b)(u%b)))",
    //          nlen, ndata, elen, edata, dlen, ddata, plen, pdata,
    //          qlen, qdata, coefflen, coeffdata);
    // } else {
    //     rc = gcry_sexp_build(rsa, NULL, "(public-key(rsa(n%b)(e%b)))",
    //                          nlen, ndata, elen, edata);
    // }
    if (ret) {
        *rsa = NULL;
        return -1;
    }

    return 0;
}
*/

// int
// _libssh2_rsa_sha1_verify(libssh2_rsa_ctx * rsactx,
//                          const unsigned char *sig,
//                          unsigned long sig_len,
//                          const unsigned char *m, unsigned long m_len)
// {
//     unsigned char hash[SHA_DIGEST_LENGTH];
//     int ret = 0;
//     return (ret == 1) ? 0 : -1;
// }

#endif /* LIBSSH2_MBEDTLS */
