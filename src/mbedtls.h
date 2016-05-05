#include <stdlib.h>
#include <string.h>

#include <mbedtls/md5.h>
#include <mbedtls/rsa.h>
#include <mbedtls/bignum.h>
#include <mbedtls/cipher.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/sha1.h>

/* Define which features are supported. */
#define LIBSSH2_MD5             1

#define LIBSSH2_HMAC_RIPEMD     1
#define LIBSSH2_HMAC_SHA256     1
#define LIBSSH2_HMAC_SHA512     1

#define LIBSSH2_AES             1
#define LIBSSH2_AES_CTR         1
#define LIBSSH2_BLOWFISH        1
#define LIBSSH2_RC4             1
#define LIBSSH2_CAST            0
#define LIBSSH2_3DES            1

#define LIBSSH2_RSA             1
#define LIBSSH2_DSA             0

#define MD5_DIGEST_LENGTH 16
#define SHA_DIGEST_LENGTH      20
#define SHA256_DIGEST_LENGTH   32
#define SHA512_DIGEST_LENGTH   64

/*******************************************************************/
/*
 * mbedTLS backend: Global context handles
 */

mbedtls_entropy_context  _libssh2_mbedtls_entropy;
mbedtls_ctr_drbg_context _libssh2_mbedtls_ctr_drbg;

/*******************************************************************/
/*
 * mbedTLS backend: Generic functions
 */

#define libssh2_crypto_init() \
  _libssh2_mbedtls_init()
#define libssh2_crypto_exit() \
  _libssh2_mbedtls_free()

#define _libssh2_random(buf, len) \
  _libssh2_mbedtls_random(buf, len)

#define libssh2_prepare_iovec(vec, len)  /* Empty. */

/*******************************************************************/
/*
 * mbedTLS backend: Hash structure
 */

#define libssh2_sha1_ctx        mbedtls_sha1_context
#define libssh2_sha256_ctx      mbedtls_sha256_context
#define libssh2_md5_ctx         mbedtls_md5_context
#define libssh2_hmac_ctx        mbedtls_md_context_t

#define libssh2_rsa_ctx            mbedtls_rsa_context
#define _libssh2_rsa_free(rsactx)  mbedtls_rsa_free(rsactx)


 /*******************************************************************/
/*
 * mbedTLS backend: Cipher Context structure
 */
#define _libssh2_cipher_ctx         mbedtls_cipher_context_t

#define _libssh2_cipher_type(algo)  mbedtls_cipher_type_t algo

#define _libssh2_cipher_aes256ctr MBEDTLS_CIPHER_AES_256_CTR
#define _libssh2_cipher_aes192ctr MBEDTLS_CIPHER_AES_192_CTR
#define _libssh2_cipher_aes128ctr MBEDTLS_CIPHER_AES_128_CTR
#define _libssh2_cipher_aes256    MBEDTLS_CIPHER_AES_256_CBC
#define _libssh2_cipher_aes192    MBEDTLS_CIPHER_AES_192_CBC
#define _libssh2_cipher_aes128    MBEDTLS_CIPHER_AES_128_CBC
#define _libssh2_cipher_blowfish  MBEDTLS_CIPHER_BLOWFISH_CBC
#define _libssh2_cipher_arcfour   MBEDTLS_CIPHER_ARC4_128
#define _libssh2_cipher_cast5     MBEDTLS_CIPHER_NULL
#define _libssh2_cipher_3des      MBEDTLS_CIPHER_DES_EDE3_CBC

/*
 * mbedTLS backend: Cipher functions
 */

#define _libssh2_cipher_init(ctx, type, iv, secret, encrypt) \
  _libssh2_mbedtls_cipher_init(ctx, type, iv, secret, encrypt)
#define _libssh2_cipher_crypt(ctx, type, encrypt, block, blocklen) \
  _libssh2_mbedtls_cipher_crypt(ctx, type, encrypt, block, blocklen)
#define _libssh2_cipher_dtor(ctx) \
  _libssh2_mbedtls_cipher_dtor(ctx)


/*******************************************************************/
/*
 * mbedTLS backend: BigNumber Support
 */

#define _libssh2_bn_ctx int /* not used */
#define _libssh2_bn_ctx_new() 0 /* not used */
#define _libssh2_bn_ctx_free(bnctx) ((void)0) /* not used */

#define _libssh2_bn mbedtls_mpi


/*******************************************************************/
/*
 * mbedTLS backend: forward declarations
 */
void
_libssh2_mbedtls_init(void);

void
_libssh2_mbedtls_free(void);

int
_libssh2_mbedtls_random(unsigned char *buf, int len);

int
_libssh2_mbedtls_cipher_init(_libssh2_cipher_ctx *ctx,
                            _libssh2_cipher_type(type),
                            unsigned char *iv,
                            unsigned char *secret,
                            int encrypt);
int
_libssh2_mbedtls_cipher_crypt(_libssh2_cipher_ctx *ctx,
                             _libssh2_cipher_type(type),
                             int encrypt,
                             unsigned char *block,
                             size_t blocklen);
void
_libssh2_mbedtls_cipher_dtor(_libssh2_cipher_ctx *ctx);
