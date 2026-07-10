#ifndef LIBSSH2_CRYPTO_H
#define LIBSSH2_CRYPTO_H
/* Copyright (C) Simon Josefsson
 * Copyright (C) The Written Word, Inc.
 * Copyright (C) Daniel Stenberg
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

#if defined(LIBSSH2_OPENSSL) || defined(LIBSSH2_WOLFSSL)
#include "openssl.h"
#elif defined(LIBSSH2_LIBGCRYPT)
#include "libgcrypt.h"
#elif defined(LIBSSH2_MBEDTLS)
#include "mbedtls.h"
#elif defined(LIBSSH2_OS400QC3)
#include "os400qc3.h"
#elif defined(LIBSSH2_WINCNG)
#include "wincng.h"
#else
#error "no cryptography backend selected"
#endif

#ifndef ssh2_crypto_init
void ssh2_crypto_init(void);
#endif
#ifndef ssh2_crypto_exit
void ssh2_crypto_exit(void);
#endif
#ifndef ssh2_random
int ssh2_random(unsigned char *buf, size_t len);
#endif

#ifndef ssh2_prepare_iovec
#define ssh2_prepare_iovec(vec, len)  do {} while(0)
#endif

/* return: success = 1, error = 0 */
int ssh2_hash_init(ssh2_hash_ctx *ctx, ssh2_hash_alg alg);
#ifndef ssh2_hash_update
int ssh2_hash_update(ssh2_hash_ctx *ctx, const void *input, size_t input_len);
#endif
int ssh2_hash_final(ssh2_hash_ctx *ctx, void *digest, size_t digest_len);
int ssh2_hash(ssh2_hash_alg alg, const void *input, size_t input_len,
              void *digest, size_t digest_len);

#ifndef ssh2_hmac_alg
#define ssh2_hmac_alg    ssh2_hash_alg
#endif
#ifndef SSH2_SHA256_HMAC
#define SSH2_SHA1_HMAC   SSH2_SHA1_ALG
#define SSH2_SHA256_HMAC SSH2_SHA256_ALG
#define SSH2_SHA384_HMAC SSH2_SHA384_ALG
#define SSH2_SHA512_HMAC SSH2_SHA512_ALG
#if LIBSSH2_MD5 || LIBSSH2_MD5_PEM
#define SSH2_MD5_HMAC    SSH2_MD5_ALG
#endif
#endif

/* return: success = 1, error = 0 */
int ssh2_hmac_ctx_init(ssh2_hmac_ctx *ctx);
int ssh2_hmac_init(ssh2_hmac_ctx *ctx, ssh2_hmac_alg alg,
                   void *key, size_t key_len);
#ifndef ssh2_hmac_update
int ssh2_hmac_update(ssh2_hmac_ctx *ctx, const void *input, size_t input_len);
#endif
int ssh2_hmac_final(ssh2_hmac_ctx *ctx, void *mac, size_t mac_len);
void ssh2_hmac_cleanup(ssh2_hmac_ctx *ctx);

#if LIBSSH2_MD5 || LIBSSH2_MD5_PEM
#define SSH2_MD5_DIG_LEN                16
#endif
#if LIBSSH2_HMAC_RIPEMD
#define SSH2_RIPEMD160_DIG_LEN          20
#endif
#define SSH2_SHA1_DIG_LEN               20
#define SSH2_SHA256_DIG_LEN             32
#define SSH2_SHA384_DIG_LEN             48
#define SSH2_SHA512_DIG_LEN             64

#define SSH2_ED25519_KEY_LEN            32
#define SSH2_ED25519_PRIVATE_KEY_LEN    64
#define SSH2_ED25519_SIG_LEN            64

#define SSH2_EC_P256_PUBLIC_KEY_LEN     65
#define SSH2_EC_P384_PUBLIC_KEY_LEN     97

#define SSH2_MLKEM_SHARED_SECRET_LEN    32
#define SSH2_MLKEM_512_PRIVATE_KEY_LEN  1632
#define SSH2_MLKEM_512_PUBLIC_KEY_LEN   800
#define SSH2_MLKEM_512_CIPHERTEXT       768
#define SSH2_MLKEM_768_PRIVATE_KEY_LEN  2400
#define SSH2_MLKEM_768_PUBLIC_KEY_LEN   1184
#define SSH2_MLKEM_768_CIPHERTEXT       1088
#define SSH2_MLKEM_1024_PRIVATE_KEY_LEN 3168
#define SSH2_MLKEM_1024_PUBLIC_KEY_LEN  1568
#define SSH2_MLKEM_1024_CIPHERTEXT      1568

#if LIBSSH2_RSA
int ssh2_rsa_new(ssh2_rsa_ctx **rsa,
                 const unsigned char *edata, size_t elen,
                 const unsigned char *ndata, size_t nlen,
                 const unsigned char *ddata, size_t dlen,
                 const unsigned char *pdata, size_t plen,
                 const unsigned char *qdata, size_t qlen,
                 const unsigned char *e1data, size_t e1len,
                 const unsigned char *e2data, size_t e2len,
                 const unsigned char *coeffdata, size_t coefflen);
int ssh2_rsa_new_private(ssh2_rsa_ctx **rsa,
                         LIBSSH2_SESSION *session,
                         const char *filename,
                         const unsigned char *passphrase);
int ssh2_rsa_new_private_frommemory(ssh2_rsa_ctx **rsa,
                                    LIBSSH2_SESSION *session,
                                    const char *blob, size_t blob_len,
                                    const unsigned char *passphrase);
#if LIBSSH2_RSA_SHA1
int ssh2_rsa_sha1_sign(ssh2_rsa_ctx *rsa, LIBSSH2_SESSION *session,
                       const unsigned char *hash, size_t hash_len,
                       unsigned char **signature, size_t *signature_len);
int ssh2_rsa_sha1_verify(ssh2_rsa_ctx *rsa,
                         const unsigned char *sig, size_t sig_len,
                         const unsigned char *m, size_t m_len);
#endif
#if LIBSSH2_RSA_SHA2
int ssh2_rsa_sha2_sign(ssh2_rsa_ctx *rsa, LIBSSH2_SESSION *session,
                       const unsigned char *hash, size_t hash_len,
                       unsigned char **signature, size_t *signature_len);
int ssh2_rsa_sha2_verify(ssh2_rsa_ctx *rsa, size_t hash_len,
                         const unsigned char *sig, size_t sig_len,
                         const unsigned char *m, size_t m_len);
#endif
#ifndef ssh2_rsa_free
void ssh2_rsa_free(ssh2_rsa_ctx *rsa);
#endif
#endif

#if LIBSSH2_DSA
int ssh2_dsa_new(ssh2_dsa_ctx **dsa,
                 const unsigned char *pdata, size_t plen,
                 const unsigned char *qdata, size_t qlen,
                 const unsigned char *gdata, size_t glen,
                 const unsigned char *ydata, size_t ylen,
                 const unsigned char *xdata, size_t xlen);
int ssh2_dsa_new_private(ssh2_dsa_ctx **dsa,
                         LIBSSH2_SESSION *session,
                         const char *filename,
                         const unsigned char *passphrase);
int ssh2_dsa_new_private_frommemory(ssh2_dsa_ctx **dsa,
                                    LIBSSH2_SESSION *session,
                                    const char *blob, size_t blob_len,
                                    const unsigned char *passphrase);
int ssh2_dsa_sha1_sign(ssh2_dsa_ctx *dsa,
                       const unsigned char *hash, size_t hash_len,
                       unsigned char *signature);
int ssh2_dsa_sha1_verify(ssh2_dsa_ctx *dsa,
                         const unsigned char *sig,
                         const unsigned char *m, size_t m_len);
#ifndef ssh2_dsa_free
void ssh2_dsa_free(ssh2_dsa_ctx *dsa);
#endif
#endif

#if LIBSSH2_ECDSA
/* Maximum uncompressed EC point length for NIST P-521:
 * two 521-bit coordinates rounded up to bytes, plus 1-byte format prefix.
 */
#define EC_MAX_POINT_LEN ((((521 + 7) / 8) * 2) + 1)

int ssh2_ecdh_gen_k(ssh2_bn **k, ssh2_ec_key *private_key,
                    const unsigned char *server_public_key,
                    size_t server_public_key_len);

ssh2_curve_type ssh2_ecdsa_get_curve_type(ssh2_ecdsa_ctx *ec_ctx);

int ssh2_ecdsa_create_key(ssh2_ec_key **ec_ctx, LIBSSH2_SESSION *session,
                          unsigned char **out_public_key_octal,
                          size_t *out_public_key_octal_len,
                          ssh2_curve_type curve);

int ssh2_ecdsa_curve_name_with_octal_new(
    ssh2_ecdsa_ctx **ec_ctx,
    const unsigned char *publickey_encoded, size_t publickey_encoded_len,
    ssh2_curve_type curve);

int ssh2_ecdsa_new_private(ssh2_ecdsa_ctx **ec_ctx,
                           LIBSSH2_SESSION *session,
                           const char *filename,
                           const unsigned char *passphrase);

int ssh2_ecdsa_new_private_frommemory(ssh2_ecdsa_ctx **ec_ctx,
                                      LIBSSH2_SESSION *session,
                                      const char *blob, size_t blob_len,
                                      const unsigned char *passphrase);

int ssh2_ecdsa_sign(ssh2_ecdsa_ctx *ec_ctx, LIBSSH2_SESSION *session,
                    const unsigned char *hash, size_t hash_len,
                    unsigned char **signature, size_t *signature_len);
int ssh2_ecdsa_verify(ssh2_ecdsa_ctx *ec_ctx,
                      const unsigned char *r, size_t r_len,
                      const unsigned char *s, size_t s_len,
                      const unsigned char *m, size_t m_len);
#ifndef ssh2_ecdsa_free
void ssh2_ecdsa_free(ssh2_ecdsa_ctx *ec_ctx);
#endif
#endif /* LIBSSH2_ECDSA */

#if LIBSSH2_ED25519
int ssh2_curve25519_gen_k(
    ssh2_bn **k,
    uint8_t private_key[SSH2_ED25519_KEY_LEN],
    uint8_t server_public_key[SSH2_ED25519_KEY_LEN]);

int ssh2_curve25519_new(LIBSSH2_SESSION *session,
                        uint8_t **out_public_key,
                        uint8_t **out_private_key);

int ssh2_ed25519_new_public(ssh2_ed25519_ctx **ed_ctx,
                            LIBSSH2_SESSION *session,
                            const unsigned char *raw_pub_key,
                            const size_t key_len);

int ssh2_ed25519_new_private(ssh2_ed25519_ctx **ed_ctx,
                             LIBSSH2_SESSION *session,
                             const char *filename,
                             const uint8_t *passphrase);

int ssh2_ed25519_new_private_frommemory(ssh2_ed25519_ctx **ed_ctx,
                                        LIBSSH2_SESSION *session,
                                        const char *blob, size_t blob_len,
                                        const unsigned char *passphrase);

int ssh2_ed25519_sign(ssh2_ed25519_ctx *ed_ctx, LIBSSH2_SESSION *session,
                      uint8_t **out_sig, size_t *out_sig_len,
                      const uint8_t *message, size_t message_len);
int ssh2_ed25519_verify(ssh2_ed25519_ctx *ed_ctx, LIBSSH2_SESSION *session,
                        const uint8_t *s, size_t s_len,
                        const uint8_t *m, size_t m_len);
#endif /* LIBSSH2_ED25519 */

#if LIBSSH2_MLKEM
int ssh2_mlkem_new(LIBSSH2_SESSION *session,
                   int mlkem_size,
                   unsigned char **out_public_key,
                   unsigned char **out_private_key);

int ssh2_mlkem_get_sk(unsigned char *out_shared_key,
                      int mlkem_size,
                      uint8_t *private_key,
                      uint8_t *server_ciphertext);
#endif /* LIBSSH2_MLKEM */

int ssh2_cipher_init(ssh2_cipher_ctx *ctx, SSH2_CIPHER_T(algo),
                     unsigned char *iv, unsigned char *secret, int encrypt);
int ssh2_cipher_crypt(ssh2_cipher_ctx *ctx, SSH2_CIPHER_T(algo),
                      int encrypt, unsigned char *block, size_t blocksize,
                      int firstlast);
#ifndef ssh2_cipher_dtor
void ssh2_cipher_dtor(ssh2_cipher_ctx *ctx);
#endif

int ssh2_pub_priv_keyfile(LIBSSH2_SESSION *session,
                          unsigned char **method,
                          size_t *method_len,
                          unsigned char **pubkeydata,
                          size_t *pubkeydata_len,
                          const char *privatekey,
                          const char *passphrase);

int ssh2_pub_priv_keyfilememory(LIBSSH2_SESSION *session,
                                unsigned char **method,
                                size_t *method_len,
                                unsigned char **pubkeydata,
                                size_t *pubkeydata_len,
                                const char *privatekeydata,
                                size_t privatekeydata_len,
                                const char *passphrase);

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
                              const unsigned char *passphrase);

#ifndef ssh2_bn_ctx
#define ssh2_bn_ctx              int
#define ssh2_bn_ctx_new()        0
#define ssh2_bn_ctx_free(bnctx)  ((void)0)
#endif

#ifndef ssh2_bn_init
ssh2_bn *ssh2_bn_init(void);
void ssh2_bn_free(ssh2_bn *bn);
#endif
#ifndef ssh2_bn_set_word
int ssh2_bn_set_word(ssh2_bn *bn, uint32_t word);
size_t ssh2_bn_bits(const ssh2_bn *bn);
int ssh2_bn_from_bin(ssh2_bn *bn, const unsigned char *bin, size_t len);
int ssh2_bn_to_bin(const ssh2_bn *bn, unsigned char *bin);
#endif
#ifndef ssh2_bn_init_from_bin
#define ssh2_bn_init_from_bin()  ssh2_bn_init()
#endif

void ssh2_dh_init(ssh2_dh_ctx *dhctx);
int ssh2_dh_key_pair(ssh2_dh_ctx *dhctx, ssh2_bn *pub, ssh2_bn *g,
                     ssh2_bn *p, int group_order, ssh2_bn_ctx *bnctx);
int ssh2_dh_is_valid(ssh2_bn *f, ssh2_bn *p); /* for unit tests */
int ssh2_dh_secret(ssh2_dh_ctx *dhctx, ssh2_bn *secret, ssh2_bn *f,
                   ssh2_bn *p, ssh2_bn_ctx *bnctx);
void ssh2_dh_dtor(ssh2_dh_ctx *dhctx);

#if LIBSSH2_RSA
#define PEM_RSA_HEADER "-----BEGIN RSA PRIVATE KEY-----"
#define PEM_RSA_FOOTER "-----END RSA PRIVATE KEY-----"
#endif
#if LIBSSH2_DSA
#define PEM_DSA_HEADER "-----BEGIN DSA PRIVATE KEY-----"
#define PEM_DSA_FOOTER "-----END DSA PRIVATE KEY-----"
#endif
#define OPENSSH_PRIVKEY_HEADER     "-----BEGIN OPENSSH PRIVATE KEY-----"
#define OPENSSH_PRIVKEY_FOOTER     "-----END OPENSSH PRIVATE KEY-----"
#define OPENSSH_PRIVKEY_AUTH_MAGIC "openssh-key-v1"

#endif /* LIBSSH2_CRYPTO_H */
