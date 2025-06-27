/* Copyright (C) Viktor Szakats
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef LIBSSH2_MD5_ENABLE
#undef LIBSSH2_MD5
#define LIBSSH2_MD5 0
#endif

#ifndef LIBSSH2_MD5_PEM_ENABLE
#undef LIBSSH2_MD5_PEM
#define LIBSSH2_MD5_PEM LIBSSH2_MD5
#else
#define LIBSSH2_MD5_PEM 1
#endif

#ifndef LIBSSH2_HMAC_RIPEMD_ENABLE
#undef LIBSSH2_HMAC_RIPEMD
#define LIBSSH2_HMAC_RIPEMD 0
#endif

#ifndef LIBSSH2_DSA_ENABLE
#undef LIBSSH2_DSA
#define LIBSSH2_DSA 0
#endif

#ifdef LIBSSH2_NO_RSA
#undef LIBSSH2_RSA
#define LIBSSH2_RSA 0
#endif

#ifdef LIBSSH2_NO_RSA_SHA1
#undef LIBSSH2_RSA_SHA1
#define LIBSSH2_RSA_SHA1 0
#endif

#ifdef LIBSSH2_NO_ECDSA
#undef LIBSSH2_ECDSA
#define LIBSSH2_ECDSA 0
#endif

#ifdef LIBSSH2_NO_ED25519
#undef LIBSSH2_ED25519
#define LIBSSH2_ED25519 0
#endif

#ifdef LIBSSH2_NO_AES_CTR
#undef LIBSSH2_AES_CTR
#define LIBSSH2_AES_CTR 0
#endif

#ifdef LIBSSH2_NO_AES_CBC
#undef LIBSSH2_AES_CBC
#define LIBSSH2_AES_CBC 0
#endif

#ifndef LIBSSH2_BLOWFISH_ENABLE
#undef LIBSSH2_BLOWFISH
#define LIBSSH2_BLOWFISH 0
#endif

#ifndef LIBSSH2_RC4_ENABLE
#undef LIBSSH2_RC4
#define LIBSSH2_RC4 0
#endif

#ifndef LIBSSH2_CAST_ENABLE
#undef LIBSSH2_CAST
#define LIBSSH2_CAST 0
#endif

#ifndef LIBSSH2_3DES_ENABLE
#undef LIBSSH2_3DES
#define LIBSSH2_3DES 0
#endif
