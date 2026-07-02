/* Copyright (C) Daniel Stenberg
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

const char *libssh2_version(int req_version_num)
{
    if(req_version_num <= LIBSSH2_VERSION_NUM)
        return LIBSSH2_VERSION;
    return NULL; /* this is not a suitable library! */
}

libssh2_crypto_engine_t libssh2_crypto_engine(void)
{
    return SSH2_CRYPTO_ENGINE;
}

static const char *ssh2_build_options =
    "crypto:"
    SSH2_CRYPTO_ENGINE_NAME
    " "
    "MD5:"
#if LIBSSH2_MD5
    "on"
#else
    "off"
#endif
    " "
    "MD5-PEM:"
#if LIBSSH2_MD5_PEM
    "on"
#else
    "off"
#endif
    " "
    "RIPEMD160:"
#if LIBSSH2_HMAC_RIPEMD
    "on"
#else
    "off"
#endif
    " "
    "DSA:"
#if LIBSSH2_DSA
    "on"
#else
    "off"
#endif
    " "
    "RSA:"
#if LIBSSH2_RSA
    "on"
#else
    "off"
#endif
    " "
    "RSA-SHA1:"
#if LIBSSH2_RSA_SHA1
    "on"
#else
    "off"
#endif
    " "
    "ECDSA:"
#if LIBSSH2_ECDSA
    "on"
#else
    "off"
#endif
    " "
    "ED25519:"
#if LIBSSH2_ED25519
    "on"
#else
    "off"
#endif
    " "
    "ML-KEM:"
#if LIBSSH2_MLKEM
    "on"
#else
    "off"
#endif
    " "
    "AES-GCM:"
#if LIBSSH2_AES_GCM
    "on"
#else
    "off"
#endif
    " "
    "AES-CTR:"
#if LIBSSH2_AES_CTR
    "on"
#else
    "off"
#endif
    " "
    "AES-CBC:"
#if LIBSSH2_AES_CBC
    "on"
#else
    "off"
#endif
    " "
    "BLOWFISH:"
#if LIBSSH2_BLOWFISH
    "on"
#else
    "off"
#endif
    " "
    "RC4:"
#if LIBSSH2_RC4
    "on"
#else
    "off"
#endif
    " "
    "CAST:"
#if LIBSSH2_CAST
    "on"
#else
    "off"
#endif
    " "
    "3DES:"
#if LIBSSH2_3DES
    "on"
#else
    "off"
#endif
    " "
    "zlib:"
#ifdef LIBSSH2_HAVE_ZLIB
    "on"
#else
    "off"
#endif
    " "
    "clear-memory:"
#ifndef LIBSSH2_NO_CLEAR_MEMORY
    "on"
#else
    "off"
#endif
    " "
    "debug-logging:"
#ifdef LIBSSH2DEBUG
    "on"
#else
    "off"
#endif
#ifdef LIBSSH2_WOLFSSL
    " "
    "debug-wolfSSL:"
#ifdef DEBUG_WOLFSSL
    "on"
#else
    "off"
#endif
#endif /* LIBSSH2_WOLFSSL */
    ;

const char *libssh2_build_options(void)
{
    return ssh2_build_options;
}
