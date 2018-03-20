/* Copyright (C) 2016, Etienne Samson
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
 */

#include "libssh2_priv.h"
#include <stdarg.h>

int libssh2_hash(libssh2_hash_algorithm algo,
                 const void *message, unsigned long len,
                 void *out)
{
    libssh2_hash_ctx ctx;
    int err = libssh2_hash_init(&ctx, algo);
    if (err != 0) {
        libssh2_crypto_trace("libssh2_hash: hash_ctx fail %d\n", err);
        return -1;
    }

    libssh2_hash_update(ctx, message, len);
    libssh2_hash_final(ctx, out);

    return 0;
}

int libssh2_hash_size(libssh2_hash_algorithm algo) {
    switch (algo) {
#ifdef LIBSSH2_MD5
        case libssh2_hash_MD5: return MD5_DIGEST_LENGTH;
#endif
        case libssh2_hash_SHA1: return SHA1_DIGEST_LENGTH;
        case libssh2_hash_SHA256: return SHA256_DIGEST_LENGTH;
        case libssh2_hash_SHA384: return SHA384_DIGEST_LENGTH;
#ifdef LIBSSH2_HMAC_SHA512
        case libssh2_hash_SHA512: return SHA512_DIGEST_LENGTH;
#endif
#ifdef LIBSSH2_HMAC_RIPEMD
        case libssh2_hash_RIPEMD160: return RIPEMD160_DIGEST_LENGTH;
#endif
        default: return -1;
    }
}

void libssh2_crypto_trace(const char *fmt, ...)
{
    va_list args;
    char msg[2048];

    va_start(args, fmt);
    vsprintf(msg, fmt, args);
    va_end(args);

    fprintf(stderr, "%s", msg);
}
