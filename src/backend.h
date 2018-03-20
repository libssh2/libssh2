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

#ifndef LIBSSH2_BACKEND_H
#define LIBSSH2_BACKEND_H

/**
 * Definitions needed to implement a specific crypto library
 *
 * This document offers some hints about implementing a new crypto library
 * interface.
 *
 * A crypto library interface consists of at least a header file, defining
 * entities referenced from the libssh2 core modules.
 * Real code implementation (if needed), is left at the implementor's choice.
 *
 * This document lists the entities that must/may be defined in the header file.
 *
 * Procedures listed as "void" may indeed have a result type: void indicates
 * the libssh2 core modules never use the function result.
 */

#define MD5_DIGEST_LENGTH 16
#define SHA1_DIGEST_LENGTH 20
#define SHA256_DIGEST_LENGTH 32
#define SHA384_DIGEST_LENGTH 48
#define SHA512_DIGEST_LENGTH 64
#define RIPEMD160_DIGEST_LENGTH 20

typedef enum {
    libssh2_hash_MD5 = 1,
    libssh2_hash_SHA1,
    libssh2_hash_SHA256,
    libssh2_hash_SHA384,
    libssh2_hash_SHA512,
    libssh2_hash_RIPEMD160,
} libssh2_hash_algorithm;

/* Initializes the crypto library. */
extern void libssh2_crypto_init(void);

/* Terminates the crypto library use. */
extern void libssh2_crypto_exit(void);

/* Hashing */
typedef struct libssh2_hash_ctx {
    char __private[256];
} libssh2_hash_ctx;

/*
 * Hash a message.
 *
 * This function hashes the given message with the given algorithm and
 * returns the result in out.
 *
 * Returns 0 on success, -1 on error.
 */
int libssh2_hash(libssh2_hash_algorithm algo,
                 const void *message, size_t len,
                 void *output);

/*
 * Initialise a hashing context.
 *
 * Returns 0 on success, -1 on error.
 */
int libssh2_hash_init(libssh2_hash_ctx *ctx, libssh2_hash_algorithm algo);

/*
 * Update a hash
 *
 * Updates the hash with the given data.
 *
 * Returns 0 on success, -1 on error.
 */
int libssh2_hash_update(libssh2_hash_ctx ctx,
                        const void *data, size_t datalen);

/*
 * Finalize a hash.
 *
 * Returns the final result of the hashing.
 *
 * Returns 0 on success, -1 on error.
 */
int libssh2_hash_final(libssh2_hash_ctx ctx, void *output);

/*
 * Return the hash size for a given algorithm.
 *
 * Returns the hash length on success, -1 on error.
 */
int libssh2_hash_size(libssh2_hash_algorithm algo);


/* HMAC */

/* Type of an HMAC computation context. Generally a struct.
 * Used for all hash algorithms.
 */
typedef struct libssh2_hmac_ctx {
    char __private[288];
} libssh2_hmac_ctx;

/*
 * Initialize a HMAC context.
 *
 * Setup the HMAC for hashing with the given hash algorithm and key.
 * Returns 0 on success, -1 on error.
 */
int libssh2_hmac_init(libssh2_hmac_ctx *ctx,
                      libssh2_hash_algorithm algo,
                      const void *key,
                      size_t keylen);

/*
 * Update a HMAC
 *
 * Continue computation of an HMAC on datalen bytes at data using context ctx.
 * Returns 0 on success, -1 on error.
 */
int libssh2_hmac_update(libssh2_hmac_ctx ctx,
                        const void *data, size_t datalen);

/*
 * Finalize a HMAC
 *
 * Get the computed HMAC from context ctx into the output buffer.
 * The minimum data buffer size depends on the HMAC hash algorithm.
 *
 * Returns 0 on success, -1 on error.
 */
int libssh2_hmac_final(libssh2_hmac_ctx ctx, void *output);

/*
 * Releases the HMAC computation context at ctx.
 *
 * Returns 0 on success, -1 on error.
 */
int libssh2_hmac_cleanup(libssh2_hmac_ctx ctx);

/** Compatibility layer */

#define libssh2_sha1_ctx libssh2_hash_ctx
#define libssh2_sha1_init(c) (libssh2_hash_init(c, libssh2_hash_SHA1) == 0)
#define libssh2_sha1_update(c, d, l) libssh2_hash_update(c, d, l)
#define libssh2_sha1_final(c, o) libssh2_hash_final(c, o)
#define libssh2_sha1(m, l, o) libssh2_hash(libssh2_hash_SHA1, m, l, o)

#define libssh2_sha256_ctx libssh2_hash_ctx
#define libssh2_sha256_init(c) (libssh2_hash_init(c, libssh2_hash_SHA256) == 0)
#define libssh2_sha256_update(c, d, l) libssh2_hash_update(c, d, l)
#define libssh2_sha256_final(c, o) libssh2_hash_final(c, o)
#define libssh2_sha256(m, l, o) libssh2_hash(libssh2_hash_SHA256, m, l, o)

#define libssh2_sha384_ctx libssh2_hash_ctx
#define libssh2_sha384_init(c) (libssh2_hash_init(c, libssh2_hash_SHA384) == 0)
#define libssh2_sha384_update(c, d, l) libssh2_hash_update(c, d, l)
#define libssh2_sha384_final(c, o) libssh2_hash_final(c, o)
#define libssh2_sha384(m,l,o) libssh2_hash(libssh2_hash_SHA384, m, l, o)

#define libssh2_sha512_ctx libssh2_hash_ctx
#define libssh2_sha512_init(c) (libssh2_hash_init(c, libssh2_hash_SHA512) == 0)
#define libssh2_sha512_update(c, d, l) libssh2_hash_update(c, d, l)
#define libssh2_sha512_final(c, o) libssh2_hash_final(c, o)
#define libssh2_sha512(m,l,o) libssh2_hash(libssh2_hash_SHA512, m, l, o)

#define libssh2_md5_ctx libssh2_hash_ctx
#define libssh2_md5_init(c) (libssh2_hash_init(c, libssh2_hash_MD5) == 0)
#define libssh2_md5_update(c, d, l) libssh2_hash_update(c, d, l)
#define libssh2_md5_final(c, o) libssh2_hash_final(c, o)

#define libssh2_hmac_ctx_init(ctx) /* Nothing */
#define libssh2_hmac_md5_init(ctx, data, len) \
    libssh2_hmac_init(ctx, libssh2_hash_MD5, data, len)
#define libssh2_hmac_sha1_init(ctx, data, len) \
    libssh2_hmac_init(ctx, libssh2_hash_SHA1, data, len)
#define libssh2_hmac_sha256_init(ctx, data, len) \
    libssh2_hmac_init(ctx, libssh2_hash_SHA256, data, len)
#define libssh2_hmac_sha512_init(ctx, data, len) \
    libssh2_hmac_init(ctx, libssh2_hash_SHA512, data, len)
#define libssh2_hmac_ripemd160_init(ctx, data, len) \
    libssh2_hmac_init(ctx, libssh2_hash_RIPEMD160, data, len)

#endif /* LIBSSH2_BACKEND_H */
