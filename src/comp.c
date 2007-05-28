/* Copyright (c) 2004-2007, Sara Golemon <sarag@libssh2.org>
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
 */

#include "libssh2_priv.h"
#ifdef LIBSSH2_HAVE_ZLIB
# include <zlib.h>
#endif

/* ********
   * none *
   ******** */

/* {{{ libssh2_comp_method_none_comp
 * Minimalist compression: Absolutely none
 */
static int libssh2_comp_method_none_comp(LIBSSH2_SESSION *session,
                     int compress,
                     unsigned char **dest,
                     unsigned long *dest_len,
                     unsigned long payload_limit,
                     int *free_dest,
                     const unsigned char *src,
                     unsigned long src_len,
                     void **abstract)
{
    (void)session;
    (void)compress;
    (void)payload_limit;
    (void)abstract;
    *dest = (unsigned char *)src;
    *dest_len = src_len;

    *free_dest = 0;

    return 0;
}
/* }}} */

static const LIBSSH2_COMP_METHOD libssh2_comp_method_none = {
    "none",
    NULL,
    libssh2_comp_method_none_comp,
    NULL
};

#ifdef LIBSSH2_HAVE_ZLIB
/* ********
   * zlib *
   ******** */

/* {{{ Memory management wrappers
 * Yes, I realize we're doing a callback to a callback,
 * Deal...
 */

static voidpf libssh2_comp_method_zlib_alloc(voidpf opaque, uInt items, uInt size)
{
    LIBSSH2_SESSION *session = (LIBSSH2_SESSION*)opaque;

    return (voidpf)LIBSSH2_ALLOC(session, items * size);
}

static void libssh2_comp_method_zlib_free(voidpf opaque, voidpf address)
{
    LIBSSH2_SESSION *session = (LIBSSH2_SESSION*)opaque;

    LIBSSH2_FREE(session, address);
}
/* }}} */

/* {{{ libssh2_comp_method_zlib_init
 * All your bandwidth are belong to us (so save some)
 */
static int libssh2_comp_method_zlib_init(LIBSSH2_SESSION *session, int compress, void **abstract)
{
    z_stream *strm;
    int status;

    strm = LIBSSH2_ALLOC(session, sizeof(z_stream));
    if (!strm) {
        libssh2_error(session, LIBSSH2_ERROR_ALLOC, "Unable to allocate memory for zlib compression/decompression", 0);
        return -1;
    }
    memset(strm, 0, sizeof(z_stream));

    strm->opaque = (voidpf)session;
    strm->zalloc = (alloc_func)libssh2_comp_method_zlib_alloc;
    strm->zfree = (free_func)libssh2_comp_method_zlib_free;
    if (compress) {
        /* deflate */
        status = deflateInit(strm, Z_DEFAULT_COMPRESSION);
    } else {
        /* inflate */
        status = inflateInit(strm);
    }

    if (status != Z_OK) {
        LIBSSH2_FREE(session, strm);
        return -1;
    }
    *abstract = strm;

    return 0;
}
/* }}} */

/* {{{ libssh2_comp_method_zlib_comp
 * zlib, a compression standard for all occasions
 */
static int libssh2_comp_method_zlib_comp(LIBSSH2_SESSION *session,
                     int compress,
                     unsigned char **dest,
                     unsigned long *dest_len,
                     unsigned long payload_limit,
                     int *free_dest,
                     const unsigned char *src,
                     unsigned long src_len,
                     void **abstract)
{
    z_stream *strm = *abstract;
    /* A short-term alloc of a full data chunk is better than a series of
       reallocs */
    char *out;
    int out_maxlen = compress ? (src_len + 4) : (2 * src_len);
    int limiter = 0;

    /* In practice they never come smaller than this */
    if (out_maxlen < 25) {
        out_maxlen = 25;
    }

    if (out_maxlen > (int)payload_limit) {
        out_maxlen = payload_limit;
    }

    strm->next_in = (unsigned char *)src;
    strm->avail_in = src_len;
    strm->next_out = (unsigned char *)LIBSSH2_ALLOC(session, out_maxlen);
    out = (char *)strm->next_out;
    strm->avail_out = out_maxlen;
    if (!strm->next_out) {
        libssh2_error(session, LIBSSH2_ERROR_ALLOC, "Unable to allocate compression/decompression buffer", 0);
        return -1;
    }
    while (strm->avail_in) {
        int status;

        if (compress) {
            status = deflate(strm, Z_PARTIAL_FLUSH);
        } else {
            status = inflate(strm, Z_PARTIAL_FLUSH);
        }
        if (status != Z_OK) {
            libssh2_error(session, LIBSSH2_ERROR_ZLIB, "compress/decompression failure", 0);
            LIBSSH2_FREE(session, out);
            return -1;
        }
        if (strm->avail_in) {
            unsigned long out_ofs = out_maxlen - strm->avail_out;
            char *newout;

            out_maxlen += compress ? (strm->avail_in + 4) : (2 * strm->avail_in);

            if ((out_maxlen > (int)payload_limit) &&
                !compress && limiter++) {
                libssh2_error(session, LIBSSH2_ERROR_ZLIB,
                          "Excessive growth in decompression phase", 0);
                LIBSSH2_FREE(session, out);
                return -1;
            }

            newout = LIBSSH2_REALLOC(session, out, out_maxlen);
            if (!newout) {
                libssh2_error(session, LIBSSH2_ERROR_ALLOC, "Unable to expand compress/decompression buffer", 0);
                LIBSSH2_FREE(session, out);
                return -1;
            }
            out = newout;
            strm->next_out = (unsigned char *)out + out_ofs;
            strm->avail_out += compress ? (strm->avail_in + 4) : (2 * strm->avail_in);
        } else while (!strm->avail_out) {
            /* Done with input, might be a byte or two in internal buffer during compress
             * Or potentially many bytes if it's a decompress
             */
            int grow_size = compress ? 8 : 1024;
            char *newout;

            if (out_maxlen >= (int)payload_limit) {
                libssh2_error(session, LIBSSH2_ERROR_ZLIB, "Excessive growth in decompression phase", 0);
                LIBSSH2_FREE(session, out);
                return -1;
            }

            if (grow_size > (int)(payload_limit - out_maxlen)) {
                grow_size = payload_limit - out_maxlen;
            }

            out_maxlen += grow_size;
            strm->avail_out = grow_size;

            newout = LIBSSH2_REALLOC(session, out, out_maxlen);
            if (!newout) {
                libssh2_error(session, LIBSSH2_ERROR_ALLOC, "Unable to expand final compress/decompress buffer", 0);
                LIBSSH2_FREE(session, out);
                return -1;
            }
            out = newout;
            strm->next_out = (unsigned char *)out + out_maxlen -
                grow_size;

            if (compress) {
                status = deflate(strm, Z_PARTIAL_FLUSH);
            } else {
                status = inflate(strm, Z_PARTIAL_FLUSH);
            }
            if (status != Z_OK) {
                libssh2_error(session, LIBSSH2_ERROR_ZLIB, "compress/decompression failure", 0);
                LIBSSH2_FREE(session, out);
                return -1;
            }
        }
    }

    *dest = (unsigned char *)out;
    *dest_len = out_maxlen - strm->avail_out;
    *free_dest = 1;

    return 0;
}
/* }}} */

/* {{{ libssh2_comp_method_zlib_dtor
 * All done, no more compression for you
 */
static int libssh2_comp_method_zlib_dtor(LIBSSH2_SESSION *session, int compress, void **abstract)
{
    z_stream *strm = *abstract;

    if (strm) {
        if (compress) {
            /* deflate */
            deflateEnd(strm);
        } else {
            /* inflate */
            inflateEnd(strm);
        }

        LIBSSH2_FREE(session, strm);
    }

    *abstract = NULL;

    return 0;
}
/* }}} */

static const LIBSSH2_COMP_METHOD libssh2_comp_method_zlib = {
    "zlib",
    libssh2_comp_method_zlib_init,
    libssh2_comp_method_zlib_comp,
    libssh2_comp_method_zlib_dtor,
};
#endif /* LIBSSH2_HAVE_ZLIB */

/* ***********************
   * Compression Methods *
   *********************** */

static const LIBSSH2_COMP_METHOD *_libssh2_comp_methods[] = {
    &libssh2_comp_method_none,
#ifdef LIBSSH2_HAVE_ZLIB
    &libssh2_comp_method_zlib,
#endif /* LIBSSH2_HAVE_ZLIB */
    NULL
};

const LIBSSH2_COMP_METHOD **libssh2_comp_methods(void) {
    return _libssh2_comp_methods;
}

