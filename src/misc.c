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
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

/* {{{ libssh2_ntohu32
 */
unsigned long libssh2_ntohu32(const unsigned char *buf)
{
    return (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3];
}
/* }}} */

/* {{{ libssh2_ntohu64
 * Note: Some 32-bit platforms have issues with bitops on long longs
 * Work around this by doing expensive (but safer) arithmetic ops with optimization defying parentheses
 */
libssh2_uint64_t libssh2_ntohu64(const unsigned char *buf)
{
    unsigned long msl, lsl;

    msl = (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3];
    lsl = (buf[4] << 24) | (buf[5] << 16) | (buf[6] << 8) | buf[7];

    return ((msl * 65536) * 65536) + lsl;
}
/* }}} */

/* {{{ libssh2_htonu32
 */
void libssh2_htonu32(unsigned char *buf, unsigned long value)
{
    buf[0] = (value >> 24) & 0xFF;
    buf[1] = (value >> 16) & 0xFF;
    buf[2] = (value >> 8) & 0xFF;
    buf[3] = value & 0xFF;
}
/* }}} */

/* {{{ libssh2_htonu64
 */
void libssh2_htonu64(unsigned char *buf, libssh2_uint64_t value)
{
    unsigned long msl = (value / 65536) / 65536;

    buf[0] = (msl >> 24) & 0xFF;
    buf[1] = (msl >> 16) & 0xFF;
    buf[2] = (msl >> 8) & 0xFF;
    buf[3] = msl & 0xFF;

    buf[4] = (value >> 24) & 0xFF;
    buf[5] = (value >> 16) & 0xFF;
    buf[6] = (value >> 8) & 0xFF;
    buf[7] = value & 0xFF;
}
/* }}} */

/* Base64 Conversion */

/* {{{ */
static const char libssh2_base64_table[] =
    { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
      'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
      'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
      'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
      '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/', '\0'
    };

static const char libssh2_base64_pad = '=';

static const short libssh2_base64_reverse_table[256] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
    -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
    -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
};
/* }}} */


/* {{{ libssh2_base64_decode
 * Decode a base64 chunk and store it into a newly alloc'd buffer
 */
LIBSSH2_API int libssh2_base64_decode(LIBSSH2_SESSION *session, char **data, unsigned int *datalen,
                                                                const char *src, unsigned int src_len)
{
    unsigned char *s, *d;
    short v;
    int i = 0, len = 0;

    *data = LIBSSH2_ALLOC(session, (3 * src_len / 4) + 1);
    d = (unsigned char *)*data;
    if (!d) {
        return -1;
    }

    for(s = (unsigned char *)src; ((char*)s) < (src + src_len); s++) {
        if ((v = libssh2_base64_reverse_table[*s]) < 0) continue;
        switch (i % 4) {
            case 0:
                d[len] = v << 2;
                break;
            case 1:
                d[len++] |= v >> 4;
                d[len] = v << 4;
                break;
            case 2:
                d[len++] |= v >> 2;
                d[len] = v << 6;
                break;
            case 3:
                d[len++] |= v;
                break;
        }
        i++;
    }
    if ((i % 4) == 1) {
        /* Invalid -- We have a byte which belongs exclusively to a partial octet */
        LIBSSH2_FREE(session, *data);
        return -1;
    }

    *datalen = len;
    return 0;
}
/* }}} */

#ifdef LIBSSH2DEBUG
LIBSSH2_API int libssh2_trace(LIBSSH2_SESSION *session, int bitmask)
{
    session->showmask = bitmask;
    return 0;
}

void _libssh2_debug(LIBSSH2_SESSION *session, int context,
            const char *format, ...)
{
    char buffer[1536];
    int len;
    va_list vargs;
    static const char * const contexts[9] = {
        "Unknown",
        "Transport",
        "Key Exchange",
        "Userauth",
        "Connection",
        "scp",
        "SFTP Subsystem",
        "Failure Event",
        "Publickey Subsystem",
    };

    if (context < 1 || context > 8) {
        context = 0;
    }
    if (!(session->showmask & (1<<context))) {
        /* no such output asked for */
        return;
    }

    len = snprintf(buffer, 1535, "[libssh2] %s: ", contexts[context]);

    va_start(vargs, format);
    len += vsnprintf(buffer + len, 1535 - len, format, vargs);
    buffer[len] = '\n';
    va_end(vargs);
    write(2, buffer, len + 1);

}

#else
LIBSSH2_API int libssh2_trace(LIBSSH2_SESSION *session, int bitmask)
{
    (void)session;
    (void)bitmask;
    return 0;
}
#endif
