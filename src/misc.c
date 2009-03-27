/* Copyright (c) 2004-2007, Sara Golemon <sarag@libssh2.org>
 * Copyright (c) 2009 by Daniel Stenberg
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

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#include <errno.h>

#ifdef WIN32
static int wsa2errno(void)
{
    switch (WSAGetLastError()) {
    case WSAEWOULDBLOCK:
        return EAGAIN;

    case WSAENOTSOCK:
        return EBADF;

    case WSAEINTR:
        return EINTR;

    default:
        /* It is most important to ensure errno does not stay at EAGAIN
         * when a different error occurs so just set errno to a generic
         * error */
        return EIO;
    }
}
#endif

#ifndef _libssh2_recv
/* _libssh2_recv
 *
 * Wrapper around standard recv to allow WIN32 systems
 * to set errno
 */
ssize_t
_libssh2_recv(int socket, void *buffer, size_t length, int flags)
{
    ssize_t rc = recv(socket, buffer, length, flags);
#ifdef WIN32
    if (rc < 0 )
        errno = wsa2errno();
#endif
    return rc;
}
#endif /* _libssh2_recv */

#ifndef _libssh2_send

/* _libssh2_send
 *
 * Wrapper around standard send to allow WIN32 systems
 * to set errno
 */
ssize_t
_libssh2_send(int socket, const void *buffer, size_t length, int flags)
{
    ssize_t rc = send(socket, buffer, length, flags);
#ifdef WIN32
    if (rc < 0 )
        errno = wsa2errno();
#endif
    return rc;
}
#endif /* _libssh2_recv */

/* libssh2_ntohu32
 */
unsigned int
_libssh2_ntohu32(const unsigned char *buf)
{
    return (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3];
}


/* _libssh2_ntohu64
 */
libssh2_uint64_t
_libssh2_ntohu64(const unsigned char *buf)
{
    unsigned long msl, lsl;

    msl = (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3];
    lsl = (buf[4] << 24) | (buf[5] << 16) | (buf[6] << 8) | buf[7];

    return ((libssh2_uint64_t)msl <<32) | lsl;
}

/* _libssh2_htonu32
 */
void
_libssh2_htonu32(unsigned char *buf, unsigned int value)
{
    buf[0] = (value >> 24) & 0xFF;
    buf[1] = (value >> 16) & 0xFF;
    buf[2] = (value >> 8) & 0xFF;
    buf[3] = value & 0xFF;
}

/* Base64 Conversion */

static const char base64_table[] =
{
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
    'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/', '\0'
};

static const char base64_pad = '=';

static const short base64_reverse_table[256] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
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

/* libssh2_base64_decode
 *
 * Decode a base64 chunk and store it into a newly alloc'd buffer
 */
LIBSSH2_API int
libssh2_base64_decode(LIBSSH2_SESSION * session, char **data,
                      unsigned int *datalen, const char *src,
                      unsigned int src_len)
{
    unsigned char *s, *d;
    short v;
    int i = 0, len = 0;

    *data = LIBSSH2_ALLOC(session, (3 * src_len / 4) + 1);
    d = (unsigned char *) *data;
    if (!d) {
        return -1;
    }

    for(s = (unsigned char *) src; ((char *) s) < (src + src_len); s++) {
        if ((v = base64_reverse_table[*s]) < 0)
            continue;
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
        /* Invalid -- We have a byte which belongs exclusively to a partial
           octet */
        LIBSSH2_FREE(session, *data);
        return -1;
    }

    *datalen = len;
    return 0;
}

#ifdef LIBSSH2DEBUG
LIBSSH2_API int
libssh2_trace(LIBSSH2_SESSION * session, int bitmask)
{
    session->showmask = bitmask;
    return 0;
}

void
_libssh2_debug(LIBSSH2_SESSION * session, int context, const char *format, ...)
{
    char buffer[1536];
    int len;
    va_list vargs;
    struct timeval now;
    static int firstsec;
    static const char *const contexts[9] = {
        "Unknown",
        "Transport",
        "Key Ex",
        "Userauth",
        "Conn",
        "SCP",
        "SFTP",
        "Failure Event",
        "Publickey",
    };

    if (context < 1 || context > 8) {
        context = 0;
    }
    if (!(session->showmask & (1 << context))) {
        /* no such output asked for */
        return;
    }
    gettimeofday(&now, NULL);
    if(!firstsec) {
        firstsec = now.tv_sec;
    }
    now.tv_sec -= firstsec;

    len = snprintf(buffer, sizeof(buffer), "[libssh2] %d.%06d %s: ",
                   (int)now.tv_sec, (int)now.tv_usec, contexts[context]);

    va_start(vargs, format);
    len += vsnprintf(buffer + len, 1535 - len, format, vargs);
    buffer[len] = '\n';
    va_end(vargs);
    write(2, buffer, len + 1);

}

#else
LIBSSH2_API int
libssh2_trace(LIBSSH2_SESSION * session, int bitmask)
{
    (void) session;
    (void) bitmask;
    return 0;
}
#endif
