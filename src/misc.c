/* Copyright (C) Sara Golemon <sarag@libssh2.org>
 * Copyright (C) Daniel Stenberg
 * Copyright (C) Simon Josefsson
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

#include "libssh2_priv.h"

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <assert.h>

#ifdef _WIN32
/* Force parameter type. */
#define SSH2_RECV_LOW(s, b, l, f)  recv(s, b, (int)(l), f)
#define SSH2_SEND_LOW(s, b, l, f)  send(s, b, (int)(l), f)
#else
#define SSH2_RECV_LOW  recv
#define SSH2_SEND_LOW  send
#endif

#if defined(_MSC_VER) && _MSC_VER < 1900
/* snprintf is not in pre-VS2015 CRTs and _snprintf dangerously incompatible.
   Replicate standard snprintf using _vsnprintf_s and _vscprintf. */
#if _MSC_VER < 1800  /* for VS2010, VS2012 */
#define va_copy(dest, src) ((dest) = (src))
#endif
int ssh2_vsnprintf(char *buf, size_t buf_len, const char *fmt, va_list args)
{
    if(buf && buf_len) {
        int ret;
        va_list args_dupe;
        va_copy(args_dupe, args);
        ret = _vsnprintf_s(buf, buf_len, _TRUNCATE, fmt, args_dupe);
        va_end(args_dupe);
        if(ret >= 0)
            return ret;
    }
    return _vscprintf(fmt, args);
}

int ssh2_snprintf(char *buf, size_t buf_len, const char *fmt, ...)
{
    int ret;
    va_list args;
    va_start(args, fmt);
    ret = ssh2_vsnprintf(buf, buf_len, fmt, args);
    va_end(args);
    return ret;
}
#endif

int ssh2_err_flags(LIBSSH2_SESSION *session, int errcode,
                   const char *errmsg, int errflags)
{
    if(!session) {
        ssh2_deb((session, LIBSSH2_TRACE_ERROR,
                 "ssh2_err_flags: session is NULL, error: %s",
                 errmsg ? errmsg : "(null)"));
        return errcode;
    }

    if(session->err_flags & SSH2_ERR_FLAG_DUP)
        SSH2_FREE(session, SSH2_UNCONST(session->err_msg));

    session->err_code = errcode;
    session->err_flags = 0;

    if(errmsg && (errflags & SSH2_ERR_FLAG_DUP) != 0) {
        size_t len = strlen(errmsg);
        char *copy = SSH2_ALLOC(session, len + 1);
        if(copy) {
            memcpy(copy, errmsg, len + 1);
            session->err_flags = SSH2_ERR_FLAG_DUP;
            session->err_msg = copy;
        }
        else
            /* Out of memory: this code path is unlikely */
            session->err_msg = "former error forgotten (OOM)";
    }
    else
        session->err_msg = errmsg;

#ifdef LIBSSH2DEBUG
    if(errcode == LIBSSH2_ERROR_EAGAIN && !session->api_block_mode)
        /* if this is EAGAIN and we are in non-blocking mode, do not generate
           a debug output for this */
        return errcode;
    ssh2_deb((session, LIBSSH2_TRACE_ERROR, "%d - %s", session->err_code,
              session->err_msg));
#endif

    return errcode;
}

int ssh2_err(LIBSSH2_SESSION *session, int errcode, const char *errmsg)
{
    return ssh2_err_flags(session, errcode, errmsg, 0);
}

#ifdef _WIN32
int ssh2_wsa2errno(void)
{
    switch(WSAGetLastError()) {
    case WSAEWOULDBLOCK:
        return EAGAIN;

    case WSAENOTSOCK:
        return EBADF;

    case WSAEINTR:
        return EINTR;

    default:
        /* It is most important to ensure errno does not stay at EAGAIN
         * when a different error occurs so set errno to a generic error */
        return EIO;
    }
}
#endif

/*
 * Replacement for the standard recv, return -errno on failure.
 */
ssize_t ssh2_recv(libssh2_socket_t socket, void *buffer, size_t length,
                  int flags, void **abstract)
{
    ssize_t rc;

    (void)abstract;

    rc = SSH2_RECV_LOW(socket, buffer, length, flags);
    if(rc < 0) {
        int sockerr = SSH2_ERRNO();
        /* Profiling tools that use SIGPROF can cause EINTR responses.
           recv() does not modify its arguments when it returns EINTR,
           but there may be data waiting, so the caller should try again */
        if(sockerr == EINTR)
            return -EAGAIN;
        /* Sometimes the first recv() function call sets errno to ENOENT on
           Solaris and HP-UX */
        if(sockerr == ENOENT)
            return -EAGAIN;
        if(sockerr == EWOULDBLOCK)
            return -EAGAIN;
        return -sockerr;
    }
    return rc;
}

/*
 * Replacement for the standard send, return -errno on failure.
 */
ssize_t ssh2_send(libssh2_socket_t socket,
                  const void *buffer, size_t length,
                  int flags, void **abstract)
{
    ssize_t rc;

    (void)abstract;

    rc = SSH2_SEND_LOW(socket, buffer, length, flags);
    if(rc < 0) {
        int sockerr = SSH2_ERRNO();
        /* Profiling tools that use SIGPROF can cause EINTR responses.
           send() is defined as not yet sending any data when it returns EINTR,
           so the caller should try again */
        if(sockerr == EINTR)
            return -EAGAIN;
        if(sockerr == EWOULDBLOCK)
            return -EAGAIN;
        return -sockerr;
    }
    return rc;
}

uint32_t ssh2_ntohu32(const unsigned char *buf)
{
    return
        ((uint32_t)buf[0] << 24) |
        ((uint32_t)buf[1] << 16) |
        ((uint32_t)buf[2] << 8)  |
        ((uint32_t)buf[3]);
}

libssh2_uint64_t ssh2_ntohu64(const unsigned char *buf)
{
    return
        ((libssh2_uint64_t)buf[0] << 56) |
        ((libssh2_uint64_t)buf[1] << 48) |
        ((libssh2_uint64_t)buf[2] << 40) |
        ((libssh2_uint64_t)buf[3] << 32) |
        ((libssh2_uint64_t)buf[4] << 24) |
        ((libssh2_uint64_t)buf[5] << 16) |
        ((libssh2_uint64_t)buf[6] <<  8) |
        ((libssh2_uint64_t)buf[7]);
}

void ssh2_htonu32(unsigned char *buf, uint32_t value)
{
    buf[0] = (unsigned char)((value >> 24) & 0xFF);
    buf[1] = (unsigned char)((value >> 16) & 0xFF);
    buf[2] = (unsigned char)((value >> 8) & 0xFF);
    buf[3] = (unsigned char)(value & 0xFF);
}

void ssh2_store_u32(unsigned char **buf, uint32_t value)
{
    ssh2_htonu32(*buf, value);
    *buf += sizeof(uint32_t);
}

void ssh2_store_u64(unsigned char **buf, libssh2_uint64_t value)
{
    unsigned char *ptr = *buf;

    ptr[0] = (unsigned char)((value >> 56) & 0xFF);
    ptr[1] = (unsigned char)((value >> 48) & 0xFF);
    ptr[2] = (unsigned char)((value >> 40) & 0xFF);
    ptr[3] = (unsigned char)((value >> 32) & 0xFF);
    ptr[4] = (unsigned char)((value >> 24) & 0xFF);
    ptr[5] = (unsigned char)((value >> 16) & 0xFF);
    ptr[6] = (unsigned char)((value >> 8) & 0xFF);
    ptr[7] = (unsigned char)(value & 0xFF);

    *buf += sizeof(libssh2_uint64_t);
}

int ssh2_store_str(unsigned char **buf, const char *str, size_t len)
{
    uint32_t len_stored = (uint32_t)len;

    ssh2_store_u32(buf, len_stored);
    if(len_stored) {
        memcpy(*buf, str, len_stored);
        *buf += len_stored;
    }

    assert(len_stored == len);
    return len_stored == len;
}

int ssh2_store_hybrid_str(unsigned char **buf, const char *str_1,
                          size_t len_1, const char *str_2, size_t len_2)
{
    uint32_t len_stored;

    if(len_1 > UINT32_MAX - len_2)
        return 0;

    len_stored = (uint32_t)len_1 + (uint32_t)len_2;

    ssh2_store_u32(buf, len_stored);
    if(len_1) {
        memcpy(*buf, str_1, len_1);
        *buf += len_1;
    }

    if(len_2) {
        memcpy(*buf, str_2, len_2);
        *buf += len_2;
    }

    assert(len_stored == len_1 + len_2);
    return len_stored == len_1 + len_2;
}

int ssh2_store_bignum_bytes(unsigned char **buf,
                            const unsigned char *bytes, size_t len)
{
    uint32_t len_stored;
    uint32_t extraByte;
    const unsigned char *p;

    for(p = bytes; len > 0 && *p == 0; --len, ++p)
        ;

    extraByte = (len > 0 && (p[0] & 0x80) != 0);
    len_stored = (uint32_t)len;
    if(extraByte && len_stored == UINT32_MAX)
        len_stored--;
    ssh2_store_u32(buf, len_stored + extraByte);

    if(extraByte) {
        (*buf)[0] = 0;
        *buf += 1;
    }

    if(len_stored) {
        memcpy(*buf, p, len_stored);
        *buf += len_stored;
    }

    assert(len_stored == len);
    return len_stored == len;
}

int ssh2_hash(ssh2_hash_alg alg, const void *input, size_t input_len,
              void *digest, size_t digest_len)
{
    ssh2_hash_ctx ctx;
    int success = ssh2_hash_init(&ctx, alg);
    if(success) {
        success &= ssh2_hash_update(&ctx, input, input_len);
        success &= ssh2_hash_final(&ctx, digest, digest_len);
    }
    return success;
}

/* Base64 Conversion */

static const short ssh2_base64_reverse_table[256] = {
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

#ifndef LIBSSH2_NO_DEPRECATED
/*
 * Legacy public function. (DEPRECATED, DO NOT USE!)
 */
int libssh2_base64_decode(LIBSSH2_SESSION *session,
                          char **dest, unsigned int *dest_len,
                          const char *src, unsigned int src_len)
{
    int rc;
    size_t dlen;

    rc = ssh2_base64_decode(session, dest, &dlen, src, src_len);

    if(dest_len)
        *dest_len = (unsigned int)dlen;

    return rc;
}
#endif

/*
 * Decode a base64 chunk and store it into a newly alloc'd buffer
 */
int ssh2_base64_decode(LIBSSH2_SESSION *session,
                       char **data, size_t *datalen,
                       const char *src, size_t src_len)
{
    unsigned char *d;
    const char *s;
    short v;
    size_t i = 0, len = 0;

    *datalen = 0;
    *data = SSH2_ALLOC(session, src_len);
    d = (unsigned char *)*data;
    if(!d)
        return ssh2_err(session, LIBSSH2_ERROR_ALLOC,
                        "Unable to allocate memory for base64 decoding");

    for(s = src; s < (src + src_len); s++) {
        v = ssh2_base64_reverse_table[(unsigned char)*s];
        if(v < 0)
            continue;
        switch(i % 4) {
        case 0:
            d[len] = (unsigned char)(v << 2);
            break;
        case 1:
            d[len++] |= (unsigned char)(v >> 4);
            d[len] = (unsigned char)(v << 4);
            break;
        case 2:
            d[len++] |= (unsigned char)(v >> 2);
            d[len] = (unsigned char)(v << 6);
            break;
        case 3:
            d[len++] |= (unsigned char)v;
            break;
        }
        i++;
    }
    if((i % 4) == 1) {
        /* Invalid -- We have a byte which belongs exclusively to a partial
           octet */
        SSH2_SAFEFREE(session, *data);
        return ssh2_err(session, LIBSSH2_ERROR_INVAL, "Invalid base64");
    }

    *datalen = len;
    return 0;
}

/* ---- Base64 Encoding/Decoding Table --- */

static const char table64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/*
 * Returns the length of the newly created base64 string. The third argument
 * is a pointer to an allocated area holding the base64 data. If something
 * went wrong, 0 is returned.
 */
size_t ssh2_base64_encode(LIBSSH2_SESSION *session,
                          const char *inp, size_t insize, char **outptr)
{
    unsigned char ibuf[3];
    unsigned char obuf[4];
    int i;
    int inputparts;
    char *output;
    char *base64data;
    const char *indata = inp;

    *outptr = NULL; /* set to NULL in case of failure before we reach the
                       end */

    if(insize == 0)
        return 0; /* nothing to encode */

    base64data = output = SSH2_ALLOC(session, insize * 4 / 3 + 4);
    if(!output)
        return 0;

    while(insize > 0) {
        for(i = inputparts = 0; i < 3; i++) {
            if(insize > 0) {
                inputparts++;
                ibuf[i] = *indata;
                indata++;
                insize--;
            }
            else
                ibuf[i] = 0;
        }

        obuf[0] = (unsigned char) ((ibuf[0] & 0xFC) >> 2);
        obuf[1] = (unsigned char)(((ibuf[0] & 0x03) << 4) | \
                                  ((ibuf[1] & 0xF0) >> 4));
        obuf[2] = (unsigned char)(((ibuf[1] & 0x0F) << 2) | \
                                  ((ibuf[2] & 0xC0) >> 6));
        obuf[3] = (unsigned char)  (ibuf[2] & 0x3F);

        switch(inputparts) {
        case 1: /* only one byte read */
            output[0] = table64[obuf[0]];
            output[1] = table64[obuf[1]];
            output[2] = '=';
            output[3] = '=';
            break;
        case 2: /* two bytes read */
            output[0] = table64[obuf[0]];
            output[1] = table64[obuf[1]];
            output[2] = table64[obuf[2]];
            output[3] = '=';
            break;
        default:
            output[0] = table64[obuf[0]];
            output[1] = table64[obuf[1]];
            output[2] = table64[obuf[2]];
            output[3] = table64[obuf[3]];
            break;
        }
        output += 4;
    }
    *output = 0;
    *outptr = base64data; /* make it return the actual data memory */

    return strlen(base64data); /* return the length of the new data */
}

/* ---- End of Base64 Encoding ---- */

void libssh2_free(LIBSSH2_SESSION *session, void *ptr)
{
    SSH2_FREE(session, ptr);
}

#ifdef LIBSSH2DEBUG
int libssh2_trace(LIBSSH2_SESSION *session, int bitmask)
{
    if(!session)
        return LIBSSH2_ERROR_BAD_USE;
    session->showmask = bitmask;
    return LIBSSH2_ERROR_NONE;
}

int libssh2_trace_sethandler(LIBSSH2_SESSION *session, void *context,
                             libssh2_trace_handler_func callback)
{
    if(!session)
        return LIBSSH2_ERROR_BAD_USE;
    session->tracehandler = callback;
    session->tracehandler_context = context;
    return LIBSSH2_ERROR_NONE;
}

void ssh2_deb_low(LIBSSH2_SESSION *session, int context,
                  const char *format, ...)
{
    static const char * const contexts[] = {
        "Unknown",
        "Transport",
        "Key Ex",
        "Userauth",
        "Conn",
        "SCP",
        "SFTP",
        "Failure Event",
        "Publickey",
        "Socket",
    };
    static long firstsec;

    char buffer[1536];
    int len, msglen, buflen = sizeof(buffer);
    va_list vargs;
    struct timeval now;
    const char *contexttext = contexts[0];
    unsigned int contextindex;

    if(session && !(session->showmask & context))
        return;  /* no such output asked for */

    /* Find the first matching context string for this message */
    for(contextindex = 0; contextindex < SSH2_ARRAYSIZE(contexts);
        contextindex++) {
        if((context & (1 << contextindex)) != 0) {
            contexttext = contexts[contextindex];
            break;
        }
    }

    ssh2_gettimeofday(&now, NULL);
    if(!firstsec)
        firstsec = now.tv_sec;
    now.tv_sec -= firstsec;

    /* '[libssh2] 9999999999.9999999999 Failure Event: ' */
    len = ssh2_snprintf(buffer, buflen, "[libssh2] %d.%06d %s: ",
                        (int)now.tv_sec, (int)now.tv_usec, contexttext);
    if(len < 0 || len >= buflen) {
        msglen = len < 0 ? 0 : (buflen - 1);
        buffer[msglen] = '\0';
    }
    else {
        buflen -= len;
        msglen = len;
        va_start(vargs, format);
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
#endif
        len = ssh2_vsnprintf(buffer + msglen, buflen, format, vargs);
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif
        va_end(vargs);
        if(len < 0 || len >= buflen) {
            msglen += len < 0 ? 0 : (buflen - 1);
            buffer[msglen] = '\0';
        }
        else
            msglen += len;
    }

    if(session && session->tracehandler)
        session->tracehandler(session, session->tracehandler_context, buffer,
                              msglen);
    else
        /* !checksrc! disable BANNEDFUNC 1 */
        fprintf(stderr, "%s\n", buffer);
}
#else /* !LIBSSH2DEBUG */
int libssh2_trace(LIBSSH2_SESSION *session, int bitmask)
{
    (void)session;
    (void)bitmask;
    return LIBSSH2_ERROR_NONE;
}

int libssh2_trace_sethandler(LIBSSH2_SESSION *session, void *context,
                             libssh2_trace_handler_func callback)
{
    (void)session;
    (void)context;
    (void)callback;
    return LIBSSH2_ERROR_NONE;
}
#endif

/* init the list head */
void ssh2_list_init(struct list_head *head)
{
    head->first = head->last = NULL;
}

/* add a node to the list */
void ssh2_list_add(struct list_head *head, struct list_node *entry)
{
    /* store a pointer to the head */
    entry->head = head;

    /* we add this entry at the "top" so it has no next */
    entry->next = NULL;

    /* make our prev point to what the head thinks is last */
    entry->prev = head->last;

    /* and make head's last be us now */
    head->last = entry;

    /* make sure our 'prev' node points to us next */
    if(entry->prev)
        entry->prev->next = entry;
    else
        head->first = entry;
}

/* return the "first" node in the list this head points to */
void *ssh2_list_first(struct list_head *head)
{
    return head->first;
}

/* return the next node in the list */
void *ssh2_list_next(struct list_node *node)
{
    return node->next;
}

/* return the prev node in the list */
void *ssh2_list_prev(struct list_node *node)
{
    return node->prev;
}

/* remove this node from the list */
void ssh2_list_remove(struct list_node *entry)
{
    if(entry->prev)
        entry->prev->next = entry->next;
    else
        entry->head->first = entry->next;

    if(entry->next)
        entry->next->prev = entry->prev;
    else
        entry->head->last = entry->prev;
}

#if 0
/* insert a node before the given 'after' entry */
void ssh2_list_insert(struct list_node *after, /* insert before this */
                      struct list_node *entry)
{
    /* 'after' is next to 'entry' */
    entry->next = after;

    /* entry's prev is then made to be the prev after current has */
    entry->prev = after->prev;

    /* the node that is now before 'entry' was previously before 'after'
       and must be made to point to 'entry' correctly */
    if(entry->prev)
        entry->prev->next = entry;
    else
      /* there was no node before this, so we make sure we point the head
         pointer to this node */
      after->head->first = entry;

    /* after's prev entry points back to entry */
    after->prev = entry;

    /* after's next entry is still the same as before */

    /* entry's head is the same as after's */
    entry->head = after->head;
}
#endif

ssh2_time_t ssh2_now(void) /* ms */
{
#ifdef _WIN32
    ssh2_time_t sec, ns;
    LARGE_INTEGER freq, count;
    /* These never fail on supported Windows versions */
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&count);
    sec = (ssh2_time_t)(count.QuadPart / freq.QuadPart);
    ns = (ssh2_time_t)(((count.QuadPart % freq.QuadPart) *
        1000000000) / freq.QuadPart);
    return sec * 1000 + ns / 1000000;
#else /* !_WIN32 */
#if defined(CLOCK_MONOTONIC_RAW) /* Apple/Linux */
    struct timespec ts;
    if(!clock_gettime(CLOCK_MONOTONIC_RAW, &ts))
        return (ssh2_time_t)ts.tv_sec * 1000 +
            (ssh2_time_t)ts.tv_nsec / 1000000;
#elif defined(CLOCK_MONOTONIC) /* POSIX */
    struct timespec ts;
    if(!clock_gettime(CLOCK_MONOTONIC, &ts))
        return (ssh2_time_t)ts.tv_sec * 1000 +
            (ssh2_time_t)ts.tv_nsec / 1000000;
#elif defined(HAVE_GETTIMEOFDAY)
    struct timeval tv;
    if(!gettimeofday(&tv, NULL))
        return (ssh2_time_t)tv.tv_sec * 1000 + (ssh2_time_t)tv.tv_usec / 1000;
#endif
    {
        ssh2_time_t ms = (ssh2_time_t)time(NULL) * 1000;
        return ms ? ms : 1;
    }
#endif /* _WIN32 */
}

#ifndef HAVE_GETTIMEOFDAY
/*
 * Implementation according to:
 * The Open Group Base Specifications Issue 6
 * IEEE Std 1003.1, 2004 Edition
 *
 * THIS SOFTWARE IS NOT COPYRIGHTED
 *
 * This source code is offered for use in the public domain. You may
 * use, modify or distribute it freely.
 *
 * This code is distributed in the hope that it is useful but
 * WITHOUT ANY WARRANTY. ALL WARRANTIES, EXPRESS OR IMPLIED ARE HEREBY
 * DISCLAIMED. This includes but is not limited to warranties of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */
int ssh2_gettimeofday(struct timeval *tp, void *tzp)
{
    (void)tzp;
    if(tp) {
#ifdef _WIN32
/* Offset between 1601-01-01 and 1970-01-01 in 100 nanosec units */
#define SSH2_WIN32_FT_OFFSET 116444736000000000
        union {
            libssh2_uint64_t ns100; /* time since 1 Jan 1601 in 100ns units */
            FILETIME ft;
        } now;
        GetSystemTimeAsFileTime(&now.ft);
        tp->tv_usec = (long)((now.ns100 / 10) % 1000000);
        tp->tv_sec = (long)((now.ns100 - SSH2_WIN32_FT_OFFSET) / 10000000);
#else
        /* Platforms without a native implementation or local replacement */
        tp->tv_usec = 0;
        tp->tv_sec = 0;
#endif
    }
    /* Always return 0 as per Open Group Base Specifications Issue 6.
       Do not set errno on error.  */
    return 0;
}
#endif /* !HAVE_GETTIMEOFDAY */

void *ssh2_calloc(LIBSSH2_SESSION *session, size_t size)
{
    void *p = SSH2_ALLOC(session, size);
    if(p)
        memset(p, 0, size);
    return p;
}

/* XOR operation on buffers input1 and input2, result in output.
   It is safe to use an input buffer as the output buffer. */
void ssh2_xor_data(unsigned char *output,
                   const unsigned char *input1,
                   const unsigned char *input2,
                   size_t length)
{
    size_t i;

    for(i = 0; i < length; i++)
        *output++ = *input1++ ^ *input2++;
}

#ifdef LIBSSH2_MEMZERO
static void *(* const volatile memset_libssh)(void *, int, size_t) = memset;

void ssh2_memzero(void *buf, size_t size)
{
    memset_libssh(buf, 0, size);
}
#endif

/* String buffer */

struct string_buf *ssh2_string_buf_new(LIBSSH2_SESSION *session)
{
    struct string_buf *ret;

    ret = ssh2_calloc(session, sizeof(*ret));
    if(!ret)
        return NULL;

    return ret;
}

void ssh2_string_buf_free(LIBSSH2_SESSION *session, struct string_buf *buf)
{
    if(!buf)
        return;

    if(buf->data)
        SSH2_FREE(session, buf->data);

    SSH2_FREE(session, buf);
}

int ssh2_get_byte(struct string_buf *buf, unsigned char *out)
{
    if(!ssh2_check_length(buf, 1))
        return -1;

    *out = buf->dataptr[0];
    buf->dataptr += 1;
    return 0;
}

int ssh2_get_boolean(struct string_buf *buf, unsigned char *out)
{
    if(!ssh2_check_length(buf, 1))
        return -1;

    *out = buf->dataptr[0] == 0 ? 0 : 1;
    buf->dataptr += 1;
    return 0;
}

int ssh2_get_u32(struct string_buf *buf, uint32_t *out)
{
    if(!ssh2_check_length(buf, 4))
        return -1;

    *out = ssh2_ntohu32(buf->dataptr);
    buf->dataptr += 4;
    return 0;
}

int ssh2_get_u64(struct string_buf *buf, libssh2_uint64_t *out)
{
    if(!ssh2_check_length(buf, 8))
        return -1;

    *out = ssh2_ntohu64(buf->dataptr);
    buf->dataptr += 8;
    return 0;
}

int ssh2_match_string(struct string_buf *buf, const char *match)
{
    unsigned char *out;
    size_t len = 0;
    if(ssh2_get_string(buf, &out, &len) || len != strlen(match) ||
       strncmp((const char *)out, match, strlen(match)))
        return -1;
    return 0;
}

int ssh2_get_string(struct string_buf *buf, unsigned char **outbuf,
                    size_t *outlen)
{
    uint32_t data_len;
    if(!buf || ssh2_get_u32(buf, &data_len) != 0)
        return -1;
    if(!ssh2_check_length(buf, data_len))
        return -1;
    *outbuf = buf->dataptr;
    buf->dataptr += data_len;

    if(outlen)
        *outlen = (size_t)data_len;

    return 0;
}

int ssh2_copy_string(LIBSSH2_SESSION *session, struct string_buf *buf,
                     unsigned char **outbuf, size_t *outlen)
{
    size_t str_len;
    unsigned char *str;

    if(ssh2_get_string(buf, &str, &str_len))
        return -1;

    if(str_len) {
        *outbuf = SSH2_ALLOC(session, str_len);
        if(*outbuf)
            memcpy(*outbuf, str, str_len);
        else
            return -1;
    }
    else
        *outbuf = NULL;

    if(outlen)
        *outlen = str_len;

    return 0;
}

int ssh2_get_bignum_bytes(struct string_buf *buf, unsigned char **outbuf,
                          size_t *outlen)
{
    uint32_t data_len;
    uint32_t bn_len;
    unsigned char *bnptr;

    if(ssh2_get_u32(buf, &data_len))
        return -1;
    if(!ssh2_check_length(buf, data_len))
        return -1;

    bn_len = data_len;
    bnptr = buf->dataptr;

    /* trim leading zeros */
    while(bn_len > 0 && *bnptr == 0x00) {
        bn_len--;
        bnptr++;
    }

    *outbuf = bnptr;
    buf->dataptr += data_len;

    if(outlen)
        *outlen = (size_t)bn_len;

    return 0;
}

/* Given the current location in buf, ssh2_check_length() ensures
   callers can read the next len number of bytes out of the buffer
   before reading the buffer content */
int ssh2_check_length(struct string_buf *buf, size_t requested_len)
{
    unsigned char *endp = &buf->data[buf->len];
    size_t left = endp - buf->dataptr;
    return requested_len <= left && left <= buf->len;
}

int ssh2_eob(struct string_buf *buf)
{
    unsigned char *endp = &buf->data[buf->len];
    return buf->dataptr >= endp;
}

int ssh2_timingsafe_bcmp(const void *b1, const void *b2, size_t n)
{
    const unsigned char *p1 = (const unsigned char *)b1;
    const unsigned char *p2 = (const unsigned char *)b2;
    int ret = 0;

    for(; n > 0; n--)
        ret |= *p1++ ^ *p2++;
    return ret != 0;
}

#ifndef LIBSSH2_KEY_SK
int ssh2_sk_pubkey(LIBSSH2_SESSION *session, char **method,
                   unsigned char **pubkeydata, size_t *pubkeydata_len,
                   int *algorithm, unsigned char *flags,
                   const char **application,
                   const unsigned char **key_handle, size_t *handle_len,
                   const char *privatekey,
                   const char *privkeyblob, size_t privkeyblob_len,
                   const char *passphrase)
{
    (void)method;
    (void)pubkeydata;
    (void)pubkeydata_len;
    (void)algorithm;
    (void)flags;
    (void)application;
    (void)key_handle;
    (void)handle_len;
    (void)privatekey;
    (void)privkeyblob;
    (void)privkeyblob_len;
    (void)passphrase;

    return ssh2_err(session, LIBSSH2_ERROR_FILE,
                    "Unable to extract public SK key from private key: "
                    "Method unimplemented in "
                    SSH2_CRYPTO_ENGINE_NAME " backend");
}
#endif

#ifdef _WIN32
#include <share.h>  /* for _SH_DENYNO */
#include <stdlib.h>  /* for malloc(), free() */
#include <tchar.h>  /* for _tcsncmp() */

#ifdef _UNICODE
static wchar_t *ssh2_win32_fn_convert_UTF8_to_wchar(const char *str_utf8)
{
    wchar_t *str_w = NULL;

    if(str_utf8) {
        int str_w_len = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                            str_utf8, -1, NULL, 0);
        if(str_w_len > 0) {
            str_w = malloc(str_w_len * sizeof(wchar_t));
            if(str_w) {
                if(MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                       str_utf8, -1, str_w, str_w_len) == 0) {
                    free(str_w);
                    return NULL;
                }
            }
        }
    }
    return str_w;
}
#endif

/* declare GetFullPathNameW for mingw-w64 UWP builds targeting old Windows */
#if defined(LIBSSH2_WINDOWS_UWP) && defined(__MINGW32__) && \
  (_WIN32_WINNT < _WIN32_WINNT_WIN10)
WINBASEAPI DWORD WINAPI GetFullPathNameW(LPCWSTR, DWORD, LPWSTR, LPWSTR *);
#endif

/* Fix excessive paths (paths that exceed MAX_PATH length of 260).
 *
 * This is a helper function to fix paths that would exceed the MAX_PATH
 * limitation check done by Windows APIs. It does so by normalizing the passed
 * in filename or path 'in' to its full canonical path, and if that path is
 * longer than MAX_PATH then setting 'out' to "\\?\" prefix + that full path.
 *
 * For example 'in' filename255chars in current directory C:\foo\bar is
 * fixed as \\?\C:\foo\bar\filename255chars for 'out' which tells Windows
 * it is ok to access that filename even though the actual full path is longer
 * than 260 chars.
 *
 * For non-Unicode builds this function may fail sometimes because only the
 * Unicode versions of some Windows API functions can access paths longer than
 * MAX_PATH, for example GetFullPathNameW which is used in this function. When
 * the full path is then converted from Unicode to multibyte that fails if any
 * directories in the path contain characters not in the current codepage.
 */
static int ssh2_win32_fix_excessive_path(const TCHAR *in, TCHAR **out)
{
    size_t needed, count;
    const wchar_t *in_w;
    wchar_t *fbuf = NULL;

    /* MS-documented "approximate" limit for the maximum path length */
    const size_t max_path_len = 32767;

#ifndef _UNICODE
    wchar_t *ibuf = NULL;
    char *obuf = NULL;
#endif

    *out = NULL;

    /* skip paths already normalized */
    if(!_tcsncmp(in, _TEXT("\\\\?\\"), 4))
        goto cleanup;

#ifndef _UNICODE
    /* convert multibyte input to unicode */
    if(mbstowcs_s(&needed, NULL, 0, in, 0))
        goto cleanup;
    if(!needed || needed >= max_path_len)
        goto cleanup;
    ibuf = malloc(needed * sizeof(wchar_t));
    if(!ibuf)
        goto cleanup;
    if(mbstowcs_s(&count, ibuf, needed, in, needed - 1))
        goto cleanup;
    if(count != needed)
        goto cleanup;
    in_w = ibuf;
#else
    in_w = in;
#endif

    /* GetFullPathNameW returns the normalized full path in unicode. It
       converts forward slashes to backslashes, processes .. to remove
       directory segments, etc. Unlike GetFullPathNameA it can process
       paths that exceed MAX_PATH. */
    needed = (size_t)GetFullPathNameW(in_w, 0, NULL, NULL);
    if(!needed || needed > max_path_len)
        goto cleanup;
    /* skip paths that are not excessive and do not need modification */
    if(needed <= MAX_PATH)
        goto cleanup;
    fbuf = malloc(needed * sizeof(wchar_t));
    if(!fbuf)
        goto cleanup;
    count = (size_t)GetFullPathNameW(in_w, (DWORD)needed, fbuf, NULL);
    if(!count || count >= needed)
        goto cleanup;

    /* prepend \\?\ or \\?\UNC\ to the excessively long path.
     *
     * c:\longpath            --->    \\?\c:\longpath
     * \\.\c:\longpath        --->    \\?\c:\longpath
     * \\?\c:\longpath        --->    \\?\c:\longpath  (unchanged)
     * \\server\c$\longpath   --->    \\?\UNC\server\c$\longpath
     *
     * https://learn.microsoft.com/dotnet/standard/io/file-path-formats
     */
    if(!wcsncmp(fbuf, L"\\\\?\\", 4))
        ; /* do nothing */
    else if(!wcsncmp(fbuf, L"\\\\.\\", 4))
        fbuf[2] = '?';
    else if(!wcsncmp(fbuf, L"\\\\.", 3) || !wcsncmp(fbuf, L"\\\\?", 3))
        /* Unexpected, not UNC. The formatting doc does not allow this
           AFAICT. */
        goto cleanup;
    else {
        wchar_t *temp;

        if(!wcsncmp(fbuf, L"\\\\", 2)) {
            /* "\\?\UNC\" + full path without "\\" + null */
            needed = 8 + (count - 2) + 1;
            if(needed > max_path_len)
                goto cleanup;

            temp = malloc(needed * sizeof(wchar_t));
            if(!temp)
                goto cleanup;

            if(wcsncpy_s(temp, needed, L"\\\\?\\UNC\\", 8)) {
                free(temp);
                goto cleanup;
            }
            if(wcscpy_s(temp + 8, needed, fbuf + 2)) {
                free(temp);
                goto cleanup;
            }
        }
        else {
            /* "\\?\" + full path + null */
            needed = 4 + count + 1;
            if(needed > max_path_len)
                goto cleanup;

            temp = malloc(needed * sizeof(wchar_t));
            if(!temp)
                goto cleanup;

            if(wcsncpy_s(temp, needed, L"\\\\?\\", 4)) {
                free(temp);
                goto cleanup;
            }
            if(wcscpy_s(temp + 4, needed, fbuf)) {
                free(temp);
                goto cleanup;
            }
        }

        free(fbuf);
        fbuf = temp;
    }

#ifndef _UNICODE
    /* convert unicode full path to multibyte output */
    if(wcstombs_s(&needed, NULL, 0, fbuf, 0))
        goto cleanup;
    if(!needed || needed >= max_path_len)
        goto cleanup;
    obuf = malloc(needed);
    if(!obuf)
        goto cleanup;
    if(wcstombs_s(&count, obuf, needed, fbuf, needed - 1))
        goto cleanup;
    if(count != needed)
        goto cleanup;
    *out = obuf;
    obuf = NULL;
#else
    *out = fbuf;
    fbuf = NULL;
#endif

cleanup:
    free(fbuf);
#ifndef _UNICODE
    free(ibuf);
    free(obuf);
#endif
    return !!*out;
}

FILE *ssh2_fopen(const char *filename, const char *mode)
{
    FILE *fp = NULL;
    TCHAR *fixed = NULL;
    const TCHAR *target = NULL;

#ifdef _UNICODE
    wchar_t *filename_w = ssh2_win32_fn_convert_UTF8_to_wchar(filename);
    wchar_t *mode_w = ssh2_win32_fn_convert_UTF8_to_wchar(mode);
    if(filename_w && mode_w) {
        if(ssh2_win32_fix_excessive_path(filename_w, &fixed))
            target = fixed;
        else
            target = filename_w;
        fp = _wfsopen(target, mode_w, _SH_DENYNO);
    }
    else
        errno = EINVAL;
    free(filename_w);
    free(mode_w);
#else
    if(ssh2_win32_fix_excessive_path(filename, &fixed))
        target = fixed;
    else
        target = filename;
    fp = _fsopen(target, mode, _SH_DENYNO);
#endif

    free(fixed);
    return fp;
}
#endif /* _WIN32 */
