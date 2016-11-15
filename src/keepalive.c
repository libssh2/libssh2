/* Copyright (C) 2010  Simon Josefsson
 * Author: Simon Josefsson
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
 */

#include "libssh2_priv.h"
#include "transport.h" /* _libssh2_transport_write */
#include "session.h"
#include "keepalive.h"
/* Keep-alive stuff. */

LIBSSH2_API void
libssh2_keepalive_config (LIBSSH2_SESSION *session,
                          int want_reply,
                          unsigned interval)
{
    if (interval == 1)
        session->keepalive_interval = 2;
    else
        session->keepalive_interval = interval;
    session->keepalive_want_reply = want_reply ? 1 : 0;
}

int _libssh2_keepalive_send (LIBSSH2_SESSION *session,
                             int *seconds_to_next)
{
    /* The following variables are declared with static allocation so
       that the pointers passed to _libssh2_transport_write do not
       change between calls.
       Keep-alive packet format is ...
       SSH_MSG_GLOBAL_REQUEST || 4-byte len || str || want-reply. */
    static const unsigned char keepalive_data_wr[] =     /* wr: wants reply */
        "\x50\x00\x00\x00\x15keepalive@libssh2.org\x01";
    static const unsigned char keepalive_data_nr[] =     /* nr: no reply */
        "\x50\x00\x00\x00\x15keepalive@libssh2.org\x00";

    int rc;
    time_t now = 0;

    if (!session->keepalive_data) {
        if (!session->keepalive_interval ||
            /* libssh2_keepalive_send is called from
             * _libssh2_wait_socket and it may be invoked when the
             * transport layer is already busy sending a different
             * packet, so, the following check must be performed... */
            _libssh2_transport_send_ready(session)) {
            if (seconds_to_next)
                *seconds_to_next = 0;
            return 0;
        }

        now = time(NULL);
        if (session->keepalive_last_sent + session->keepalive_interval > now) {
            if (seconds_to_next)
                *seconds_to_next = (int)(session->keepalive_last_sent - now
                                         + session->keepalive_interval);
            return 0;
        }

        session->keepalive_data = (session->keepalive_want_reply
                                   ? keepalive_data_wr
                                   : keepalive_data_nr);
    }

    rc = _libssh2_transport_send(session,
                                 session->keepalive_data, sizeof(keepalive_data_wr) - 1,
                                 NULL, 0);

    if (rc == LIBSSH2_ERROR_EAGAIN)
        return rc;

    /* We set the state even when an error happens. It is probably
       useless as errors from _libssh2_transport_read are usually
       final, but hey, it is a harmless operation anyway! */
    session->keepalive_last_sent = (now ? now : time(NULL));
    session->keepalive_data = NULL;
    if (seconds_to_next)
        *seconds_to_next = session->keepalive_interval;

    if (rc < 0) {
        _libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND,
                       "Unable to send keepalive message");
        return rc;
    }

    return 0;
}

LIBSSH2_API int
libssh2_keepalive_send (LIBSSH2_SESSION *session,
                        int *seconds_to_next) {
    int rc;
    BLOCK_ADJUST(rc, session,
                 _libssh2_keepalive_send(session, seconds_to_next));
    return rc;
}
