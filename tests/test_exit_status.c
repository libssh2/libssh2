/* Copyright (C) The libssh2 project and its contributors.
 *
 * libssh2 test telling a received exit status apart from none
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "runner.h"

int test(LIBSSH2_SESSION *session)
{
    LIBSSH2_CHANNEL *channel;

    /* set in Dockerfile */
    if(test_auth_pubkey(session, 0, "libssh2", NULL,
                        "keys/id_rsa_pem.pub",
                        "keys/id_rsa_pem"))
        return 1;

    /* A finished command sends an exit-status, so its receipt is reported
       and the value read back is a real 0. */
    channel = libssh2_channel_open_session(session);
    if(!channel) {
        print_last_session_error("libssh2_channel_open_session");
        return 1;
    }
    if(libssh2_channel_exec(channel, "exit 0")) {
        print_last_session_error("libssh2_channel_exec");
        return 1;
    }
    while(!libssh2_channel_eof(channel)) {
        char buf[1024];
        if(libssh2_channel_read(channel, buf, sizeof(buf)) < 0)
            break;
    }
    libssh2_channel_close(channel);
    if(!libssh2_channel_has_exit_status(channel)) {
        fprintf(stderr, "exit status not reported as received\n");
        return 1;
    }
    if(libssh2_channel_get_exit_status(channel) != 0) {
        fprintf(stderr, "unexpected exit status: %d\n",
                libssh2_channel_get_exit_status(channel));
        return 1;
    }
    libssh2_channel_free(channel);

    /* A channel that runs no command receives no exit-status, so its absence
       is reported rather than read as a 0. */
    channel = libssh2_channel_open_session(session);
    if(!channel) {
        print_last_session_error("libssh2_channel_open_session");
        return 1;
    }
    libssh2_channel_close(channel);
    if(libssh2_channel_has_exit_status(channel)) {
        fprintf(stderr, "exit status reported for a channel that had none\n");
        return 1;
    }
    libssh2_channel_free(channel);

    return 0;
}
