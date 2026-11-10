/* Copyright (C) The libssh2 project and its contributors.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * OSS-Fuzz target: exercise the ssh-agent client reply parsing (agent.c)
 * with the fuzz input standing in for the agent's reply stream.
 */
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

extern "C" {
#include "libssh2.h"
#include "libssh2_priv.h"
}

/* Mirror of struct _LIBSSH2_AGENT from src/agent.c (unix build).
 * Keep in lockstep with src/agent.c! */
struct agent_mirror {
    LIBSSH2_SESSION *session;
    libssh2_socket_t fd;
    void *ops;
    struct {
        unsigned char *request;
        size_t request_len;
        unsigned char *response;
        size_t response_len;
        int state;
        size_t send_recv_total;
    } transctx;
    void *identity;
    struct list_head head;
    char *identity_agent_path;
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    LIBSSH2_SESSION *session = NULL;
    LIBSSH2_AGENT *agent = NULL;
    struct agent_mirror *mirror;
    struct libssh2_agent_publickey *ident = NULL;
    struct libssh2_agent_publickey *prev_ident = NULL;
    int socket_fds[2] = { -1, -1 };
    int rc;
    int tries;

    if(size < 5)
        return 0;

    if(libssh2_init(0))
        return 0;

    if(socketpair(AF_UNIX, SOCK_STREAM, 0, socket_fds))
        return 0;

    session = libssh2_session_init();

    if(!session)
        goto EXIT_LABEL;

    libssh2_session_set_blocking(session, 0);
    session->socket_fd = socket_fds[0];

    agent = libssh2_agent_init(session);

    if(!agent)
        goto EXIT_LABEL;

    /* libssh2_agent_init() leaves agent->ops unset; ops (and the unix
     * backend) are only installed by libssh2_agent_connect(), which
     * connects to the socket named by SSH_AUTH_SOCK. Point it at a real
     * listening unix socket so the connect path runs for real, then swap
     * the connection descriptor for our socketpair carrying the fuzz
     * replies. Both ends are made nonblocking so no recv() can hang on
     * the silent peer. */
    {
        char path[64];
        struct sockaddr_un addr;
        int listener = socket(AF_UNIX, SOCK_STREAM, 0);

        if(listener < 0)
            goto EXIT_LABEL;

        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        snprintf(path, sizeof(path), "/tmp/l2ag.%d", (int)getpid());
        strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
        unlink(path);

        if(bind(listener, (struct sockaddr *)&addr, sizeof(addr)) ||
           listen(listener, 1)) {
            close(listener);
            unlink(path);
            goto EXIT_LABEL;
        }

        setenv("SSH_AUTH_SOCK", path, 1);
        rc = libssh2_agent_connect(agent);
        setenv("SSH_AUTH_SOCK", "", 1);
        unlink(path);
        close(listener);

        if(rc)
            goto EXIT_LABEL;

        /* Swap the real connection for the fuzz reply stream. */
        mirror = (struct agent_mirror *)agent;
        mirror->fd = socket_fds[0];
        fcntl(socket_fds[0], F_SETFL,
              fcntl(socket_fds[0], F_GETFL, 0) | O_NONBLOCK);
        fcntl(socket_fds[1], F_SETFL,
              fcntl(socket_fds[1], F_GETFL, 0) | O_NONBLOCK);

        /* The fuzz data is the agent's reply to SSH_AGENTC_REQUEST_IDENTITIES
         * (sent by libssh2_agent_list_identities): a length-prefixed stream
         * that the reply parser decodes. */
        rc = send(socket_fds[1], data, size, MSG_NOSIGNAL);
        if(rc != (ssize_t)size)
            goto EXIT_LABEL;
    }

    for(tries = 0; tries < 8; tries++) {
        rc = libssh2_agent_list_identities(agent);

        if(rc != LIBSSH2_ERROR_EAGAIN)
            break;
    }

    for(tries = 0; tries < 8; tries++) {
        rc = libssh2_agent_get_identity(agent, &ident, prev_ident);

        if(rc != LIBSSH2_ERROR_EAGAIN) {
            prev_ident = ident;
            break;
        }
    }

EXIT_LABEL:

    if(agent) {
        (void)libssh2_agent_disconnect(agent);
        libssh2_agent_free(agent);
    }

    if(session)
        libssh2_session_free(session);

    if(socket_fds[0] != -1)
        close(socket_fds[0]);

    if(socket_fds[1] != -1)
        close(socket_fds[1]);

    return 0;
}
