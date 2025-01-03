/* Copyright (C) The libssh2 project and its contributors.
 *
 * Sample showing how to do forward the ssh-agent to the remote host.
 * Adapted from x11.c.
 *
 * $ ./ssh2_agent_forwarding host user
 *
 * For example:
 *
 * $ ./ssh2_agent_forwarding 127.0.0.1 user
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "libssh2_setup.h"
#include <libssh2.h>

#include <stdio.h>

#ifdef HAVE_SYS_UN_H

#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_SYS_UN_H
#include <sys/un.h>
#endif

#include <stdlib.h>
#include <string.h>

#include <termios.h>

struct agent_chan_list {
    LIBSSH2_CHANNEL *chan;
    libssh2_socket_t sock; /* Local agent socket */
    struct agent_chan_list *next;
};

static struct agent_chan_list *aclist_head = NULL;
static struct agent_chan_list *aclist_tail = NULL;

static struct termios _saved_tio;

/*
 * Callback to start a new agent connection from the remote host.
 * Save the channel to loop on it, save the agent connection
 */
static void authagent(LIBSSH2_SESSION *session, LIBSSH2_CHANNEL *channel,
                      void **abstract) {
    char *sockpath;
    struct agent_chan_list *current_node;
    libssh2_socket_t lsock = LIBSSH2_INVALID_SOCKET;
    struct sockaddr_un addr;
    int rc;
    (void) session;
    (void) abstract;

    /* Get local ssh-agent socket */
    sockpath = getenv("SSH_AUTH_SOCK");
    if(!sockpath) {
        fprintf(stderr, "SSH_AUTH_SOCK not set\n");
        libssh2_channel_free(channel);
        return;
    }

    /* Connect to local agent */
    lsock = socket(PF_UNIX, SOCK_STREAM, 0);
    if(lsock == LIBSSH2_INVALID_SOCKET) {
        fprintf(stderr, "Failed to create socket\n");
        libssh2_channel_free(channel);
        return;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, sockpath);
    rc = connect(lsock, (struct sockaddr *) &addr, sizeof(addr));
    if(rc == -1) {
        fprintf(stderr, "Failed to connect to local agent\n");
        libssh2_channel_free(channel);
        shutdown(lsock, SHUT_RDWR);
        LIBSSH2_SOCKET_CLOSE(lsock);
        return;
    }

    /* Add entry to channel list */
    current_node = malloc(sizeof(*current_node));
    current_node->chan = channel;
    current_node->sock = lsock;
    current_node->next = NULL;
    if(!aclist_tail) {
        aclist_head = aclist_tail = current_node;
    }
    else {
        aclist_tail->next = current_node;
        aclist_tail = current_node;
    }
}

/*
 * Send/receive data between the remote and local agents attached to this
 * channel.
 */
static int agent_proxy_data(struct agent_chan_list *agent)
{
    char *buf;
    unsigned int bufsize = 8192;
    int rc;
    unsigned int nfds = 1;
    LIBSSH2_POLLFD fds[1];
    fd_set set;
    struct timeval timeval_out;
    timeval_out.tv_sec = 0;
    timeval_out.tv_usec = 0;

    FD_ZERO(&set);
#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
#endif
    FD_SET(agent->sock, &set);
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

    buf = calloc(bufsize, sizeof(char));
    if(!buf)
        return 0;

    fds[0].type = LIBSSH2_POLLFD_CHANNEL;
    fds[0].fd.channel = agent->chan;
    fds[0].events = LIBSSH2_POLLFD_POLLIN;
    fds[0].revents = LIBSSH2_POLLFD_POLLIN;

    rc = libssh2_poll(fds, nfds, 0);
    if(rc > 0) {
        ssize_t nread;
        nread = libssh2_channel_read(agent->chan, buf, bufsize);
        if(nread > 0)
            write(agent->sock, buf, (size_t) nread);
    }

    rc = select((int)(agent->sock + 1), &set, NULL, NULL, &timeval_out);
    if(rc > 0) {
        ssize_t nread;

        memset(buf, 0, bufsize);

        /* Data in sock */
        nread = read(agent->sock, buf, bufsize);
        if(nread > 0) {
            libssh2_channel_write(agent->chan, buf, (size_t)nread);
        }
        else {
            free(buf);
            return -1;
        }
    }

    free(buf);
    if(libssh2_channel_eof(agent->chan) == 1) {
        return -1;
    }
    return 0;
}

/*
 * Utility function to remove a Node of the chained list
 */
static void remove_node(struct agent_chan_list *elem)
{
    struct agent_chan_list *current_node = NULL;

    current_node = aclist_head;

    if(aclist_head == elem) {
        if(aclist_tail == aclist_head) {
            aclist_tail = NULL;
        }
        aclist_head = aclist_head->next;
        free(current_node);
        return;
    }

    while(current_node->next) {
        if(current_node->next == elem) {
            current_node->next = current_node->next->next;
            if(!current_node->next->next) {
                aclist_tail = current_node;
            }
            free(elem);
            break;
        }
    }
}

static int _raw_mode(void)
{
    int rc;
    struct termios tio;

    rc = tcgetattr(fileno(stdin), &tio);
    if(rc != -1) {
        _saved_tio = tio;
        /* do the equivalent of cfmakeraw() manually, to build on Solaris */
        tio.c_iflag &= ~(tcflag_t)(IGNBRK|BRKINT|PARMRK|ISTRIP|
                                   INLCR|IGNCR|ICRNL|IXON);
        tio.c_oflag &= ~(tcflag_t)OPOST;
        tio.c_lflag &= ~(tcflag_t)(ECHO|ECHONL|ICANON|ISIG|IEXTEN);
        tio.c_cflag &= ~(tcflag_t)(CSIZE|PARENB);
        tio.c_cflag |= CS8;
        rc = tcsetattr(fileno(stdin), TCSADRAIN, &tio);
    }
    return rc;
}

static int _normal_mode(void)
{
    int rc;
    rc = tcsetattr(fileno(stdin), TCSADRAIN, &_saved_tio);
    return rc;
}

int main(int argc, char *argv[])
{
    uint32_t hostaddr;
    libssh2_socket_t sock;
    int i;
    struct sockaddr_in sin;
    const char *fingerprint;
    char *userauthlist;
    char *username;
    int rc;
    LIBSSH2_SESSION *session = NULL;
    LIBSSH2_CHANNEL *channel;
    LIBSSH2_AGENT *agent = NULL;
    struct libssh2_agent_publickey *identity, *prev_identity = NULL;
    struct agent_chan_list *current_node;
    size_t bufsiz = 8193;
    char *buf = NULL;
    unsigned int nfds = 1;
    LIBSSH2_POLLFD fds[1];

    /* Struct winsize for term size */
    struct winsize w_size;
    struct winsize w_size_bck;

    /* For select on stdin */
    fd_set set;
    struct timeval timeval_out;
    timeval_out.tv_sec = 0;
    timeval_out.tv_usec = 10;

#ifdef _WIN32
    WSADATA wsadata;

    rc = WSAStartup(MAKEWORD(2, 0), &wsadata);
    if(rc) {
        fprintf(stderr, "WSAStartup failed with error: %d\n", rc);
        return 1;
    }
#endif

    if(argc < 3) {
        fprintf(stderr, "Usage: %s <host> <user>\n", argv[0]);
        return 1;
    }
    hostaddr = inet_addr(argv[1]);
    username = argv[2];

    rc = libssh2_init(0);
    if(rc) {
        fprintf(stderr, "libssh2 initialization failed (%d)\n", rc);
        return 1;
    }

    /* Ultra basic "connect to port 22 on localhost".  Your code is
     * responsible for creating the socket establishing the connection
     */
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock == LIBSSH2_INVALID_SOCKET) {
        fprintf(stderr, "failed to create socket.\n");
        rc = 1;
        goto shutdown;
    }

    sin.sin_family = AF_INET;
    sin.sin_port = htons(22);
    sin.sin_addr.s_addr = hostaddr;
    if(connect(sock, (struct sockaddr *)(&sin), sizeof(struct sockaddr_in))) {
        fprintf(stderr, "failed to connect.\n");
        goto shutdown;
    }

    /* Create a session instance */
    session = libssh2_session_init();
    if(!session) {
        fprintf(stderr, "Could not initialize SSH session.\n");
        goto shutdown;
    }

    rc = libssh2_session_handshake(session, sock);
    if(rc) {
        fprintf(stderr, "Failure establishing SSH session: %d\n", rc);
        goto shutdown;
    }

    /* At this point we have not yet authenticated.  The first thing to do
     * is check the hostkey's fingerprint against our known hosts Your app
     * may have it hard coded, may go to a file, may present it to the
     * user, that's your call
     */
    fingerprint = libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_SHA1);
    fprintf(stderr, "Fingerprint: ");
    for(i = 0; i < 20; i++) {
        fprintf(stderr, "%02X ", (unsigned char)fingerprint[i]);
    }
    fprintf(stderr, "\n");

    /* Set agent callback */
    libssh2_session_callback_set2(session, LIBSSH2_CALLBACK_AUTHAGENT,
                                  (libssh2_cb_generic *) authagent);

    /* check what authentication methods are available */
    userauthlist = libssh2_userauth_list(session, username,
                                         (unsigned int)strlen(username));
    if(userauthlist) {
        fprintf(stderr, "Authentication methods: %s\n", userauthlist);
        if(!strstr(userauthlist, "publickey")) {
            fprintf(stderr, "'publickey' authentication is not supported\n");
            goto shutdown;
        }

        /* Connect to the ssh-agent */
        agent = libssh2_agent_init(session);
        if(!agent) {
            fprintf(stderr, "Failure initializing ssh-agent support\n");
            rc = 1;
            goto shutdown;
        }
        if(libssh2_agent_connect(agent)) {
            fprintf(stderr, "Failure connecting to ssh-agent\n");
            rc = 1;
            goto shutdown;
        }
        if(libssh2_agent_list_identities(agent)) {
            fprintf(stderr, "Failure requesting identities to ssh-agent\n");
            rc = 1;
            goto shutdown;
        }
        for(;;) {
            rc = libssh2_agent_get_identity(agent, &identity, prev_identity);
            if(rc == 1)
                break;
            if(rc < 0) {
                fprintf(stderr,
                        "Failure obtaining identity from ssh-agent support\n");
                rc = 1;
                goto shutdown;
            }
            if(libssh2_agent_userauth(agent, username, identity)) {
                fprintf(stderr, "Authentication with username %s and "
                        "public key %s failed.\n",
                        username, identity->comment);
            }
            else {
                fprintf(stderr, "Authentication with username %s and "
                        "public key %s succeeded.\n",
                        username, identity->comment);
                break;
            }
            prev_identity = identity;
        }
        if(rc) {
            fprintf(stderr, "Could not continue authentication\n");
            goto shutdown;
        }
    }

    /* We're authenticated now. */

    /* Request a shell */
    channel = libssh2_channel_open_session(session);
    if(!channel) {
        fprintf(stderr, "Unable to open a session\n");
        goto shutdown;
    }

    /* Request ssh-agent forwarding.
     * This will set up the agent socket on the server, but we'll still need to
     * handle agent requests via the callback.
     */
    libssh2_channel_request_auth_agent(channel);
    if(!channel) {
        fprintf(stderr, "Failed requesting agent forwarding\n");
        goto skip_shell;
    }

    /* Some environment variables may be set,
     * It's up to the server which ones it'll allow though
     */
    libssh2_channel_setenv(channel, "FOO", "bar");

    /* Request a terminal with 'vanilla' terminal emulation
     * See /etc/termcap for more options. This is useful when opening
     * an interactive shell.
     */
    if(libssh2_channel_request_pty(channel, "vanilla")) {
        fprintf(stderr, "Failed requesting pty\n");
        goto skip_shell;
    }

    /* Open a SHELL on that pty */
    if(libssh2_channel_shell(channel)) {
        fprintf(stderr, "Unable to request shell on allocated pty\n");
        goto skip_shell;
    }

    rc = _raw_mode();
    if(rc) {
        fprintf(stderr, "Failed to enter into raw mode\n");
        goto skip_shell;
    }

    memset(&w_size, 0, sizeof(struct winsize));
    memset(&w_size_bck, 0, sizeof(struct winsize));

    for(;;) {

        FD_ZERO(&set);
#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
#endif
        FD_SET(fileno(stdin), &set);
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

        /* See if a resize pty has to be sent */
        ioctl(fileno(stdin), TIOCGWINSZ, &w_size);
        if((w_size.ws_row != w_size_bck.ws_row) ||
           (w_size.ws_col != w_size_bck.ws_col)) {
            w_size_bck = w_size;

            libssh2_channel_request_pty_size(channel,
                                             w_size.ws_col,
                                             w_size.ws_row);
        }

        buf = calloc(bufsiz, sizeof(char));
        if(!buf)
            break;

        fds[0].type = LIBSSH2_POLLFD_CHANNEL;
        fds[0].fd.channel = channel;
        fds[0].events = LIBSSH2_POLLFD_POLLIN;
        fds[0].revents = LIBSSH2_POLLFD_POLLIN;

        rc = libssh2_poll(fds, nfds, 0);
        if(rc > 0) {
            libssh2_channel_read(channel, buf, sizeof(buf));
            fprintf(stdout, "%s", buf);
            fflush(stdout);
        }

        /* Looping on X clients */
        if(aclist_head) {
            current_node = aclist_head;
        }
        else
            current_node = NULL;

        while(current_node) {
            struct agent_chan_list *next;
            rc = agent_proxy_data(current_node);
            next = current_node->next;
            if(rc == -1) {
                shutdown(current_node->sock, SHUT_RDWR);
                LIBSSH2_SOCKET_CLOSE(current_node->sock);
                remove_node(current_node);
            }

            current_node = next;
        }

        rc = select((int)(fileno(stdin) + 1), &set, NULL, NULL, &timeval_out);
        if(rc > 0) {
            ssize_t nread;

            /* Data in stdin */
            nread = read(fileno(stdin), buf, 1);
            if(nread > 0)
                libssh2_channel_write(channel, buf, sizeof(buf));
        }

        free(buf);

        if(libssh2_channel_eof(channel) == 1) {
            break;
        }
    }
    _normal_mode();

skip_shell:

    if(channel) {
        libssh2_channel_free(channel);
        channel = NULL;
    }

    /* Other channel types are supported via:
     * libssh2_scp_send()
     * libssh2_scp_recv2()
     * libssh2_channel_direct_tcpip()
     */

shutdown:

    for(current_node = aclist_head; current_node;
        current_node = current_node->next) {
        libssh2_channel_free(current_node->chan);
        current_node->chan = NULL;
        shutdown(current_node->sock, SHUT_RDWR);
        LIBSSH2_SOCKET_CLOSE(current_node->sock);
    }

    if(agent) {
        libssh2_agent_disconnect(agent);
        libssh2_agent_free(agent);
    }

    if(session) {
        libssh2_session_disconnect(session, "Normal Shutdown");
        libssh2_session_free(session);
    }

    if(sock != LIBSSH2_INVALID_SOCKET) {
        shutdown(sock, 2);
        LIBSSH2_SOCKET_CLOSE(sock);
    }

    fprintf(stderr, "all done\n");

    libssh2_exit();

#ifdef _WIN32
    WSACleanup();
#endif

    return rc;
}

#else

int main(void)
{
    fprintf(stderr, "Sorry, this platform is not supported.");
    return 1;
}

#endif /* HAVE_SYS_UN_H */
