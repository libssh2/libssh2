// -*- compile-command: "gcc -Wall -Wextra x11_forwarding.c -o x11_forwarding -lssh2" -*-
/* Copyright (c) 2016 by Luiz A. Bühnemann <la3280@gmail.com>
 *
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
/* This file contains an example of how to handle X11 forwarding using libssh2
 *
 * How to use:
 *
 * 1st make sure your X server can accept TCP/IP connections;
 * 2nd grab the .Xauthority MIT-MAGIC-COOKIE-1 for authentication;
 * 3rd run this example program following usage help.
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <libssh2.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>

#define SSH_X11_BASEPORT 6000

#define UNUSED(x)    (void) x

struct ssh_x11_channel {
        /* SSH server tunnel */
        LIBSSH2_CHANNEL *channel;

        /* X11 server socket */
        int sock;

        struct ssh_x11_channel *next;
};

struct ssh_connection_info {
        /* SSH Login information */
        char *hostname;
        int port;
        char *username;
        char *password;

        /* X11 Information */
        int x11_screen;
        char *mit_magic_cookie;
        int forward_single_connection;
        char *x11_address;
        int x11_display;

        /* The program that will be started on the SSH server */
        char *command;

        /* Internal */
        int sock;
        LIBSSH2_CHANNEL *channel;
        LIBSSH2_SESSION *session;
        struct ssh_x11_channel *channels;
};

static int tcp_set_blocking(int fd, int blocking)
{
        int flags = fcntl(fd, F_GETFL, 0);

        if (flags < 0)
                return -1;

        flags = blocking ? (flags & ~O_NONBLOCK) : (flags | O_NONBLOCK);

        return fcntl(fd, F_SETFL, flags);
}

static void ssh_x11_channel_add(struct ssh_x11_channel **channels,
        LIBSSH2_CHANNEL *channel, int sock)
{
        struct ssh_x11_channel *chan = malloc(sizeof(struct ssh_x11_channel));

        chan->channel = channel;
        chan->sock = sock;
        chan->next = *channels;
        *channels = chan;
        tcp_set_blocking(sock, 0);
}

static void ssh_x11_channel_remove(struct ssh_x11_channel **channels,
        struct ssh_x11_channel *channel)
{
        struct ssh_x11_channel *chan, *prev = NULL;

        for (chan = *channels; chan; prev = chan, chan = chan->next) {
                if (chan != channel)
                        continue;

                /* At the head of the list */
                if (prev == NULL)
                        *channels = chan->next;
                else
                        prev->next = chan->next;

                free(chan);
                return;
        }
}

static void dump_connection_info(struct ssh_connection_info *cinfo)
{
        printf("hostname: %s\nport: %i\nusername: %s\npassword: %s\n"
                "x11-screen: %i\nmit-magic-cookie-1: %s\nforward-single-conn: %i\n"
                "x11-address: %s\nx11-display: %i\ncommand: %s\n", cinfo->hostname,
                cinfo->port, cinfo->username, cinfo->password, cinfo->x11_screen,
                cinfo->mit_magic_cookie, cinfo->forward_single_connection,
                cinfo->x11_address, cinfo->x11_display, cinfo->command);
}


static int tcp_connect(const char *host, unsigned short port)
{
        struct sockaddr_in sin;
        unsigned long addr;
        int sock, r;

        addr = inet_addr(host);
        sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == -1)
                return sock;
        sin.sin_family = AF_INET;
        sin.sin_port = htons(port);
        sin.sin_addr.s_addr = addr;
        r = connect(sock, (struct sockaddr *) &sin, sizeof(struct sockaddr_in));
        if (r == -1)
                return r;
        return sock;
}

static int ssh_exec(LIBSSH2_CHANNEL *channel, const char *command)
{
        int r;

        r = libssh2_channel_exec(channel, command);
        if (r < 0)
                return 8;

        return 0;
}

static void close_x11_channel(struct ssh_x11_channel *chan)
{
        shutdown(chan->sock, SHUT_RDWR);
        close(chan->sock);
        libssh2_channel_close(chan->channel);
}

static int get_fds(fd_set *fds, struct ssh_connection_info *cinfo)
{
        int maxfd = -1;
        struct ssh_x11_channel *chan = cinfo->channels;

        while (chan) {
                if (chan->sock > maxfd)
                        maxfd = chan->sock;
                FD_SET(chan->sock, fds);
                chan = chan->next;
        }

        FD_SET(cinfo->sock, fds);
        if (cinfo->sock > maxfd)
                maxfd = cinfo->sock;

        return maxfd;
}

static int wait_for_data(fd_set *fds, struct ssh_connection_info *cinfo)
{
        int maxfd = get_fds(fds, cinfo);
        int r = select(maxfd + 1, fds, NULL, NULL, NULL);
        if (r < 0)
                return -1;
        return r;
}

static int poll_bytes_available(LIBSSH2_CHANNEL *chan)
{
        unsigned long read_avail;
        libssh2_channel_window_read_ex(chan, &read_avail, NULL);
        return (int) read_avail;
}

static int has_pending_bytes(LIBSSH2_CHANNEL *main_channel,
        const struct ssh_x11_channel *channels)
{
        const struct ssh_x11_channel *chan;

        if (poll_bytes_available(main_channel))
                return 1;
        for (chan = channels; chan; chan = chan->next)
                if (poll_bytes_available(chan->channel))
                        return 1;
        return 0;
}

static int write_all(int fd, const char *buf, int size)
{
        int written = 0, r;

        while (written < size) {
                r = write(fd, buf + written, size - written);
                if (r == -1 && errno == EAGAIN)
                        continue;
                if (r <= 0)
                        return -1;
                written += r;
        }

        return written;
}

static int forward_channel_data(LIBSSH2_CHANNEL *chan, int fd)
{
        int pending, written, r;
        char buf[128000];

        pending = poll_bytes_available(chan);
        if (!pending) {
                if (libssh2_channel_eof(chan))
                        return -1;
                return 0;
        }

        written = 0;
        while (written < pending) {
                r = libssh2_channel_read(chan, buf, sizeof(buf));
                if (r == LIBSSH2_ERROR_EAGAIN)
                        continue;
                if (r <= 0)
                        return -2;
                if (write_all(fd, buf, r) < 0)
                        return -3;
                written += r;
        }

        return written;
}

static int forward_socket_data(int fd, LIBSSH2_CHANNEL *chan)
{
        int written, pending, r;
        char buf[128000];

        while ((pending = read(fd, buf, sizeof(buf))) > 0) {
                written = 0;
                while (written < pending) {
                        r = libssh2_channel_write(chan, buf + written,
                                pending - written);
                        if (r == LIBSSH2_ERROR_EAGAIN)
                                continue;
                        if (r <= 0)
                                return -1;
                        written += r;
                }
        }
        return written;
}

static int read_main_channel(LIBSSH2_CHANNEL *chan)
{
        int r;
        char buf[128000];

        if (libssh2_channel_eof(chan))
                return -1;

        r = libssh2_channel_read(chan, buf, sizeof(buf));
        if (r == LIBSSH2_ERROR_EAGAIN)
                return 0;
        if (r < 0)
                return -2;

        if (r > 0 && write_all(STDOUT_FILENO, buf, r) < 0)
                return -3;

        return r;
}

/*
 * Checks for the X11 forwarding tunnel both ways
 * incoming data from the X11 server is forwarded to the X11 client on the
 * remote machine and data from the X11 client is forwarded to the X11 server.
 * The basic layout of the connection is as follows:
 *
 * X11 Server                 X11 Client (Application)
 *    |^                                |^
 *    ||                                ||
 *    v|                                v|
 * x11_forwarding====================SSH server
 */
static int update_channels(fd_set *fds, LIBSSH2_CHANNEL *main_channel,
        struct ssh_x11_channel **channels)
{
        struct ssh_x11_channel *chan, *next;
        int r;

        do {
                /* Read from main channel */
                r = read_main_channel(main_channel);
                /* EOF */
                if (r == -1)
                        return -1;
                /* Error */
                else if (r < 0)
                        return -2;

                /* Checks for incoming data from the X11 client to the X11 server */
                chan = *channels;
                while (chan) {
                        r = forward_channel_data(chan->channel, chan->sock);
                        /* EOF */
                        if (r == -1) {
                                next = chan->next;
                                close_x11_channel(chan);
                                ssh_x11_channel_remove(channels, chan);
                                chan = next;
                                continue;
                        }
                        /* Error */
                        else if (r < 0) {
                                return -2;
                        }
                        chan = chan->next;
                }

                /* Checks for incoming data from the X11 server to the X11 client */
                chan = *channels;
                while (chan) {
                        if (!FD_ISSET(chan->sock, fds)) {
                                chan = chan->next;
                                continue;
                        }
                        if (forward_socket_data(chan->sock, chan->channel) < 0)
                                return -2;
                        chan = chan->next;
                }

        } while (has_pending_bytes(main_channel, *channels));

        return 0;
}

static void close_all_x11_channels(struct ssh_x11_channel **channels)
{
        struct ssh_x11_channel *chan = *channels, *next;

        while (chan) {
                next = chan->next;
                close_x11_channel(chan);
                free(chan);
                chan = next;
        }
        *channels = NULL;
}

static int mainloop(struct ssh_connection_info *cinfo)
{
        fd_set fds;
        int r;

        while (1) {
                /* Wait for data in both ssh client and X11 server */
                r = wait_for_data(&fds, cinfo);
                if (r < 0)
                        break;

                /* Read data */
                r = update_channels(&fds, cinfo->channel, &cinfo->channels);
                if (r < 0)
                        break;
        }

        close_all_x11_channels(&cinfo->channels);
        libssh2_channel_close(cinfo->channel);
        libssh2_channel_free(cinfo->channel);

        return 0;
}

static void x11_connection_handler(LIBSSH2_SESSION *session, LIBSSH2_CHANNEL *channel,
        char *shost, int sport, void **abstract)
{
        struct ssh_connection_info *cinfo = *abstract;
        int sock;

        UNUSED(session);
        UNUSED(shost);
        UNUSED(sport);

        sock = tcp_connect(cinfo->x11_address, SSH_X11_BASEPORT + cinfo->x11_display);
        if (sock < 0) {
                printf("Error connecting to X11 server.\n");
                return;
        }
        libssh2_channel_set_blocking(channel, 0);
        ssh_x11_channel_add(&cinfo->channels, channel, sock);
}

int main(int argc, char **argv)
{
        LIBSSH2_SESSION *session;
        LIBSSH2_CHANNEL *channel;
        int sock, r;
        struct ssh_connection_info cinfo;

        if (argc < 11) {
                printf("Usage: %s <hostname> <port> <username> <password> "
                        "<x11_screen> <MIT-MAGIC-COOKIE-1> <single connection> "
                        "<X address> <X display> <command>\n", argv[0]);
                return 255;
        }

        /* Fill connection settings */
        cinfo.hostname                  = argv[1];
        cinfo.port                      = atoi(argv[2]);
        cinfo.username                  = argv[3];
        cinfo.password                  = argv[4];
        cinfo.x11_screen                = atoi(argv[5]);
        cinfo.mit_magic_cookie        = argv[6];
        cinfo.forward_single_connection = atoi(argv[7]);
        cinfo.x11_address               = argv[8];
        cinfo.x11_display               = atoi(argv[9]);
        cinfo.command                   = argv[10];
        cinfo.channels                  = NULL;

        dump_connection_info(&cinfo);

        if (libssh2_init(0))
                return 1;

        sock = tcp_connect(cinfo.hostname, cinfo.port);
        if (sock < 0)
                return 2;
        cinfo.sock = sock;

        session = libssh2_session_init_ex(NULL, NULL, NULL, &cinfo);
        if (!session)
                return 3;
        cinfo.session = session;

        r = libssh2_session_handshake(session, sock);
        if (r < 0)
                return 4;

        libssh2_session_callback_set(session, LIBSSH2_CALLBACK_X11,
                x11_connection_handler);

        r = libssh2_userauth_password(session, cinfo.username, cinfo.password);
        if (r < 0)
                return 5;

        channel = libssh2_channel_open_session(session);
        if (!channel)
                return 6;
        cinfo.channel = channel;

        r = libssh2_channel_request_pty(channel, "linux");
        if (r < 0)
                return 7;

        r = libssh2_channel_x11_req_ex(channel, cinfo.forward_single_connection,
                "MIT-MAGIC-COOKIE-1", cinfo.mit_magic_cookie, cinfo.x11_screen);
        if (r < 0)
                return 8;

        r = ssh_exec(channel, cinfo.command);
        if (r < 0)
                return 9;

        mainloop(&cinfo);

        libssh2_session_disconnect(session, "Normal shutdown");
        libssh2_session_free(session);
        close(sock);
        libssh2_exit();

        return 0;
}
