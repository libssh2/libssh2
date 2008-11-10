/*
 * $Id: scp_write_nonblock.c,v 1.9 2008/11/10 16:48:41 bagder Exp $
 *
 * Sample showing how to do a simple SCP transfer.
 */

#include "libssh2_config.h"

#include <libssh2.h>

#ifdef HAVE_WINSOCK2_H
# include <winsock2.h>
#endif
#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
# ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_ARPA_INET_H
# include <arpa/inet.h>
#endif
#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#endif

#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <ctype.h>

int main(int argc, char *argv[])
{
    unsigned long hostaddr;
    int sock, i, auth_pw = 1;
    struct sockaddr_in sin;
    const char *fingerprint;
    LIBSSH2_SESSION *session;
    LIBSSH2_CHANNEL *channel;
    const char *username="username";
    const char *password="password";
    const char *loclfile="scp_write.c";
    const char *scppath="/tmp/TEST";
    FILE *local;
    int rc;
#if defined(HAVE_IOCTLSOCKET)
    long flag = 1;
#endif
    char mem[1024];
    size_t nread;
    char *ptr;
    struct stat fileinfo;

#ifdef WIN32
    WSADATA wsadata;

    WSAStartup(MAKEWORD(2,0), &wsadata);
#endif

    if (argc > 1) {
        hostaddr = inet_addr(argv[1]);
    } else {
        hostaddr = htonl(0x7F000001);
    }
    if (argc > 2) {
        username = argv[2];
    }
    if (argc > 3) {
        password = argv[3];
    }
    if(argc > 4) {
        loclfile = argv[4];
    }
    if (argc > 5) {
        scppath = argv[5];
    }

    local = fopen(loclfile, "rb");
    if (!local) {
        fprintf(stderr, "Can't local file %s\n", loclfile);
        goto shutdown;
    }

    stat(loclfile, &fileinfo);

    /* Ultra basic "connect to port 22 on localhost"
     * Your code is responsible for creating the socket establishing the
     * connection
     */
    sock = socket(AF_INET, SOCK_STREAM, 0);

    sin.sin_family = AF_INET;
    sin.sin_port = htons(22);
    sin.sin_addr.s_addr = hostaddr;
    if (connect(sock, (struct sockaddr*)(&sin),
            sizeof(struct sockaddr_in)) != 0) {
        fprintf(stderr, "failed to connect!\n");
        return -1;
    }

    /* We set the socket non-blocking. We do it after the connect just to
        simplify the example code. */
#ifdef F_SETFL
    /* FIXME: this can/should be done in a more portable manner */
    rc = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, rc | O_NONBLOCK);
#elif defined(HAVE_IOCTLSOCKET)
    ioctlsocket(sock, FIONBIO, &flag);
#else
#ifdef WIN32
    u_long mode = 1;
    ioctlsocket (sock, FIONBIO, &mode);
#else
#error "add support for setting the socket non-blocking here"
#endif
#endif

    /* Create a session instance
     */
    session = libssh2_session_init();
    if(!session)
        return -1;

    /* Since we have set non-blocking, tell libssh2 we are non-blocking */
    libssh2_session_set_blocking(session, 0);

    /* ... start it up. This will trade welcome banners, exchange keys,
     * and setup crypto, compression, and MAC layers
     */
    while ((rc = libssh2_session_startup(session, sock))
           == LIBSSH2_ERROR_EAGAIN);
    if(rc) {
        fprintf(stderr, "Failure establishing SSH session: %d\n", rc);
        return -1;
    }

    /* At this point we havn't yet authenticated.  The first thing to do
     * is check the hostkey's fingerprint against our known hosts Your app
     * may have it hard coded, may go to a file, may present it to the
     * user, that's your call
     */
    fingerprint = libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_MD5);
    fprintf(stderr, "Fingerprint: ");
    for(i = 0; i < 16; i++) {
        fprintf(stderr, "%02X ", (unsigned char)fingerprint[i]);
    }
    fprintf(stderr, "\n");

    if (auth_pw) {
        /* We could authenticate via password */
        while ((rc = libssh2_userauth_password(session, username, password)) ==
               LIBSSH2_ERROR_EAGAIN);
        if (rc) {
            fprintf(stderr, "Authentication by password failed.\n");
            goto shutdown;
        }
    } else {
        /* Or by public key */
        while ((rc = libssh2_userauth_publickey_fromfile(session, username,
                                                         "/home/username/.ssh/id_rsa.pub",
                                                         "/home/username/.ssh/id_rsa",
                                                         password)) == LIBSSH2_ERROR_EAGAIN);
        if (rc) {
            fprintf(stderr, "\tAuthentication by public key failed\n");
            goto shutdown;
        }
    }

    /* Request a file via SCP */
    do {
        channel = libssh2_scp_send(session, scppath, 0x1FF & fileinfo.st_mode,
                                   (unsigned long)fileinfo.st_size);

        if ((!channel) && (libssh2_session_last_errno(session) !=
                           LIBSSH2_ERROR_EAGAIN)) {
            char *err_msg;

            libssh2_session_last_error(session, &err_msg, NULL, 0);
            fprintf(stderr, "%s\n", err_msg);
            goto shutdown;
        }
    } while (!channel);

    fprintf(stderr, "SCP session waiting to send file\n");
    do {
        nread = fread(mem, 1, sizeof(mem), local);
        if (nread <= 0) {
            /* end of file */
            break;
        }
        ptr = mem;

        do {
            /* write data in a loop until we block */
            while ((rc = libssh2_channel_write(channel, ptr, nread)) ==
                   LIBSSH2_ERROR_EAGAIN);
            if (rc < 0) {
                fprintf(stderr, "ERROR %d\n", rc);
            }
            ptr += rc;
            nread -= rc;
        } while (nread > 0);
    } while (1);

    fprintf(stderr, "Sending EOF\n");
    while (libssh2_channel_send_eof(channel) == LIBSSH2_ERROR_EAGAIN);

    fprintf(stderr, "Waiting for EOF\n");
    while (libssh2_channel_wait_eof(channel) == LIBSSH2_ERROR_EAGAIN);

    fprintf(stderr, "Waiting for channel to close\n");
    while (libssh2_channel_wait_closed(channel) == LIBSSH2_ERROR_EAGAIN);

    libssh2_channel_free(channel);
    channel = NULL;

 shutdown:

    while ((rc = libssh2_session_disconnect(session,
                                            "Normal Shutdown, Thank you for playing")) == LIBSSH2_ERROR_EAGAIN);
    libssh2_session_free(session);

#ifdef WIN32
    Sleep(1000);
    closesocket(sock);
#else
    sleep(1);
    close(sock);
#endif
    fprintf(stderr, "all done\n");
    return 0;
}
