/* Self test, based on example/ssh2.c. */

#include "libssh2_setup.h"
#include <libssh2.h>

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

#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

static const char *pubkey = "etc/user.pub";
static const char *privkey = "etc/user";
static const char *username = "username";
static const char *password = "password";

int main(int argc, char *argv[])
{
    uint32_t hostaddr;
    libssh2_socket_t sock;
    int i, auth_pw = 0;
    struct sockaddr_in sin;
    const char *fingerprint;
    char *userauthlist;
    int rc;
    LIBSSH2_SESSION *session = NULL;
    LIBSSH2_CHANNEL *channel;

#ifdef WIN32
    WSADATA wsadata;

    rc = WSAStartup(MAKEWORD(2, 0), &wsadata);
    if(rc) {
        fprintf(stderr, "WSAStartup failed with error: %d\n", rc);
        return 1;
    }
#endif

    (void)argc;
    (void)argv;

    if(getenv("USER"))
        username = getenv("USER");

    if(getenv("PRIVKEY"))
        privkey = getenv("PRIVKEY");

    if(getenv("PUBKEY"))
        pubkey = getenv("PUBKEY");

    hostaddr = htonl(0x7F000001);

    rc = libssh2_init(0);
    if(rc) {
        fprintf(stderr, "libssh2 initialization failed (%d)\n", rc);
        return 1;
    }

    rc = 1;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock == LIBSSH2_INVALID_SOCKET) {
        fprintf(stderr, "failed to create socket!\n");
        goto shutdown;
    }

#ifndef WIN32
    fcntl(sock, F_SETFL, 0);
#endif
    sin.sin_family = AF_INET;
    sin.sin_port = htons(4711);
    sin.sin_addr.s_addr = hostaddr;
    if(connect(sock, (struct sockaddr*)(&sin), sizeof(struct sockaddr_in))) {
        fprintf(stderr, "failed to connect!\n");
        goto shutdown;
    }

    /* Create a session instance and start it up. This will trade welcome
     * banners, exchange keys, and setup crypto, compression, and MAC layers
     */
    session = libssh2_session_init();
    if(libssh2_session_handshake(session, sock)) {
        fprintf(stderr, "Failure establishing SSH session\n");
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

    /* check what authentication methods are available */
    userauthlist = libssh2_userauth_list(session, username,
                                         (unsigned int)strlen(username));
    if(userauthlist) {
        fprintf(stderr, "Authentication methods: %s\n", userauthlist);
        if(strstr(userauthlist, "password")) {
            auth_pw |= 1;
        }
        if(strstr(userauthlist, "keyboard-interactive")) {
            auth_pw |= 2;
        }
        if(strstr(userauthlist, "publickey")) {
            auth_pw |= 4;
        }

        if(auth_pw & 4) {
            /* Authenticate by public key */
            if(libssh2_userauth_publickey_fromfile(session, username,
                                                   pubkey, privkey,
                                                   password)) {
                fprintf(stderr, "Authentication by public key failed!\n");
                goto shutdown;
            }
            else {
                fprintf(stderr, "Authentication by public key succeeded.\n");
            }
        }
        else {
            fprintf(stderr, "No supported authentication methods found!\n");
            goto shutdown;
        }
    }

    /* Request a session channel on which to run a shell */
    channel = libssh2_channel_open_session(session);
    if(!channel) {
        fprintf(stderr, "Unable to open a session\n");
        goto shutdown;
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
        goto shutdown;
    }

    rc = 0;

skip_shell:

    if(channel) {
        libssh2_channel_free(channel);
        channel = NULL;
    }

shutdown:

    if(session) {
        libssh2_session_disconnect(session, "Normal Shutdown");
        libssh2_session_free(session);
    }

    if(sock != LIBSSH2_INVALID_SOCKET) {
#ifdef WIN32
        closesocket(sock);
#else
        close(sock);
#endif
    }

    fprintf(stderr, "all done\n");

    libssh2_exit();

    return rc;
}
