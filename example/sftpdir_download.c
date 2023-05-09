/*
 * Sample showing how to download SFTP directory.
 *
 * The sample code has default values for host name, user name, password and
 * path, but you can specify them on the command line like:
 *
 * $ ./sftpdir_download 192.168.0.1 user password /tmp/secretdir /tmp/localdir
 */

#include "libssh2_setup.h"
#include <libssh2.h>
#include <libssh2_sftp.h>

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
#include <ctype.h>

#if defined(_MSC_VER)
#define __FILESIZE "I64u"
#else
#define __FILESIZE "llu"
#endif

static const char *pubkey = "/home/username/.ssh/id_rsa.pub";
static const char *privkey = "/home/username/.ssh/id_rsa";
static const char *username = "username";
static const char *password = "password";
static const char *sftppath = "/tmp/secretdir";
static const char *localpath = "/tmp/localdir";

static void download_sftpdir(LIBSSH2_SESSION *session,
                             LIBSSH2_SFTP *sftp_session,
                             const char *sftpdir, const char *localdir);

static void kbd_callback(const char *name, int name_len,
                         const char *instruction, int instruction_len,
                         int num_prompts,
                         const LIBSSH2_USERAUTH_KBDINT_PROMPT *prompts,
                         LIBSSH2_USERAUTH_KBDINT_RESPONSE *responses,
                         void **abstract)
{
    (void)name;
    (void)name_len;
    (void)instruction;
    (void)instruction_len;
    if(num_prompts == 1) {
        responses[0].text = strdup(password);
        responses[0].length = (unsigned int)strlen(password);
    }
    (void)prompts;
    (void)abstract;
} /* kbd_callback */

/* mkdir and chdir */
static int mkch_dir(const char *path)
{
    if(mkdir(path, 0755)) {
        fprintf(stderr, "Unable to create local dir: %s\n", path);
        return -1;
    }

    if(chdir(path)) {
        fprintf(stderr, "Unable to change local dir: %s.\n", path);
        return -1;
    }

    return 0;
}

static void download_file(LIBSSH2_SESSION *session, const char *remote,
                          const char *local)
{
    LIBSSH2_CHANNEL *channel;
    libssh2_struct_stat fileinfo;
    libssh2_struct_stat_size got = 0;
    int fd;

    channel = libssh2_scp_recv2(session, remote, &fileinfo);
    if(!channel) {
        fprintf(stderr, "Unable to open a session at %s %d\n",
                remote, libssh2_session_last_errno(session));
        return;
    }

    fd = open(local, O_RDWR | O_CREAT | O_APPEND, fileinfo.st_mode);
    if(fd < 0) {
        fprintf(stderr, "Can't create file %s\n", local);
        libssh2_channel_free(channel);
        return;
    }

    while(got < fileinfo.st_size) {
        char mem[1024];
        int amount = sizeof(mem);
        ssize_t nread;

        if((fileinfo.st_size - got) < amount) {
            amount = (int)(fileinfo.st_size - got);
        }

        nread = libssh2_channel_read(channel, mem, amount);
        if(nread > 0) {
            write(fd, mem, nread);
        }
        else if(nread < 0) {
            fprintf(stderr, "libssh2_channel_read() failed: %d\n",
                    (int)nread);
            break;
        }
        got += nread;
    }

    close(fd);
    libssh2_channel_free(channel);
}

static void download_link(LIBSSH2_SESSION *session,
                          LIBSSH2_SFTP *sftp_session,
                          const char *link, const char *localdir)
{
    int rc;
    char realpath[512];
    LIBSSH2_SFTP_ATTRIBUTES attrs;

    rc = libssh2_sftp_realpath(sftp_session, link, realpath, sizeof(realpath));
    if(!rc) {
        fprintf(stderr, "Can't get the realpath with SFTP: %ld",
                libssh2_sftp_last_error(sftp_session));
        return;
    }

    rc = libssh2_sftp_stat(sftp_session, realpath, &attrs);
    if(rc) {
        fprintf(stderr, "Can't get attrs with SFTP: %ld\n",
                libssh2_sftp_last_error(sftp_session));
        return;
    }

    if(LIBSSH2_SFTP_S_ISDIR(attrs.permissions)) {
        download_sftpdir(session, sftp_session, realpath, localdir);
    }
    else if(LIBSSH2_SFTP_S_ISREG(attrs.permissions)) {
        download_file(session, realpath, localdir);
    }
    else if(LIBSSH2_SFTP_S_ISLNK(attrs.permissions)) {
        download_link(session, sftp_session, realpath, localdir);
    }
}

static void download_sftpdir(LIBSSH2_SESSION *session,
                             LIBSSH2_SFTP *sftp_session,
                             const char *sftpdir, const char *localdir)
{
    LIBSSH2_SFTP_HANDLE *sftp_handle;
    int rc;
    sftp_handle = libssh2_sftp_opendir(sftp_session, sftpdir);
    if(!sftp_handle) {
        fprintf(stderr, "Unable to open dir with SFTP %s\n", sftpdir);

        if(chdir("..") == -1)
            fprintf(stderr, "Unable to chdir(..).\n");
        return;
    }

    if(mkch_dir(localdir) == -1) {
        libssh2_sftp_closedir(sftp_handle);
        return;
    }

    do {
        char mem[512];
        char longentry[512];
        char sftp_subdir[1024];
        char locl_subdir[1024];
        LIBSSH2_SFTP_ATTRIBUTES attrs;

        /* loop until we fail */
        rc = libssh2_sftp_readdir_ex(sftp_handle, mem, sizeof(mem),
                                     longentry, sizeof(longentry), &attrs);
        if(rc > 0) {
            /* rc is the length of the file name in the mem
               buffer */

            snprintf(locl_subdir, sizeof(locl_subdir), "%s/%s", localdir, mem);
            snprintf(sftp_subdir, sizeof(sftp_subdir), "%s/%s", sftpdir, mem);

            if(longentry[0] != '\0') {
                if(strncmp(mem, ".", rc) != 0 && strncmp(mem, "..", rc) != 0) {
                    if(LIBSSH2_SFTP_S_ISDIR(attrs.permissions)) {
                        download_sftpdir(session, sftp_session, sftp_subdir,
                                         locl_subdir);
                    }
                    else if(LIBSSH2_SFTP_S_ISLNK(attrs.permissions)) {
                        download_link(session, sftp_session, sftp_subdir,
                                      locl_subdir);
                    }
                    else if(LIBSSH2_SFTP_S_ISREG(attrs.permissions)) {
                        download_file(session, sftp_subdir, locl_subdir);
                    } else {
                        /* FIXME:
                           what are we supposed to do the other type? */
                    }
                }
            }
            else {
                /* Permission denied? */
                fprintf(stderr, "Download: %s: Permission denied\n", mem);
            }
        }
        else {
            break;
        }
    } while(1);

    if(chdir("..") == -1)
        fprintf(stderr, "Unable to chdir(..).\n");

    libssh2_sftp_closedir(sftp_handle);
}

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
    LIBSSH2_SFTP *sftp_session;

#ifdef WIN32
    WSADATA wsadata;

    rc = WSAStartup(MAKEWORD(2, 0), &wsadata);
    if(rc) {
        fprintf(stderr, "WSAStartup failed with error: %d\n", rc);
        return 1;
    }
#endif

    if(argc > 1) {
        hostaddr = inet_addr(argv[1]);
    }
    else {
        hostaddr = htonl(0x7F000001);
    }
    if(argc > 2) {
        username = argv[2];
    }
    if(argc > 3) {
        password = argv[3];
    }
    if(argc > 4) {
        sftppath = argv[4];
    }
    if(argc > 5) {
        localpath = argv[5];
    }

    rc = libssh2_init(0);
    if(rc) {
        fprintf(stderr, "libssh2 initialization failed (%d)\n", rc);
        return 1;
    }

    /*
     * The application code is responsible for creating the socket
     * and establishing the connection
     */
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock == LIBSSH2_INVALID_SOCKET) {
        fprintf(stderr, "failed to create socket!\n");
        goto shutdown;
    }

    sin.sin_family = AF_INET;
    sin.sin_port = htons(22);
    sin.sin_addr.s_addr = hostaddr;
    if(connect(sock, (struct sockaddr*)(&sin), sizeof(struct sockaddr_in))) {
        fprintf(stderr, "failed to connect!\n");
        goto shutdown;
    }

    /* Create a session instance */
    session = libssh2_session_init();
    if(!session) {
        fprintf(stderr, "Could not initialize SSH session!\n");
        goto shutdown;
    }

    /* ... start it up. This will trade welcome banners, exchange keys,
     * and setup crypto, compression, and MAC layers
     */
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

        /* check for options */
        if(argc > 6) {
            if((auth_pw & 1) && !strcmp(argv[6], "-p")) {
                auth_pw = 1;
            }
            if((auth_pw & 2) && !strcmp(argv[6], "-i")) {
                auth_pw = 2;
            }
            if((auth_pw & 4) && !strcmp(argv[6], "-k")) {
                auth_pw = 4;
            }
        }

        if(auth_pw & 1) {
            /* We could authenticate via password */
            if(libssh2_userauth_password(session, username, password)) {
                fprintf(stderr, "Authentication by password failed!\n");
                goto shutdown;
            }
        }
        else if(auth_pw & 2) {
            /* Or via keyboard-interactive */
            if(libssh2_userauth_keyboard_interactive(session, username,
                                                     &kbd_callback) ) {
                fprintf(stderr,
                        "Authentication by keyboard-interactive failed!\n");
                goto shutdown;
            }
            else {
                fprintf(stderr,
                        "Authentication by keyboard-interactive succeeded.\n");
            }
        }
        else if(auth_pw & 4) {
            /* Or by public key */
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

    fprintf(stderr, "libssh2_sftp_init()!\n");
    sftp_session = libssh2_sftp_init(session);

    if(!sftp_session) {
        fprintf(stderr, "Unable to init SFTP session\n");
        goto shutdown;
    }

    /* Since we have not set non-blocking, tell libssh2 we are blocking */
    libssh2_session_set_blocking(session, 1);

    fprintf(stderr, "downloading...\n");
    download_sftpdir(session, sftp_session, sftppath, localpath);
    fprintf(stderr, "all done...\n");

    libssh2_sftp_shutdown(sftp_session);

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

    return 0;
}
