/*
 * Sample showing how to upload directory to SFTP.
 *
 * The sample code has default values for host name, user name, password and
 * path, but you can specify them on the command line like:
 *
 * $ ./sftpdir_upload 192.168.0.1 user password /tmp/localdir /tmp/sftpdir
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
#include <dirent.h>
#include <limits.h>

#if defined(_MSC_VER)
#define __FILESIZE "I64u"
#else
#define __FILESIZE "llu"
#endif

static const char *pubkey = "/home/username/.ssh/id_rsa.pub";
static const char *privkey = "/home/username/.ssh/id_rsa";
static const char *username = "username";
static const char *password = "password";
static const char *localpath = "/tmp/localdir";
static const char *sftppath = "/tmp/sftpdir";

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

static void upload_file(LIBSSH2_SFTP *sftp_session, const char *loclfile,
                        const char *sftpfile)
{
    LIBSSH2_SFTP_HANDLE *sftp_handle;
    ssize_t nwritten;
    FILE *local;

    local = fopen(loclfile, "rb");
    if(!local) {
        fprintf(stderr, "Can't open local file %s\n", loclfile);
        return;
    }

    sftp_handle = libssh2_sftp_open(sftp_session, sftpfile,
                                    LIBSSH2_FXF_WRITE |
                                    LIBSSH2_FXF_CREAT |
                                    LIBSSH2_FXF_TRUNC,
                                    LIBSSH2_SFTP_S_IRUSR |
                                    LIBSSH2_SFTP_S_IWUSR |
                                    LIBSSH2_SFTP_S_IRGRP |
                                    LIBSSH2_SFTP_S_IROTH);
    if(!sftp_handle) {
        fprintf(stderr, "Unable to open file with SFTP: %ld\n",
                libssh2_sftp_last_error(sftp_session));
        fclose(local);
        return;
    }

    do {
        char *ptr;
        char mem[1024 * 100];
        size_t nread;

        nread = fread(mem, 1, sizeof(mem), local);
        if(nread <= 0)
            break;
        ptr = mem;

        do {
            nwritten = libssh2_sftp_write(sftp_handle, ptr, nread);
            if(nwritten < 0)
                break;
            ptr += nwritten;
            nread -= nwritten;
        } while(nread);
    } while(nwritten > 0);

    fclose(local);
    libssh2_sftp_close(sftp_handle);
}

static void upload_dir(LIBSSH2_SFTP *sftp_session, const char *loclpath,
                       const char *sftpdir)
{
    int rc;
    DIR *dir;
    struct dirent *entry;

    dir = opendir(loclpath);
    if(!dir) {
        fprintf(stderr, "Can't open local dir: %s\n", loclpath);
        return;
    }

    rc = libssh2_sftp_mkdir(sftp_session, sftpdir,
                            LIBSSH2_SFTP_S_IRWXU |
                            LIBSSH2_SFTP_S_IRGRP |
                            LIBSSH2_SFTP_S_IXGRP |
                            LIBSSH2_SFTP_S_IROTH |
                            LIBSSH2_SFTP_S_IXOTH);
    if(rc) {
        fprintf(stderr, "libssh2_sftp_mkdir failed: %d\n", rc);
        return;
    }

    while((entry = readdir(dir)) != NULL) {
        char locl_path[1024] = { 0 };
        char sftp_path[1024] = { 0 };

        snprintf(locl_path, sizeof(locl_path), "%s/%s", loclpath,
                 entry->d_name);
        snprintf(sftp_path, sizeof(sftp_path), "%s/%s", sftpdir,
                 entry->d_name);

        if(entry->d_type == DT_DIR) {
            if(strncmp(entry->d_name, ".", strlen(entry->d_name)) == 0 ||
               strncmp(entry->d_name, "..", strlen(entry->d_name)) == 0) {
               continue;
            }
            upload_dir(sftp_session, locl_path, sftp_path);
        } else if(entry->d_type == DT_REG) {
            upload_file(sftp_session, locl_path, sftp_path); 
        } else if(entry->d_type == DT_LNK) {
            char realname[512] = { 0 };
            char realpath[PATH_MAX + 1] = { 0 };
            ssize_t len;
            struct stat st;

            len = readlink(locl_path, realname, sizeof(realname) - 1);
            if(len < 0) {
                fprintf(stderr, "readlink failed: %d\n", errno);
                continue;
            }
            snprintf(realpath, sizeof(realpath), "%s/%s", loclpath, realname);
            if(stat(realpath, &st) == -1) {
                fprintf(stderr, "stat(%s) failed: %d\n", realpath, errno);
                continue;
            }

            if(S_ISDIR(st.st_mode)) {
                upload_dir(sftp_session, realpath, sftp_path);
            } else if(S_ISREG(st.st_mode)) {
                upload_file(sftp_session, realpath, sftp_path); 
            } else {
                /* FIXME: the other type should be uploaded? */
            }
        } else {
            /* FIXME: the other type should be uploaded? */
        }
    }

    closedir(dir);
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
        localpath = argv[4];
    }
    if(argc > 5) {
        sftppath = argv[5];
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

    fprintf(stderr, "uploading...\n");
    upload_dir(sftp_session, localpath, sftppath);
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
