/* libssh2 test receiving large amounts of data through a channel */

#include "runner.h"

/* configured in Dockerfile */
static const char *USERNAME = "libssh2";
static const char *KEY_FILE_PRIVATE = "key_rsa";
static const char *KEY_FILE_PUBLIC = "key_rsa.pub";

/* Size and number of blocks to transfer
 * This needs to be large to increase the chance of timing effects causing
 * different code paths to be hit in the unframing code, but not so long that
 * the integration tests take too long. 5 seconds of run time is probably a
 * reasonable compromise. The block size is an odd number to increase the
 * chance that various internal buffer and block boundaries are overlapped. */
#define XFER_BS 997
#define XFER_COUNT 140080

#define STRINGIFY(x) STRINGIFY2(x)
#define STRINGIFY2(x) #x

/* command to transfer the desired amount of data */
#define REMOTE_COMMAND "dd if=/dev/zero bs=" STRINGIFY(XFER_BS) \
                       " count=" STRINGIFY(XFER_COUNT) " status=none"

int test(LIBSSH2_SESSION *session)
{
    int rc;
    long xfer_bytes = 0;
    LIBSSH2_CHANNEL *channel;

    const char *userauth_list =
        libssh2_userauth_list(session, USERNAME,
                              (unsigned int)strlen(USERNAME));
    if(userauth_list == NULL) {
        print_last_session_error("libssh2_userauth_list");
        return 1;
    }

    if(strstr(userauth_list, "publickey") == NULL) {
        fprintf(stderr, "'publickey' was expected in userauth list: %s\n",
                userauth_list);
        return 1;
    }

    rc = libssh2_userauth_publickey_fromfile_ex(
        session, USERNAME, (unsigned int)strlen(USERNAME),
        srcdir_path(KEY_FILE_PUBLIC), srcdir_path(KEY_FILE_PRIVATE), NULL);
    if(rc) {
        print_last_session_error("libssh2_userauth_publickey_fromfile_ex");
        return 1;
    }

    /* Request a session channel on which to run a shell */
    channel = libssh2_channel_open_session(session);
    if(!channel) {
        fprintf(stderr, "Unable to open a session\n");
        goto shutdown;
    }

    /* Send the command to transfer data */
    if(libssh2_channel_exec(channel, REMOTE_COMMAND)) {
        fprintf(stderr, "Unable to request command on channel\n");
        goto shutdown;
    }

    /* Read data */
    while(!libssh2_channel_eof(channel)) {
        char buf[1024];
        ssize_t err = libssh2_channel_read(channel, buf, sizeof(buf));
        if(err < 0)
            fprintf(stderr, "Unable to read response: %d\n", (int)err);
        else {
            int i;
            for(i = 0; i < err; ++i) {
                if(buf[i]) {
                    fprintf(stderr, "Bad data received\n");
                    /* Test will fail below due to bad data length */
                    break;
                }
            }
            xfer_bytes += i;
        }
    }

    /* Shut down */
    if(libssh2_channel_close(channel))
        fprintf(stderr, "Unable to close channel\n");

    if(channel) {
        libssh2_channel_free(channel);
        channel = NULL;
    }

shutdown:

    /* Test check */
    if(xfer_bytes != XFER_COUNT * XFER_BS) {
        fprintf(stderr, "Not enough bytes received: %ld not %ld\n",
                xfer_bytes, (long)XFER_COUNT * XFER_BS);
        return 1;  /* error */
    }
    return 0;
}
