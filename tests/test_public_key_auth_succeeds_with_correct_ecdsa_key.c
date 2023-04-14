#include "runner.h"

/* configured in Dockerfile */
static const char *USERNAME = "libssh2";
static const char *KEY_FILE_PRIVATE = "key_ecdsa";
static const char *KEY_FILE_PUBLIC = "key_ecdsa.pub";

int test(LIBSSH2_SESSION *session)
{
    int rc;

    const char *userauth_list =
        libssh2_userauth_list(session, USERNAME,
                              (unsigned int)strlen(USERNAME));
    if(!userauth_list) {
        print_last_session_error("libssh2_userauth_list");
        return 1;
    }

    if(!strstr(userauth_list, "publickey")) {
        fprintf(stderr, "'publickey' was expected in userauth list: %s\n",
                userauth_list);
        return 1;
    }

    rc = libssh2_userauth_publickey_fromfile_ex(session, USERNAME,
                                                (unsigned int)strlen(USERNAME),
                                                srcdir_path(KEY_FILE_PUBLIC),
                                                srcdir_path(KEY_FILE_PRIVATE),
                                                NULL);
    if(rc) {
        print_last_session_error("libssh2_userauth_publickey_fromfile_ex");
        return 1;
    }

    return 0;
}
