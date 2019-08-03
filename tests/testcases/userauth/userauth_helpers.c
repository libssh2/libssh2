
#include "userauth_helpers.h"

void cl_userauth_check_mech(LIBSSH2_SESSION *session,
                            const char *username, const char *mech)
{
    const char *userauth_list = NULL;
    cl_ssh2_check_ptr_(userauth_list, session,
                       libssh2_userauth_list(session,
                                             username, strlen(username)));

    if(strstr(userauth_list, mech) == NULL) {
        cl_fail_("'%s' was expected in userauth list: %s",
                 mech, userauth_list);
    }
}

void cl_userauth_authenticate(LIBSSH2_SESSION *session, const char *username,
    const userauth_options *opts)
{
    USERAUTH_MECH auth = USERAUTH_MECH_UNNEGOTIATED;
    const char *userauth_list = NULL;

    /* check what authentication methods are available */
    cl_ssh2_check_ptr_(userauth_list, session,
                       libssh2_userauth_list(session,
                                             username, strlen(username)));

    if(strstr(userauth_list, "password") != NULL) {
        auth |= USERAUTH_MECH_PASSWORD;
    }
    if(strstr(userauth_list, "keyboard-interactive") != NULL) {
        auth |= USERAUTH_MECH_KEYBOARD_INTERACTIVE;
    }
    if(strstr(userauth_list, "publickey") != NULL) {
        auth |= USERAUTH_MECH_PUBLICKEY;
    }

    if((auth & USERAUTH_MECH_PASSWORD) && opts->password) {
        auth = USERAUTH_MECH_PASSWORD;
    }
    if((auth & USERAUTH_MECH_KEYBOARD_INTERACTIVE)) {
        auth = USERAUTH_MECH_KEYBOARD_INTERACTIVE;
    }
    if((auth & USERAUTH_MECH_PUBLICKEY) && opts->publickey) {
        auth = USERAUTH_MECH_PUBLICKEY;
    }

    if(auth & USERAUTH_MECH_PASSWORD) {
        cl_ssh2_check(libssh2_userauth_password(session, username,
                                                opts->password));
    }
    else if(auth & USERAUTH_MECH_KEYBOARD_INTERACTIVE) {
        /* Or via keyboard-interactive */
#if 0
        void *tmp;
        void **abstract = libssh2_session_abstract(session);

        tmp = *abstract;
        *abstract = (void *)opts->password;

        cl_ssh2_check(libssh2_userauth_keyboard_interactive(session,
                                                            username,
                                                            &kbd_callback));
        *abstract = tmp;
#endif
        cl_assert_(0, "notimpl");
    }
    else if(auth & USERAUTH_MECH_PUBLICKEY) {
        cl_ssh2_check(libssh2_userauth_publickey_fromfile(session, username,
                                                          opts->publickey,
                                                          opts->privatekey,
                                                          opts->password));
    }
    else {
        cl_fail("No supported authentication methods found!\n");
    }

    cl_assert_equal_i(1, libssh2_userauth_authenticated(session));
}
