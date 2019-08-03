#include "clar_libssh2.h"
#include "userauth_helpers.h"

#define WRONG_PASSWORD "i'm not the password"

static LIBSSH2_SESSION *g_session;

void test_userauth_keyboard__initialize_blocking(void)
{
    g_session = cl_ssh2_open_session_openssh(NULL, 1);
}

void test_userauth_keyboard__initialize_nonblocking(void)
{
    g_session = cl_ssh2_open_session_openssh(NULL, 0);
}

void test_userauth_keyboard__cleanup(void)
{
    cl_ssh2_close_connected_session();
}

static void kbd_callback(const char *name, int name_len,
                         const char *instruction, int instruction_len,
                         int num_prompts,
                         const LIBSSH2_USERAUTH_KBDINT_PROMPT *prompts,
                         LIBSSH2_USERAUTH_KBDINT_RESPONSE *responses,
                         void **abstract)
{
/*    int i; */
    const char *password = (const char *)*abstract;

/*
    fprintf(stdout, "Kb-int name: %.*s\n", name_len, name);
    fprintf(stdout, "Kb-int instruction: %.*s\n",
            instruction_len, instruction);
    for(i = 0; i < num_prompts; ++i) {
        fprintf(stdout, "Kb-int prompt %d: %.*s\n", i, prompts[i].length,
                prompts[i].text);
    }
*/

    if(num_prompts == 1) {
        responses[0].text = strdup(password);
        responses[0].length = strlen(password);
    }
}

void test_userauth_keyboard__interactive_auth_fails_with_wrong_response(void)
{
    void **abstract;

    cl_userauth_check_mech(g_session,
                           OPENSSH_USERNAME, "keyboard-interactive");

    abstract = libssh2_session_abstract(g_session);
    *abstract = WRONG_PASSWORD;

    cl_ssh2_fail(LIBSSH2_ERROR_AUTHENTICATION_FAILED,
         libssh2_userauth_keyboard_interactive_ex(g_session, OPENSSH_USERNAME,
                                                  strlen(OPENSSH_USERNAME),
                                                  kbd_callback));

    cl_assert_equal_i(0, libssh2_userauth_authenticated(g_session));
}

void
test_userauth_keyboard__interactive_auth_succeeds_with_correct_response(void)
{
    void **abstract;

    cl_userauth_check_mech(g_session,
                           OPENSSH_USERNAME, "keyboard-interactive");

    abstract = libssh2_session_abstract(g_session);
    *abstract = OPENSSH_PASSWORD;

    cl_ssh2_check(libssh2_userauth_keyboard_interactive_ex(g_session,
        OPENSSH_USERNAME,
        strlen(OPENSSH_USERNAME),
        kbd_callback));

    cl_assert_equal_i(1, libssh2_userauth_authenticated(g_session));
}
