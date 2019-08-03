#ifndef LIBSSH2_TESTS_USERAUTH_HELPERS
#define LIBSSH2_TESTS_USERAUTH_HELPERS

#include "../../clar_libssh2.h"

void cl_userauth_check_mech(LIBSSH2_SESSION *session, const char *username, const char *mech);

typedef enum {
	USERAUTH_MECH_UNNEGOTIATED = 0,
	USERAUTH_MECH_PASSWORD,
	USERAUTH_MECH_KEYBOARD_INTERACTIVE,
	USERAUTH_MECH_PUBLICKEY,
} USERAUTH_MECH;

typedef struct {
	const char *password;
	const char *publickey;
	const char *privatekey;

} userauth_options;

#define USERAUTH_OPTIONS_INIT { NULL, NULL, NULL }

void cl_userauth_authenticate(LIBSSH2_SESSION *session, const char *username,
							  const userauth_options *opts);

#endif /* LIBSSH2_TESTS_USERAUTH_HELPERS */
