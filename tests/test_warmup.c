/* Warm-up test. Always return 0.
   Workaround for CI/docker/etc flakiness on the first run. */

#include "session_fixture.h"
#include "runner.h"

#include <libssh2.h>

#include <stdio.h>

int main(void)
{
    LIBSSH2_SESSION *session = start_session_fixture();
    if(session != NULL) {
        size_t len = 0;
        int type = 0;
        const char *hostkey = libssh2_session_hostkey(session, &len, &type);

        (void)hostkey;

        fprintf(stdout,
                "libssh2_session_hostkey returned len, type: %d, %d\n",
                (int)len, type);
    }
    stop_session_fixture();
    return 0;
}
