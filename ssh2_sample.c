#include "libssh2.h"
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <ctype.h>

int main(int argc, char *argv[]) {
	int sock, i, auth_pw = 1;
	struct sockaddr_in sin;
	char *fingerprint;
	LIBSSH2_SESSION *session;
	LIBSSH2_CHANNEL *channel;

	/* Ultra basic "connect to port 22 on localhost"
	 * Your code is responsible for creating the socket establishing the connection
	 */
	sock = socket(AF_INET, SOCK_STREAM, 0);
	fcntl(sock, F_SETFL, 0);
	sin.sin_family = AF_INET;
	sin.sin_port = htons(22);
	sin.sin_addr.s_addr = htonl(0x7F000001);
	connect(sock, (struct sockaddr*)(&sin), sizeof(struct sockaddr_in));

	/* Create a session instance and start it up
	 * This will trade welcome banners, exchange keys, and setup crypto, compression, and MAC layers
	 */
	session = libssh2_session_init();
	if (libssh2_session_startup(session, sock)) {
		fprintf(stderr, "Failure establishing SSH session\n");
		return -1;
	}

	/* At this point we havn't authenticated,
	 * The first thing to do is check the hostkey's fingerprint against our known hosts
	 * Your app may have it hard coded, may go to a file, may present it to the user, that's your call
	 */
	fingerprint = libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_MD5);
	printf("Fingerprint: ");
	for(i = 0; i < 16; i++) {
		printf("%02X ", (unsigned char)fingerprint[i]);
	}
	printf("\n");

	if (auth_pw) {
		/* We could authenticate via password */
		if (libssh2_userauth_password(session, "username", "password")) {
			printf("Authentication by password failed.\n");
			goto shutdown;
		}
	} else {
		/* Or by public key */
		if (libssh2_userauth_publickey_fromfile(session, "username", "/home/username/.ssh/id_rsa.pub", "/home/username/.ssh/id_rsa", "pasphrase")) {
			printf("\tAuthentication by public key failed\n");
			goto shutdown;
		}
	}

	/* Request a shell */
	if (!(channel = libssh2_channel_open_session(session))) {
		fprintf(stderr, "Unable to open a session\n");
		goto shutdown;
	}

	/* Some environment variables may be set,
	 * It's up to the server which ones it'll allow though
	 */
	libssh2_channel_setenv(channel, "FOO", "bar");

	/* Request a terminal with 'vanilla' terminal emulation
	 * See /etc/termcap for more options
	 */
	if (libssh2_channel_request_pty(channel, "vanilla")) {
		fprintf(stderr, "Failed requesting pty\n");
		goto skip_shell;
	}

	/* Open a SHELL on that pty */
	if (libssh2_channel_shell(channel)) {
		fprintf(stderr, "Unable to request shell on allocated pty\n");
		goto shutdown;
	}

	/* At this point the shell can be interacted with using
	 * libssh2_channel_read()
	 * libssh2_channel_read_stderr()
	 * libssh2_channel_write()
	 * libssh2_channel_write_stderr()
	 *
	 * Blocking mode may be (en|dis)abled with: libssh2_channel_set_blocking()
	 * If the server send EOF, libssh2_channel_eof() will return non-0
	 * To send EOF to the server use: libssh2_channel_send_eof()
	 * A channel can be closed with: libssh2_channel_close()
	 * A channel can be freed with: libssh2_channel_free()
	 */

 skip_shell:
	if (channel) {
		libssh2_channel_free(channel);
		channel = NULL;
	}

	/* Other channel types are supported via:
	 * libssh2_scp_send()
	 * libssh2_scp_recv()
	 * libssh2_channel_direct_tcpip()
	 */

 shutdown:

	libssh2_session_disconnect(session, "Normal Shutdown, Thank you for playing");
	libssh2_session_free(session);

	sleep(1);
	close(sock);

	return 0;
}
