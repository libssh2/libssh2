/*
 * $Id: scp.c,v 1.2 2007/01/30 11:10:26 bagder Exp $
 *
 * Sample showing how to do a simple SCP transfer.
 */

#include <libssh2.h>

#ifndef WIN32
# include <netinet/in.h>
# include <sys/socket.h>
# include <unistd.h>
#else
# include <winsock2.h>
#endif

#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <ctype.h>

int main(int argc, char *argv[])
{
	int sock, i, auth_pw = 1;
	struct sockaddr_in sin;
	const char *fingerprint;
	LIBSSH2_SESSION *session;
	LIBSSH2_CHANNEL *channel;
	char *username=(char *)"username";
	char *password=(char *)"password";
	char *scppath=(char *)"/tmp/TEST";
	struct stat fileinfo;
	int rc;

#ifdef WIN32
	WSADATA wsadata;

	WSAStartup(WINSOCK_VERSION, &wsadata);
#endif

	/* Ultra basic "connect to port 22 on localhost"
	 * Your code is responsible for creating the socket establishing the
	 * connection
	 */
	sock = socket(AF_INET, SOCK_STREAM, 0);

	sin.sin_family = AF_INET;
	sin.sin_port = htons(22);
	sin.sin_addr.s_addr = htonl(0x7F000001);
	if (connect(sock, (struct sockaddr*)(&sin),
		    sizeof(struct sockaddr_in)) != 0) {
		fprintf(stderr, "failed to connect!\n");
		return -1;
	}

	/* Create a session instance
	 */
	session = libssh2_session_init();
	if(!session)
		return -1;

	/* ... start it up. This will trade welcome banners, exchange keys,
	 * and setup crypto, compression, and MAC layers
	 */
	rc = libssh2_session_startup(session, sock);
	if(rc) {
		fprintf(stderr, "Failure establishing SSH session: %d\n", rc);
		return -1;
	}

	/* At this point we havn't yet authenticated.  The first thing to do
	 * is check the hostkey's fingerprint against our known hosts Your app
	 * may have it hard coded, may go to a file, may present it to the
	 * user, that's your call
	 */
	fingerprint = libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_MD5);
	printf("Fingerprint: ");
	for(i = 0; i < 16; i++) {
		printf("%02X ", (unsigned char)fingerprint[i]);
	}
	printf("\n");

	if(argc > 1) {
		username = argv[1];
	}
	if(argc > 2) {
		password = argv[2];
	}
	if(argc > 3) {
		scppath = argv[3];
	}

	if (auth_pw) {
		/* We could authenticate via password */
		if (libssh2_userauth_password(session, username, password)) {
			printf("Authentication by password failed.\n");
			goto shutdown;
		}
	} else {
		/* Or by public key */
		if (libssh2_userauth_publickey_fromfile(session, username,
							"/home/username/.ssh/id_rsa.pub",
							"/home/username/.ssh/id_rsa",
							password)) {
			printf("\tAuthentication by public key failed\n");
			goto shutdown;
		}
	}

	/* Request a file via SCP */
	channel = libssh2_scp_recv(session, scppath, &fileinfo);

	if (!channel) {
		fprintf(stderr, "Unable to open a session\n");
		goto shutdown;
	}

	do {
		char mem[1024];
		/* loop until we fail */
		rc = libssh2_channel_read(channel, mem, sizeof(mem));
		fprintf(stderr, "libssh2_channel_read returned %d\n",
			rc);
		if(rc > 0) {
			write(2, mem, rc);
		}
	} while (rc > 0);

	libssh2_channel_free(channel);
	channel = NULL;

 shutdown:

	libssh2_session_disconnect(session, "Normal Shutdown, Thank you for playing");
	libssh2_session_free(session);

#ifdef WIN32
	Sleep(1000);
	closesocket(sock);
#else
	sleep(1);
	close(sock);
#endif
printf("all done\n");
	return 0;
}
