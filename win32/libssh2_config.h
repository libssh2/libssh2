#ifndef LIBSSH2_CONFIG_H
#define LIBSSH2_CONFIG_H

#ifndef WIN32
#define WIN32
#endif
#include <winsock2.h>
#include <mswsock.h>
#include <ws2tcpip.h>

#ifdef __MINGW32__
#define HAVE_UNISTD_H
#define HAVE_INTTYPES_H
#define HAVE_SYS_TIME_H
#endif

#define HAVE_WINSOCK2_H
#define HAVE_IOCTLSOCKET

/* same as WSABUF */
struct iovec {
	u_long iov_len;
	char *iov_base;
};

#define inline __inline

static inline int writev(int sock, struct iovec *iov, int nvecs)
{
	DWORD ret;
	if (WSASend(sock, (LPWSABUF)iov, nvecs, &ret, 0, NULL, NULL) == 0) {
		return ret;
	}
	return -1;
}

/* not really usleep, but safe for the way we use it in this lib */
static inline int usleep(int udelay)
{
	Sleep(udelay / 1000);
	return 0;
}

#ifdef _MSC_VER
#define snprintf _snprintf
#define vsnprintf _vsnprintf
#define strncasecmp _strnicmp
#define strcasecmp _stricmp
#else
#ifdef __MINGW32__
#define WINSOCK_VERSION MAKEWORD(2,0)
#else
#define strncasecmp strnicmp
#define strcasecmp stricmp
#endif /* __MINGW32__ */
#endif /* _MSC_VER */

/* Compile in zlib support */
#define LIBSSH2_HAVE_ZLIB 1

/* Enable newer diffie-hellman-group-exchange-sha1 syntax */
#define LIBSSH2_DH_GEX_NEW 1

#endif /* LIBSSH2_CONFIG_H */


