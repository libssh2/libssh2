#define WIN32
#include <winsock2.h>
#include <mswsock.h>
#include <ws2tcpip.h>

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

#define snprintf	_snprintf

