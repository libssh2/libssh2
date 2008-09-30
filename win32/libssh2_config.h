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

/* defined into MS PSDK but not into Mingw w32api */
#define WINSOCK_VERSION MAKEWORD(2,0)

#endif

#define HAVE_WINSOCK2_H
#define HAVE_IOCTLSOCKET
#define HAVE_SELECT

#ifdef _MSC_VER
#define snprintf _snprintf
#if _MSC_VER < 1500
#define vsnprintf _vsnprintf
#else
#define ssize_t SSIZE_T
#define uint32_t UINT32
#endif
#define strncasecmp _strnicmp
#define strcasecmp _stricmp
#else
#define strncasecmp strnicmp
#define strcasecmp stricmp
#endif /* _MSC_VER */

/* Compile in zlib support */
#define LIBSSH2_HAVE_ZLIB 1

/* Enable newer diffie-hellman-group-exchange-sha1 syntax */
#define LIBSSH2_DH_GEX_NEW 1

#endif /* LIBSSH2_CONFIG_H */


