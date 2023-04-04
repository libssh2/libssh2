#ifndef LIBSSH2_SETUP_H
#define LIBSSH2_SETUP_H

/* Header for platform/compiler-specific initialization.
   Used by 'src', 'example', 'tests' */

#if defined(_WIN32) && !defined(WIN32)
#define WIN32
#endif

/* Configuration provided by build tools (autotools and CMake),
   and via platform-specific directories for os400 and vms */
#if defined(HAVE_CONFIG_H) || defined(__OS400__) || defined(__VMS)

#include "libssh2_config.h"

/* Hand-crafted configuration for platforms which lack config tool. */
#elif defined(WIN32)

#define HAVE_IOCTLSOCKET
#define HAVE_SELECT
#define HAVE_SNPRINTF

#ifdef __MINGW32__
# define HAVE_UNISTD_H
# define HAVE_INTTYPES_H
# define HAVE_SYS_TIME_H
# define HAVE_GETTIMEOFDAY
# define HAVE_LONGLONG
# define HAVE_STRTOLL
#elif defined(_MSC_VER)
# if _MSC_VER >= 1310
#  define HAVE_LONGLONG
# endif
# if _MSC_VER >= 1800
#  define HAVE_STRTOLL
# endif
# if _MSC_VER < 1900
#  undef HAVE_SNPRINTF
# endif
#endif

#endif /* defined(HAVE_CONFIG_H) */

/* Below applies to both auto-detected and hand-crafted configs */

#ifdef WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#ifdef _MSC_VER
# ifndef _CRT_SECURE_NO_WARNINGS
# define _CRT_SECURE_NO_WARNINGS
# endif
# if _MSC_VER < 1500
#  define vsnprintf _vsnprintf
# endif
# if _MSC_VER < 1900
#  define strdup _strdup
/* Silence bogus warning C4127: conditional expression is constant */
#  pragma warning(disable:4127)
# endif
#endif

#endif /* WIN32 */

#endif /* LIBSSH2_SETUP_H */
