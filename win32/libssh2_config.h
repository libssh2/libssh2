#ifndef LIBSSH2_CONFIG_H
#define LIBSSH2_CONFIG_H

#ifndef WIN32
#define WIN32
#endif

#ifndef _CRT_SECURE_NO_DEPRECATE
#define _CRT_SECURE_NO_DEPRECATE 1
#endif

#define HAVE_LIBCRYPT32
#define HAVE_STDLIB_H
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
#  if _MSC_VER < 1500
#   define vsnprintf _vsnprintf
#  endif
#  define strdup _strdup
# endif
#endif

#endif /* LIBSSH2_CONFIG_H */
