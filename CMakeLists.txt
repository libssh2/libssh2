# Copyright (c) 2014, 2015  Alexander Lamaison <alexander.lamaison@gmail.com>
#
# Redistribution and use in source and binary forms,
# with or without modification, are permitted provided
# that the following conditions are met:
#
#   Redistributions of source code must retain the above
#   copyright notice, this list of conditions and the
#   following disclaimer.
#
#   Redistributions in binary form must reproduce the above
#   copyright notice, this list of conditions and the following
#   disclaimer in the documentation and/or other materials
#   provided with the distribution.
#
#   Neither the name of the copyright holder nor the names
#   of any other contributors may be used to endorse or
#   promote products derived from this software without
#   specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
# CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
# INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
# USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
# OF SUCH DAMAGE.

include(CheckFunctionExists)
include(CheckSymbolExists)
include(CheckIncludeFiles)
include(CheckTypeSize)
include(CheckSymbolExists)
include(CMakePushCheckState)

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake;${CMAKE_MODULE_PATH}")
include(CheckFunctionExistsMayNeedLibrary)
include(CheckNonblockingSocketSupport)

cmake_minimum_required(VERSION 3.1)

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

project(libssh2 C)
set(PROJECT_URL "https://www.libssh2.org/")
set(PROJECT_DESCRIPTION "The SSH library")

option(BUILD_STATIC_LIBS "Build Static Libraries" ON)
option(BUILD_SHARED_LIBS "Build Shared Libraries" OFF)

# Parse version

file(READ ${CMAKE_CURRENT_SOURCE_DIR}/include/libssh2.h _HEADER_CONTENTS)
string(
  REGEX REPLACE ".*#define LIBSSH2_VERSION[ \t]+\"([^\"]+)\".*" "\\1"
  LIBSSH2_VERSION "${_HEADER_CONTENTS}")
string(
  REGEX REPLACE ".*#define LIBSSH2_VERSION_MAJOR[ \t]+([0-9]+).*" "\\1"
  LIBSSH2_VERSION_MAJOR "${_HEADER_CONTENTS}")
string(
  REGEX REPLACE ".*#define LIBSSH2_VERSION_MINOR[ \t]+([0-9]+).*" "\\1"
  LIBSSH2_VERSION_MINOR "${_HEADER_CONTENTS}")
string(
  REGEX REPLACE ".*#define LIBSSH2_VERSION_PATCH[ \t]+([0-9]+).*" "\\1"
  LIBSSH2_VERSION_PATCH "${_HEADER_CONTENTS}")

if(NOT LIBSSH2_VERSION OR
   NOT LIBSSH2_VERSION_MAJOR MATCHES "^[0-9]+$" OR
   NOT LIBSSH2_VERSION_MINOR MATCHES "^[0-9]+$" OR
   NOT LIBSSH2_VERSION_PATCH MATCHES "^[0-9]+$")
  message(
    FATAL_ERROR
    "Unable to parse version from"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/libssh2.h")
endif()

include(GNUInstallDirs)
install(
  FILES docs/AUTHORS COPYING docs/HACKING README RELEASE-NOTES NEWS
  DESTINATION ${CMAKE_INSTALL_DOCDIR})

if(MSVC)
  set(CMAKE_VS_GLOBALS "TrackFileAccess=false")  # faster builds
endif()

include(max_warnings)
include(FeatureSummary)

# Add socket libraries
if(WIN32)
  list(APPEND SOCKET_LIBRARIES ws2_32)
else()
  check_function_exists_may_need_library(socket HAVE_SOCKET socket)
  if(NEED_LIB_SOCKET)
    list(APPEND SOCKET_LIBRARIES socket)
  endif()
  check_function_exists_may_need_library(inet_addr HAVE_INET_ADDR nsl)
  if(NEED_LIB_NSL)
    list(APPEND SOCKET_LIBRARIES nsl)
  endif()
endif()

option(BUILD_EXAMPLES "Build libssh2 examples" ON)
option(BUILD_TESTING "Build libssh2 test suite" ON)

if(NOT BUILD_STATIC_LIBS AND (NOT BUILD_SHARED_LIBS OR BUILD_EXAMPLES OR BUILD_TESTING))
  set(BUILD_STATIC_LIBS ON)
endif()

set(LIB_STATIC "libssh2_static")
set(LIB_SHARED "libssh2_shared")  # Must match libssh2_shared_EXPORTS macro in include/libssh2.h

# Auto-detection

## Platform checks
check_include_files(unistd.h HAVE_UNISTD_H)
check_include_files(inttypes.h HAVE_INTTYPES_H)
check_include_files(stdlib.h HAVE_STDLIB_H)
check_include_files(sys/select.h HAVE_SYS_SELECT_H)

check_include_files(sys/uio.h HAVE_SYS_UIO_H)
check_include_files(sys/socket.h HAVE_SYS_SOCKET_H)
check_include_files(sys/ioctl.h HAVE_SYS_IOCTL_H)
check_include_files(sys/time.h HAVE_SYS_TIME_H)
check_include_files(sys/un.h HAVE_SYS_UN_H)
check_include_files(winsock2.h HAVE_WINSOCK2_H)

# for example and tests
check_include_files(sys/param.h HAVE_SYS_PARAM_H)
check_include_files(arpa/inet.h HAVE_ARPA_INET_H)
check_include_files(netinet/in.h HAVE_NETINET_IN_H)

check_type_size("long long" LONGLONG)

# CMake uses C syntax in check_symbol_exists() that generates a warning with
# MSVC. To not break detection with ENABLE_WERRROR, we disable it for the
# duration of these tests.
if(MSVC AND ENABLE_WERROR)
  cmake_push_check_state()
  set(CMAKE_REQUIRED_FLAGS "/WX-")
endif()

if(HAVE_SYS_TIME_H)
  check_symbol_exists(gettimeofday sys/time.h HAVE_GETTIMEOFDAY)
else()
  check_function_exists(gettimeofday HAVE_GETTIMEOFDAY)
endif()
if(HAVE_STDLIB_H)
  check_symbol_exists(strtoll stdlib.h HAVE_STRTOLL)
else()
  check_function_exists(strtoll HAVE_STRTOLL)
endif()
if (NOT HAVE_STRTOLL)
  # Try _strtoi64 if strtoll isn't available
  check_symbol_exists(_strtoi64 stdlib.h HAVE_STRTOI64)
endif()
check_symbol_exists(snprintf stdio.h HAVE_SNPRINTF)
if(NOT WIN32)
  check_symbol_exists(explicit_bzero string.h HAVE_EXPLICIT_BZERO)
  check_symbol_exists(explicit_memset string.h HAVE_EXPLICIT_MEMSET)
  check_symbol_exists(memset_s string.h HAVE_MEMSET_S)
endif()

if(MSVC AND ENABLE_WERROR)
  cmake_pop_check_state()
endif()

if(${CMAKE_SYSTEM_NAME} STREQUAL "Darwin" OR
   ${CMAKE_SYSTEM_NAME} STREQUAL "Interix")
  # poll() does not work on these platforms
  #
  # Interix: "does provide poll(), but the implementing developer must
  # have been in a bad mood, because poll() only works on the /proc
  # filesystem here"
  #
  # Mac OS X's poll has funny behaviors, like:
  # not being able to do poll on no filedescriptors (10.3?)
  # not being able to poll on some files (like anything in /dev)
  # not having reliable timeout support
  # inconsistent return of POLLHUP where other implementations give POLLIN
  message("poll use is disabled on this platform")
else()
  check_function_exists(poll HAVE_POLL)
endif()

# Non-blocking socket support tests. Use a separate, yet unset variable
# for the socket libraries to not link against the other configured
# dependencies which might not have been built yet.
cmake_push_check_state()
set(CMAKE_REQUIRED_LIBRARIES ${SOCKET_LIBRARIES})
check_nonblocking_socket_support()
cmake_pop_check_state()

## Cryptography backend choice

set(CRYPTO_BACKEND
  ""
  CACHE
  STRING
  "The backend to use for cryptography: OpenSSL, wolfSSL, Libgcrypt,
WinCNG, mbedTLS, or empty to try any available")

# If the crypto backend was given, rather than searching for the first
# we are able to find, the find_package commands must abort configuration
# and report to the user.
if(CRYPTO_BACKEND)
  set(SPECIFIC_CRYPTO_REQUIREMENT REQUIRED)
endif()

if(CRYPTO_BACKEND STREQUAL "OpenSSL" OR NOT CRYPTO_BACKEND)

  find_package(OpenSSL ${SPECIFIC_CRYPTO_REQUIREMENT})

  if(OPENSSL_FOUND)
    set(CRYPTO_BACKEND "OpenSSL")
    set(CRYPTO_SOURCES openssl.c openssl.h)
    set(CRYPTO_BACKEND_DEFINE "LIBSSH2_OPENSSL")
    set(CRYPTO_BACKEND_INCLUDE_DIR ${OPENSSL_INCLUDE_DIR})
    list(APPEND LIBRARIES ${OPENSSL_LIBRARIES})
    list(APPEND PC_REQUIRES_PRIVATE libssl libcrypto)

    if (WIN32)
      # Statically linking to OpenSSL requires crypt32 for some Windows APIs.
      # This should really be handled by FindOpenSSL.cmake.
      list(APPEND LIBRARIES crypt32 bcrypt)
      list(APPEND PC_LIBS -lcrypt32 -lbcrypt)

      #set(CMAKE_FIND_DEBUG_MODE TRUE)

      find_file(DLL_LIBCRYPTO
        NAMES crypto.dll
          libcrypto-1_1.dll libcrypto-1_1-x64.dll
          libcrypto-3.dll libcrypto-3-x64.dll
        HINTS ${_OPENSSL_ROOT_HINTS} PATHS ${_OPENSSL_ROOT_PATHS}
        PATH_SUFFIXES bin NO_DEFAULT_PATH)
      if(DLL_LIBCRYPTO)
        message(STATUS "Found libcrypto DLL: ${DLL_LIBCRYPTO}")
      else()
        message(WARNING
          "Unable to find OpenSSL libcrypto DLL, executables may not run")
      endif()

      find_file(DLL_LIBSSL
        NAMES ssl.dll
          libssl-1_1.dll libssl-1_1-x64.dll
          libssl-3.dll libssl-3-x64.dll
        HINTS ${_OPENSSL_ROOT_HINTS} PATHS ${_OPENSSL_ROOT_PATHS}
        PATH_SUFFIXES bin NO_DEFAULT_PATH)
      if(DLL_LIBSSL)
        message(STATUS "Found libssl DLL: ${DLL_LIBSSL}")
      else()
        message(WARNING
          "Unable to find OpenSSL libssl DLL, executables may not run")
      endif()

      #set(CMAKE_FIND_DEBUG_MODE FALSE)

      if(DLL_LIBCRYPTO AND DLL_LIBSSL)
        list(APPEND _RUNTIME_DEPENDENCIES ${DLL_LIBCRYPTO} ${DLL_LIBSSL})
      endif()
    endif()

    find_package(ZLIB)

    if(ZLIB_FOUND)
      list(APPEND LIBRARIES ${ZLIB_LIBRARIES})
      list(APPEND PC_REQUIRES_PRIVATE zlib)
    endif()
  endif()
endif()

if(CRYPTO_BACKEND STREQUAL "wolfSSL" OR NOT CRYPTO_BACKEND)

  find_package(wolfssl ${SPECIFIC_CRYPTO_REQUIREMENT})

  if(WOLFSSL_FOUND)
    set(CRYPTO_BACKEND "wolfSSL")
    set(CRYPTO_SOURCES openssl.c openssl.h)
    set(CRYPTO_BACKEND_DEFINE "LIBSSH2_WOLFSSL")
    set(CRYPTO_BACKEND_INCLUDE_DIR ${WOLFSSL_INCLUDE_DIR} ${WOLFSSL_INCLUDE_DIR}/wolfssl)
    list(APPEND LIBRARIES ${WOLFSSL_LIBRARIES})
    list(APPEND PC_LIBS -lwolfssl)

    if (WIN32)
      list(APPEND LIBRARIES crypt32)
      list(APPEND PC_LIBS -lcrypt32)
    endif()

    find_package(ZLIB)

    if(ZLIB_FOUND)
      list(PREPEND CRYPTO_BACKEND_INCLUDE_DIR ${ZLIB_INCLUDE_DIR})

      list(APPEND LIBRARIES ${ZLIB_LIBRARIES})  # Public wolfSSL headers require zlib headers
      list(APPEND PC_REQUIRES_PRIVATE zlib)
    endif()
  endif()
endif()

if(CRYPTO_BACKEND STREQUAL "Libgcrypt" OR NOT CRYPTO_BACKEND)

  find_package(Libgcrypt ${SPECIFIC_CRYPTO_REQUIREMENT})

  if(LIBGCRYPT_FOUND)
    set(CRYPTO_BACKEND "Libgcrypt")
    set(CRYPTO_SOURCES libgcrypt.c libgcrypt.h)
    set(CRYPTO_BACKEND_DEFINE "LIBSSH2_LIBGCRYPT")
    set(CRYPTO_BACKEND_INCLUDE_DIR ${LIBGCRYPT_INCLUDE_DIRS})
    list(APPEND LIBRARIES ${LIBGCRYPT_LIBRARIES})
    list(APPEND PC_LIBS -lgcrypt)
  endif()
endif()

if(CRYPTO_BACKEND STREQUAL "mbedTLS" OR NOT CRYPTO_BACKEND)

  find_package(mbedTLS ${SPECIFIC_CRYPTO_REQUIREMENT})

  if(MBEDTLS_FOUND)
    set(CRYPTO_BACKEND "mbedTLS")
    set(CRYPTO_SOURCES mbedtls.c mbedtls.h)
    set(CRYPTO_BACKEND_DEFINE "LIBSSH2_MBEDTLS")
    set(CRYPTO_BACKEND_INCLUDE_DIR ${MBEDTLS_INCLUDE_DIR})
    list(APPEND LIBRARIES ${MBEDTLS_LIBRARIES})
    list(APPEND PC_LIBS -lmbedcrypto)
    link_directories(${MBEDTLS_LIBRARY_DIR})
  endif()
endif()

# Detect platform-specific crypto-backends last:

if(CRYPTO_BACKEND STREQUAL "WinCNG" OR NOT CRYPTO_BACKEND)

  # The check actually compiles the header.  This requires windows.h.
  check_include_files("windows.h;bcrypt.h" HAVE_BCRYPT_H)

  if(HAVE_BCRYPT_H)
    set(CRYPTO_BACKEND "WinCNG")
    set(CRYPTO_SOURCES wincng.c wincng.h)
    set(CRYPTO_BACKEND_DEFINE "LIBSSH2_WINCNG")
    set(CRYPTO_BACKEND_INCLUDE_DIR "")

    set(HAVE_LIBCRYPT32 TRUE)
    list(APPEND LIBRARIES bcrypt)
    list(APPEND PC_LIBS -lbcrypt)

    # Reading keys from files is optional and depends on Wincrypt
    check_include_files("windows.h;wincrypt.h" HAVE_WINCRYPT_H)

    if(HAVE_WINCRYPT_H)
      list(APPEND LIBRARIES crypt32)
      list(APPEND PC_LIBS -lcrypt32)
    endif()

  elseif(${SPECIFIC_CRYPTO_REQUIREMENT} STREQUAL ${REQUIRED})
    message(FATAL_ERROR "WinCNG not available")
  endif()
endif()

#

add_subdirectory(src)

if(BUILD_EXAMPLES)
  add_subdirectory(example)
endif()

if(BUILD_TESTING)
  enable_testing()
  add_subdirectory(tests)
endif()

option(LINT "Check style while building" OFF)
if(LINT)
  add_custom_target(lint ALL
    ./ci/checksrc.sh
    WORKING_DIRECTORY ${libssh2_SOURCE_DIR})
  if(BUILD_STATIC_LIBS)
    add_dependencies(${LIB_STATIC} lint)
  else()
    add_dependencies(${LIB_SHARED} lint)
  endif()
endif()

add_subdirectory(docs)

feature_summary(WHAT ALL)

set(CPACK_PACKAGE_VERSION_MAJOR ${LIBSSH2_VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${LIBSSH2_VERSION_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH ${LIBSSH2_VERSION_PATCH})
set(CPACK_PACKAGE_VERSION ${LIBSSH2_VERSION})
include(CPack)
