# Copyright (C) The libssh2 project and its contributors.
# SPDX-License-Identifier: BSD-3-Clause
#
###########################################################################
# Find the wolfSSL library
#
# Input variables:
#
# - `WOLFSSL_INCLUDE_DIR`:   The wolfSSL include directory.
# - `WOLFSSL_LIBRARY`:       Path to `wolfssl` library.
#
# Result variables:
#
# - `WOLFSSL_FOUND`:         System has wolfSSL.
# - `WOLFSSL_VERSION`:       Version of wolfSSL.

set(_wolfssl_pc_requires "wolfssl")

if(LIBSSH2_USE_PKGCONFIG AND
   NOT DEFINED WOLFSSL_INCLUDE_DIR AND
   NOT DEFINED WOLFSSL_LIBRARY)
  find_package(PkgConfig QUIET)
  pkg_check_modules(WOLFSSL ${_wolfssl_pc_requires})
endif()

if(WOLFSSL_FOUND)
  set(WolfSSL_FOUND TRUE)
  string(REPLACE ";" " " WOLFSSL_CFLAGS "${WOLFSSL_CFLAGS}")
  message(STATUS "Found WolfSSL (via pkg-config): ${WOLFSSL_INCLUDE_DIRS} (found version \"${WOLFSSL_VERSION}\")")
else()
  find_path(WOLFSSL_INCLUDE_DIR NAMES "wolfssl/options.h")
  find_library(WOLFSSL_LIBRARY NAMES "wolfssl")

  unset(WOLFSSL_VERSION CACHE)
  if(WOLFSSL_INCLUDE_DIR AND EXISTS "${WOLFSSL_INCLUDE_DIR}/wolfssl/version.h")
    set(_version_regex "#[\t ]*define[\t ]+LIBWOLFSSL_VERSION_STRING[\t ]+\"([^\"]*)\"")
    file(STRINGS "${WOLFSSL_INCLUDE_DIR}/wolfssl/version.h" _version_str REGEX "${_version_regex}")
    string(REGEX REPLACE "${_version_regex}" "\\1" _version_str "${_version_str}")
    set(WOLFSSL_VERSION "${_version_str}")
    unset(_version_regex)
    unset(_version_str)
  endif()

  include(FindPackageHandleStandardArgs)
  find_package_handle_standard_args(WolfSSL
    REQUIRED_VARS
      WOLFSSL_INCLUDE_DIR
      WOLFSSL_LIBRARY
    VERSION_VAR
      WOLFSSL_VERSION
  )

  if(WOLFSSL_FOUND)
    set(WOLFSSL_INCLUDE_DIRS ${WOLFSSL_INCLUDE_DIR})
    set(WOLFSSL_LIBRARIES    ${WOLFSSL_LIBRARY})
  endif()

  mark_as_advanced(WOLFSSL_INCLUDE_DIR WOLFSSL_LIBRARY)
endif()

if(WOLFSSL_FOUND AND WIN32)
  list(APPEND WOLFSSL_LIBRARIES "crypt32")
endif()

if(WOLFSSL_FOUND AND NOT TARGET libssh2::WolfSSL)
  add_library(libssh2::WolfSSL INTERFACE IMPORTED)
  set_target_properties(libssh2::WolfSSL PROPERTIES
    VERSION "${WOLFSSL_VERSION}"
    LIBSSH2_PC_MODULES "${_wolfssl_pc_requires}"
    INTERFACE_COMPILE_OPTIONS "${WOLFSSL_CFLAGS}"
    INTERFACE_INCLUDE_DIRECTORIES "${WOLFSSL_INCLUDE_DIRS}"
    INTERFACE_LINK_DIRECTORIES "${WOLFSSL_LIBRARY_DIRS}"
    INTERFACE_LINK_LIBRARIES "${WOLFSSL_LIBRARIES}")
endif()
