# Copyright (C) The libssh2 project and its contributors.
# SPDX-License-Identifier: BSD-3-Clause
#
###########################################################################
# Find the wolfssl library
#
# Input variables:
#
# WOLFSSL_INCLUDE_DIR   The wolfssl include directory
# WOLFSSL_LIBRARY       Path to wolfssl library
#
# Result variables:
#
# WOLFSSL_FOUND         System has wolfssl
# WOLFSSL_INCLUDE_DIRS  The wolfssl include directories
# WOLFSSL_LIBRARIES     The wolfssl library names
# WOLFSSL_VERSION       Version of wolfssl

find_package(PkgConfig QUIET)
pkg_check_modules(PC_WOLFSSL "wolfssl")

find_path(WOLFSSL_INCLUDE_DIR NAMES "wolfssl/options.h"
  HINTS
    ${PC_WOLFSSL_INCLUDEDIR}
    ${PC_WOLFSSL_INCLUDE_DIRS}
)

find_library(WOLFSSL_LIBRARY NAMES "wolfssl"
  HINTS
    ${PC_WOLFSSL_LIBDIR}
    ${PC_WOLFSSL_LIBRARY_DIRS}
)

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
