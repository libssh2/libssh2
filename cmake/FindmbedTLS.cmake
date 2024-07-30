# Copyright (C) The libssh2 project and its contributors.
# SPDX-License-Identifier: BSD-3-Clause

# - Try to find mbedTLS
# Input variables:
#  MBEDTLS_INCLUDE_DIR    - The mbedTLS include directory
#  MBEDCRYPTO_LIBRARY     - Path to mbedTLS Crypto library
# This will define all or none of:
#  MBEDTLS_FOUND          - If mbedTLS headers and library were found
#  MBEDTLS_INCLUDE_DIRS   - The mbedTLS include directories
#  MBEDTLS_LIBRARIES      - The libraries needed to use mbedTLS

find_package(PkgConfig QUIET)
pkg_check_modules(MBEDTLS "mbedcrypto")

if(MBEDTLS_FOUND)
  set(MBEDTLS_LIBRARIES ${MBEDTLS_LINK_LIBRARIES})
else()
  find_path(MBEDTLS_INCLUDE_DIR NAMES "mbedtls/version.h")
  find_library(MBEDCRYPTO_LIBRARY NAMES "mbedcrypto" "libmbedcrypto")

  if(MBEDTLS_INCLUDE_DIR)
    file(READ "${MBEDTLS_INCLUDE_DIR}/mbedtls/build_info.h" _mbedtls_header_1)
    file(READ "${MBEDTLS_INCLUDE_DIR}/mbedtls/version.h" _mbedtls_header_2)
    set(_mbedtls_regex "MBEDTLS_VERSION_STRING +\"([0-9|.]+)\"")
    string(REGEX MATCH "${_mbedtls_regex}" _mbedtls_match "${_mbedtls_header_1} ${_mbedtls_header_2}")
    string(REGEX REPLACE "${_mbedtls_regex}" "\\1" MBEDTLS_VERSION "${_mbedtls_match}")
  endif()

  include(FindPackageHandleStandardArgs)
  find_package_handle_standard_args("mbedTLS"
    REQUIRED_VARS
      MBEDTLS_INCLUDE_DIR
      MBEDCRYPTO_LIBRARY
    VERSION_VAR MBEDTLS_VERSION)

  mark_as_advanced(MBEDTLS_INCLUDE_DIR MBEDCRYPTO_LIBRARY)

  if(MBEDTLS_FOUND)
    set(MBEDTLS_INCLUDE_DIRS "${MBEDCRYPTO_INCLUDE_DIR}")
    set(MBEDTLS_LIBRARIES    "${MBEDCRYPTO_LIBRARY}")
    message(STATUS "Found mbedTLS libraries: ${MBEDTLS_LIBRARIES}")
  endif()
endif()
