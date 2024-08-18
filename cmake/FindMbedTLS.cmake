# Copyright (C) The libssh2 project and its contributors.
# SPDX-License-Identifier: BSD-3-Clause
#
# - Try to find mbedTLS
#
# Input variables:
#  MBEDTLS_INCLUDE_DIR - the mbedTLS include directory
#  MBEDCRYPTO_LIBRARY - path to mbedTLS Crypto library
# Output variables:
#  MBEDTLS_FOUND - system has mbedTLS
#  MBEDTLS_LIBRARIES - link these to use mbedTLS

find_path(MBEDTLS_INCLUDE_DIR NAMES "mbedtls/version.h")
find_library(MBEDCRYPTO_LIBRARY NAMES "mbedcrypto" "libmbedcrypto")

if(MBEDTLS_INCLUDE_DIR)
  if(EXISTS "${MBEDTLS_INCLUDE_DIR}/mbedtls/build_info.h")
    file(READ "${MBEDTLS_INCLUDE_DIR}/mbedtls/build_info.h" _mbedtls_header_new)
  endif()
  file(READ "${MBEDTLS_INCLUDE_DIR}/mbedtls/version.h" _mbedtls_header_old)
  set(_mbedtls_regex "MBEDTLS_VERSION_STRING +\"([0-9|.]+)\"")
  string(REGEX MATCH "${_mbedtls_regex}" _mbedtls_match "${_mbedtls_header_new} ${_mbedtls_header_old}")
  string(REGEX REPLACE "${_mbedtls_regex}" "\\1" MBEDTLS_VERSION "${_mbedtls_match}")
  unset(_mbedtls_header_new)
  unset(_mbedtls_header_old)
  unset(_mbedtls_match)
  unset(_mbedtls_regex)
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(MbedTLS
  REQUIRED_VARS MBEDTLS_INCLUDE_DIR MBEDCRYPTO_LIBRARY
  VERSION_VAR MBEDTLS_VERSION)

if(MBEDTLS_FOUND)
  set(MBEDTLS_INCLUDE_DIRS ${MBEDTLS_INCLUDE_DIR})
  set(MBEDTLS_LIBRARIES    ${MBEDCRYPTO_LIBRARY})
  message(STATUS "Found mbedTLS libraries: ${MBEDTLS_LIBRARIES}")
endif()

mark_as_advanced(MBEDTLS_INCLUDE_DIR MBEDCRYPTO_LIBRARY)
