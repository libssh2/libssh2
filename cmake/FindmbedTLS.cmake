# Copyright (C) The libssh2 project and its contributors.
# SPDX-License-Identifier: BSD-3-Clause
#
# - Try to find mbedTLS
# Once done this will define
#
# Read-Only variables
#  MBEDTLS_FOUND - system has mbedTLS
#  MBEDTLS_INCLUDE_DIR - the mbedTLS include directory
#  MBEDTLS_LIBRARY_DIR - the mbedTLS library directory
#  MBEDTLS_LIBRARIES - Link these to use mbedTLS
#  MBEDCRYPTO_LIBRARY - path to mbedTLS Crypto library

find_path(MBEDTLS_INCLUDE_DIR mbedtls/version.h)
find_library(MBEDCRYPTO_LIBRARY mbedcrypto libmbedcrypto)

if(MBEDTLS_INCLUDE_DIR AND MBEDTLS_LIBRARIES)
  # Already in cache, be silent
  set(MBEDTLS_FIND_QUIETLY TRUE)
endif()

set(MBEDTLS_LIBRARIES "${MBEDCRYPTO_LIBRARY}")

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(mbedTLS DEFAULT_MSG
  MBEDTLS_INCLUDE_DIR MBEDCRYPTO_LIBRARY)

if(MBEDTLS_FOUND)
  if(NOT MBEDTLS_FIND_QUIETLY)
    file(READ "${MBEDTLS_INCLUDE_DIR}/mbedtls/build_info.h" mbedtls_header_1)
    file(READ "${MBEDTLS_INCLUDE_DIR}/mbedtls/version.h" mbedtls_header_2)
    string(REGEX MATCH "MBEDTLS_VERSION_STRING +\"[0-9|.]+\"" MBEDTLSMATCH "${mbedtls_header_1} ${mbedtls_header_2}")
    if(MBEDTLSMATCH)
      string(REGEX REPLACE "MBEDTLS_VERSION_STRING +\"([0-9|.]+)\"" "\\1" MBEDTLS_VERSION ${MBEDTLSMATCH})
    endif()
    message(STATUS "Found mbedTLS crypto: ${MBEDCRYPTO_LIBRARY} (version \"${MBEDTLS_VERSION}\")")
  endif()
elseif(MBEDTLS_FIND_REQUIRED)
  message(FATAL_ERROR "Could not find mbedTLS")
endif()

mark_as_advanced(
  MBEDTLS_INCLUDE_DIR
  MBEDTLS_LIBRARY_DIR
  MBEDTLS_LIBRARIES
  MBEDCRYPTO_LIBRARY
)
