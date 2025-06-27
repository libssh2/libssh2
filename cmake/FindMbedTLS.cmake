# Copyright (C) The libssh2 project and its contributors.
# SPDX-License-Identifier: BSD-3-Clause
#
###########################################################################
# Find the mbedTLS library
#
# Input variables:
#
# - `MBEDTLS_INCLUDE_DIR`:  The mbedTLS include directory.
# - `MBEDCRYPTO_LIBRARY`:   Path to `mbedcrypto` library.
#
# Defines:
#
# - `MBEDTLS_FOUND`:        System has mbedTLS.
# - `MBEDTLS_VERSION`:      Version of mbedTLS.
# - `libssh2::mbedcrypto`:  mbedcrypto library target.

set(_mbedtls_pc_requires "mbedcrypto")

if(LIBSSH2_USE_PKGCONFIG AND
   NOT DEFINED MBEDTLS_INCLUDE_DIR AND
   NOT DEFINED MBEDCRYPTO_LIBRARY)
  find_package(PkgConfig QUIET)
  pkg_check_modules(_mbedtls ${_mbedtls_pc_requires})
endif()

if(_mbedtls_FOUND)
  set(MbedTLS_FOUND TRUE)
  set(MBEDTLS_FOUND TRUE)
  set(MBEDTLS_VERSION ${_mbedtls_VERSION})
  message(STATUS "Found MbedTLS (via pkg-config): ${_mbedtls_INCLUDE_DIRS} (found version \"${MBEDTLS_VERSION}\")")
else()
  set(_mbedtls_pc_requires "")

  find_path(MBEDTLS_INCLUDE_DIR NAMES "mbedtls/version.h")
  find_library(MBEDCRYPTO_LIBRARY NAMES "mbedcrypto" "libmbedcrypto")

  unset(MBEDTLS_VERSION CACHE)
  if(MBEDTLS_INCLUDE_DIR)
    if(EXISTS "${MBEDTLS_INCLUDE_DIR}/mbedtls/build_info.h")  # 3.x
      set(_version_header "${MBEDTLS_INCLUDE_DIR}/mbedtls/build_info.h")
    elseif(EXISTS "${MBEDTLS_INCLUDE_DIR}/mbedtls/version.h")  # 2.x
      set(_version_header "${MBEDTLS_INCLUDE_DIR}/mbedtls/version.h")
    else()
      unset(_version_header)
    endif()
    if(_version_header)
      set(_version_regex "#[\t ]*define[\t ]+MBEDTLS_VERSION_STRING[\t ]+\"([0-9.]+)\"")
      file(STRINGS "${_version_header}" _version_str REGEX "${_version_regex}")
      string(REGEX REPLACE "${_version_regex}" "\\1" _version_str "${_version_str}")
      set(MBEDTLS_VERSION "${_version_str}")
      unset(_version_regex)
      unset(_version_str)
      unset(_version_header)
    endif()
  endif()

  include(FindPackageHandleStandardArgs)
  find_package_handle_standard_args(MbedTLS
    REQUIRED_VARS
      MBEDTLS_INCLUDE_DIR
      MBEDCRYPTO_LIBRARY
    VERSION_VAR
      MBEDTLS_VERSION
  )

  if(MBEDTLS_FOUND)
    set(_mbedtls_INCLUDE_DIRS ${MBEDTLS_INCLUDE_DIR})
    set(_mbedtls_LIBRARIES    ${MBEDCRYPTO_LIBRARY})
  endif()

  mark_as_advanced(MBEDTLS_INCLUDE_DIR MBEDCRYPTO_LIBRARY)
endif()

if(MBEDTLS_FOUND)
  if(CMAKE_VERSION VERSION_LESS 3.13)
    link_directories(${_mbedtls_LIBRARY_DIRS})
  endif()

  if(NOT TARGET libssh2::mbedcrypto)
    add_library(libssh2::mbedcrypto INTERFACE IMPORTED)
    set_target_properties(libssh2::mbedcrypto PROPERTIES
      INTERFACE_LIBSSH2_PC_MODULES "${_mbedtls_pc_requires}"
      INTERFACE_COMPILE_OPTIONS "${_mbedtls_CFLAGS}"
      INTERFACE_INCLUDE_DIRECTORIES "${_mbedtls_INCLUDE_DIRS}"
      INTERFACE_LINK_DIRECTORIES "${_mbedtls_LIBRARY_DIRS}"
      INTERFACE_LINK_LIBRARIES "${_mbedtls_LIBRARIES}")
  endif()
endif()
