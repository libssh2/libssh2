# Copyright (C) The libssh2 project and its contributors.
# SPDX-License-Identifier: BSD-3-Clause
#
###########################################################################
# Find the Libgcrypt library
#
# Input variables:
#
# - `LIBGCRYPT_INCLUDE_DIR`:   The Libgcrypt include directory.
# - `LIBGCRYPT_LIBRARY`:       Path to `libgcrypt` library.
#
# Result variables:
#
# - `LIBGCRYPT_FOUND`:         System has Libgcrypt.
# - `LIBGCRYPT_INCLUDE_DIRS`:  The Libgcrypt include directories.
# - `LIBGCRYPT_LIBRARIES`:     The Libgcrypt library names.
# - `LIBGCRYPT_LIBRARY_DIRS`:  The Libgcrypt library directories.
# - `LIBGCRYPT_PC_REQUIRES`:   The Libgcrypt pkg-config packages.
# - `LIBGCRYPT_CFLAGS`:        Required compiler flags.
# - `LIBGCRYPT_VERSION`:       Version of Libgcrypt.

set(LIBGCRYPT_PC_REQUIRES "libgcrypt")

if(LIBSSH2_USE_PKGCONFIG AND
   NOT DEFINED LIBGCRYPT_INCLUDE_DIR AND
   NOT DEFINED LIBGCRYPT_LIBRARY)
  find_package(PkgConfig QUIET)
  pkg_check_modules(LIBGCRYPT ${LIBGCRYPT_PC_REQUIRES})
endif()

if(LIBGCRYPT_FOUND)
  set(Libgcrypt_FOUND TRUE)
  string(REPLACE ";" " " LIBGCRYPT_CFLAGS "${LIBGCRYPT_CFLAGS}")
  message(STATUS "Found Libgcrypt (via pkg-config): ${LIBGCRYPT_INCLUDE_DIRS} (found version \"${LIBGCRYPT_VERSION}\")")
else()
  find_path(LIBGCRYPT_INCLUDE_DIR NAMES "gcrypt.h")
  find_library(LIBGCRYPT_LIBRARY NAMES "gcrypt" "libgcrypt")

  unset(LIBGCRYPT_VERSION CACHE)
  if(LIBGCRYPT_INCLUDE_DIR AND EXISTS "${LIBGCRYPT_INCLUDE_DIR}/gcrypt.h")
    set(_version_regex "#[\t ]*define[\t ]+GCRYPT_VERSION[\t ]+\"([^\"]*)\"")
    file(STRINGS "${LIBGCRYPT_INCLUDE_DIR}/gcrypt.h" _version_str REGEX "${_version_regex}")
    string(REGEX REPLACE "${_version_regex}" "\\1" _version_str "${_version_str}")
    set(LIBGCRYPT_VERSION "${_version_str}")
    unset(_version_regex)
    unset(_version_str)
  endif()

  include(FindPackageHandleStandardArgs)
  find_package_handle_standard_args(Libgcrypt
    REQUIRED_VARS
      LIBGCRYPT_INCLUDE_DIR
      LIBGCRYPT_LIBRARY
    VERSION_VAR
      LIBGCRYPT_VERSION
  )

  if(LIBGCRYPT_FOUND)
    set(LIBGCRYPT_INCLUDE_DIRS ${LIBGCRYPT_INCLUDE_DIR})
    set(LIBGCRYPT_LIBRARIES    ${LIBGCRYPT_LIBRARY})
  endif()

  mark_as_advanced(LIBGCRYPT_INCLUDE_DIR LIBGCRYPT_LIBRARY)
endif()
