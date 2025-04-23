# Copyright (C) The libssh2 project and its contributors.
# SPDX-License-Identifier: BSD-3-Clause
#
###########################################################################
# Find the Libgcrypt library
#
# Input variables:
#
# - `LIBGCRYPT_INCLUDE_DIR`:  The Libgcrypt include directory.
# - `LIBGCRYPT_LIBRARY`:      Path to `libgcrypt` library.
#
# Defines:
#
# - `LIBGCRYPT_FOUND`:        System has Libgcrypt.
# - `LIBGCRYPT_VERSION`:      Version of Libgcrypt.
# - `libssh2::libgcrypt`:     libgcrypt library target.

set(_libgcrypt_pc_requires "libgcrypt")

if(LIBSSH2_USE_PKGCONFIG AND
   NOT DEFINED LIBGCRYPT_INCLUDE_DIR AND
   NOT DEFINED LIBGCRYPT_LIBRARY)
  find_package(PkgConfig QUIET)
  pkg_check_modules(_libgcrypt ${_libgcrypt_pc_requires})
endif()

if(_libgcrypt_FOUND)
  set(Libgcrypt_FOUND TRUE)
  set(LIBGCRYPT_FOUND TRUE)
  set(LIBGCRYPT_VERSION ${_libgcrypt_VERSION})
  message(STATUS "Found Libgcrypt (via pkg-config): ${_libgcrypt_INCLUDE_DIRS} (found version \"${LIBGCRYPT_VERSION}\")")
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
    set(_libgcrypt_INCLUDE_DIRS ${LIBGCRYPT_INCLUDE_DIR})
    set(_libgcrypt_LIBRARIES    ${LIBGCRYPT_LIBRARY})
  endif()

  mark_as_advanced(LIBGCRYPT_INCLUDE_DIR LIBGCRYPT_LIBRARY)
endif()

if(LIBGCRYPT_FOUND)
  if(CMAKE_VERSION VERSION_LESS 3.13)
    link_directories(${_libgcrypt_LIBRARY_DIRS})
  endif()

  if(NOT TARGET libssh2::libgcrypt)
    add_library(libssh2::libgcrypt INTERFACE IMPORTED)
    set_target_properties(libssh2::libgcrypt PROPERTIES
      INTERFACE_LIBSSH2_PC_MODULES "${_libgcrypt_pc_requires}"
      INTERFACE_COMPILE_OPTIONS "${_libgcrypt_CFLAGS}"
      INTERFACE_INCLUDE_DIRECTORIES "${_libgcrypt_INCLUDE_DIRS}"
      INTERFACE_LINK_DIRECTORIES "${_libgcrypt_LIBRARY_DIRS}"
      INTERFACE_LINK_LIBRARIES "${_libgcrypt_LIBRARIES}")
  endif()
endif()
