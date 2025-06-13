# Copyright (C) The libssh2 project and its contributors.
# SPDX-License-Identifier: BSD-3-Clause

#[=======================================================================[.rst:
FindMbedTLS v1.0
--------

Find MbedTLS library and include files.

This module is a compatibility layer for the library version below 3.6.0,
where full support of cmake configuration modules appeared. It is recommended
to use the library 3.6 and higher, for which this module is redundant.

The module provides the same targets as the MbedTLS 3.6 modules, due to which
the migration process to 3.6 will be very simple - just delete the local copy
of this file and reinitialize the project.

IMPORTED Targets
^^^^^^^^^^^^^^^^

This module defines the :prop_tgt:`IMPORTED` targets:

``MbedTLS::mbedtls``

``MbedTLS::mbedcrypto``

``MbedTLS::mbedx509``

Result Variables
^^^^^^^^^^^^^^^^

This module defines the following variables:

``MbedTLS_FOUND``
  True if ``MbedTLS`` was found.

``MbedTLS_INCLUDE_DIRS``

  Where to find mbedtls/version.h, etc.

``MbedTLS_LIBRARIES``
  List of libraries for using ``mbedtls``.

Cache Variables
^^^^^^^^^^^^^^^

This module may set the following variables depending on platform.
These variables may optionally be set to help this module find the
correct files, but clients should not use these as results:

``MbedTLS_INCLUDE_DIR``
  The full path to the directory containing ``mbedtls/version.h``.

``MbedTLS_mbedtls_LIBRARY``
  The full path to the mbedtls library.

``MbedTLS_mbedcrypto_LIBRARY``
  The full path to the mbedcrypto library.

``MbedTLS_mbedx509_LIBRARY``
  The full path to the mbedx509 library.

#]=======================================================================]

include(FindPackageHandleStandardArgs)

list(APPEND _MBEDTLS_COMPONENTS mbedtls mbedcrypto mbedx509)

find_path(MbedTLS_INCLUDE_DIR mbedtls/version.h
  HINTS /usr/pkg/include /usr/local/include /usr/include
  PATH_SUFFIXES "mbedtls3"
)

mark_as_advanced(MbedTLS_INCLUDE_DIR)

if(MbedTLS_INCLUDE_DIR AND EXISTS "${MbedTLS_INCLUDE_DIR}/mbedtls/build_info.h")
  file(STRINGS "${MbedTLS_INCLUDE_DIR}/mbedtls/build_info.h" MBEDTLS_VERSION_STR
    REGEX "^#[\t ]*define[\t ]+MBEDTLS_VERSION_STRING[\t ]+\"[\.0-9]+\"")
  string(REGEX REPLACE "^.*MBEDTLS_VERSION_STRING[\t ]+\"([0-9]+\\.[0-9]+\\.[0-9]+)\".*$"
    "\\1" MBEDTLS_VERSION_STR "${MBEDTLS_VERSION_STR}")
  set(MbedTLS_VERSION "${MBEDTLS_VERSION_STR}")

  # ZLIB support was removed in 3.0.0
  if(MbedTLS_VERSION VERSION_LESS "3.0.0")
    include(CheckSymbolExists)
    check_symbol_exists(MBEDTLS_ZLIB_SUPPORT "${MbedTLS_INCLUDE_DIR}/mbedtls/version.h" HAVE_ZLIB_SUPPORT)
    if(HAVE_ZLIB_SUPPORT)
      find_package(ZLIB REQUIRED)
    endif(HAVE_ZLIB_SUPPORT)
  endif()
else()
  message(WARNING "No Mbed TLS version information could be parsed from the source headers")
endif()

foreach(v ${_MBEDTLS_COMPONENTS})
  find_library(MbedTLS_${v}_LIBRARY
    NAMES ${v}-3 ${v}   # Some Linux distributions offers mbedtls-2 and mbedtls-3 simultaneously, prefer mbedtls-3
    PATHS /usr/pkg /usr/local /usr
  )
  mark_as_advanced(MbedTLS_mbedtls_LIBRARY)
endforeach()

find_package_handle_standard_args(MbedTLS REQUIRED_VARS MbedTLS_mbedtls_LIBRARY MbedTLS_INCLUDE_DIR)

foreach(v ${_MBEDTLS_COMPONENTS})
  if(MbedTLS_${v}_LIBRARY AND NOT TARGET MbedTLS::${v})
    add_library(MbedTLS::${v} UNKNOWN IMPORTED)
    set_target_properties(MbedTLS::${v} PROPERTIES
      IMPORTED_LOCATION "${MbedTLS_${v}_LIBRARY}"
      INTERFACE_INCLUDE_DIRECTORIES ${MbedTLS_INCLUDE_DIR}
    )
    if(HAVE_ZLIB_SUPPORT)
      set_target_properties(MbedTLS::${v} PROPERTIES
        LINK_INTERFACE_LIBRARIES ZLIB::ZLIB
      )
    endif()
  endif()
endforeach()

if(MbedTLS_FOUND)
  set(MbedTLS_INCLUDE_DIRS
    ${MbedTLS_INCLUDE_DIR}
  )
  set(MbedTLS_LIBRARIES
    ${MbedTLS_mbedtls_LIBRARY}
    ${MbedTLS_mbedcrypto_LIBRARY}
    ${MbedTLS_mbedx509_LIBRARY}
  )
endif()

unset(_MBEDTLS_COMPONENTS)
