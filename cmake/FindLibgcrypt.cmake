# Copyright (C) Alexander Lamaison <alexander.lamaison@gmail.com>
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
#
# SPDX-License-Identifier: BSD-3-Clause
#
###########################################################################
# Find the libgcrypt library
#
# Input variables:
#
# LIBGCRYPT_INCLUDE_DIR   The libgcrypt include directory
# LIBGCRYPT_LIBRARY       Path to libgcrypt library
#
# Result variables:
#
# LIBGCRYPT_FOUND         System has libgcrypt
# LIBGCRYPT_INCLUDE_DIRS  The libgcrypt include directories
# LIBGCRYPT_LIBRARIES     The libgcrypt library names
# LIBGCRYPT_VERSION       Version of libgcrypt

find_package(PkgConfig QUIET)
pkg_check_modules(PC_LIBGCRYPT QUIET "libgcrypt")

find_path(LIBGCRYPT_INCLUDE_DIR NAMES "gcrypt.h"
  HINTS
    ${PC_LIBGCRYPT_INCLUDEDIR}
    ${PC_LIBGCRYPT_INCLUDE_DIRS}
)

find_library(LIBGCRYPT_LIBRARY NAMES "gcrypt" "libgcrypt"
  HINTS
    ${PC_LIBGCRYPT_LIBDIR}
    ${PC_LIBGCRYPT_LIBRARY_DIRS}
)

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
