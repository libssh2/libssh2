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

# - Try to find Libgcrypt
# This will define all or none of:
#  LIBGCRYPT_FOUND        - If Libgcrypt headers and library were found
#  LIBGCRYPT_INCLUDE_DIRS - The Libgcrypt include directories
#  LIBGCRYPT_LIBRARIES    - The libraries needed to use Libgcrypt

find_package(PkgConfig QUIET)
pkg_check_modules(LIBGCRYPT "libgcrypt")

if(LIBGCRYPT_FOUND)
  # Use LIBGCRYPT_INCLUDE_DIRS as-is instead of forwarding it as a hint
  # to find_path(). The list includes the header path of a Libgcrypt
  # dependency, with its headers referenced by Libgcrypt's public headers.
  # We must keep this header path there for a successful build.
  set(LIBGCRYPT_LIBRARIES ${LIBGCRYPT_LINK_LIBRARIES})
else()
  find_path(LIBGCRYPT_INCLUDE_DIR NAMES "gcrypt.h")
  find_library(LIBGCRYPT_LIBRARY NAMES "gcrypt" "libgcrypt")

  include(FindPackageHandleStandardArgs)
  find_package_handle_standard_args("Libgcrypt"
    DEFAULT_MSG
    REQUIRED_VARS
      LIBGCRYPT_INCLUDE_DIR
      LIBGCRYPT_LIBRARY)

  mark_as_advanced(LIBGCRYPT_INCLUDE_DIR LIBGCRYPT_LIBRARY)

  if(LIBGCRYPT_FOUND)
    set(LIBGCRYPT_INCLUDE_DIRS ${LIBGCRYPT_INCLUDE_DIR})
    set(LIBGCRYPT_LIBRARIES    ${LIBGCRYPT_LIBRARY})
  endif()
endif()
