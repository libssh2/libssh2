# Copyright (C) Viktor Szakats
# SPDX-License-Identifier: BSD-3-Clause

# Get man_MANS variable
libssh2_transform_makefile_inc("Makefile.inc" "${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")
include("${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")

# Generate man pages
function(libssh2_add_manual_pages _listname)
  # Maximum number of files per command to stay within shell/OS limits
  if(CMAKE_HOST_UNIX)
    set(_files_per_batch 10000)
  else()  # e.g. Windows with cmd.exe and other obsolete/unidentified shells
    set(_files_per_batch 200)
  endif()
  set(_file_count 0)
  set(_rofffiles "")
  set(_mdfiles "")
  set(_eol "_EOL_")
  foreach(_file IN LISTS ${_listname} _eol)
    math(EXPR _file_count "${_file_count} + 1")
    if(_file_count GREATER_EQUAL _files_per_batch OR _file STREQUAL "_EOL_")
      add_custom_command(OUTPUT ${_rofffiles}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND "${PERL_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/cd2nroff" -k -d "${CMAKE_CURRENT_BINARY_DIR}" ${_mdfiles}
        DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/cd2nroff" ${_mdfiles}
        VERBATIM
      )
      set(_file_count 0)
      set(_rofffiles "")
      set(_mdfiles "")
    endif()

    list(APPEND _rofffiles "${CMAKE_CURRENT_BINARY_DIR}/${_file}")
    string(REPLACE ".3" ".md" _mdfile "${_file}")
    list(APPEND _mdfiles "${_mdfile}")
  endforeach()
  unset(_rofffiles)
  unset(_mdfiles)
endfunction()

libssh2_add_manual_pages(man_MANS)
add_custom_target(libssh2-man ALL DEPENDS ${man_MANS})
if(NOT LIBSSH2_DISABLE_INSTALL)
  set(_src "")
  foreach(_file IN LISTS man_MANS)
    list(APPEND _src "${CMAKE_CURRENT_BINARY_DIR}/${_file}")
  endforeach()
  include(GNUInstallDirs)
  install(FILES ${_src} DESTINATION "${CMAKE_INSTALL_MANDIR}/man3")
  unset(_src)
endif()
