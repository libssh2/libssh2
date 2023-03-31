# Copyright (c) 2014, 2015 Alexander Lamaison <alexander.lamaison@gmail.com>
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

include(CopyRuntimeDependencies)

list(APPEND LIBRARIES ${SOCKET_LIBRARIES})

add_definitions(-DHAVE_CONFIG_H)

set(EXAMPLES
  direct_tcpip
  scp
  scp_nonblock
  scp_write
  scp_write_nonblock
  sftp
  sftp_RW_nonblock
  sftp_append
  sftp_mkdir
  sftp_mkdir_nonblock
  sftp_nonblock
  sftp_write
  sftp_write_nonblock
  sftp_write_sliding
  sftpdir
  sftpdir_nonblock
  ssh2
  ssh2_agent
  ssh2_agent_forwarding
  ssh2_echo
  ssh2_exec
  subsystem_netconf
  tcpip-forward)

foreach(example ${EXAMPLES})
  add_executable(example-${example} ${example}.c)
  list(APPEND EXAMPLE_TARGETS example-${example})
  # to find generated header
  target_include_directories(example-${example} PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/../src)
  target_link_libraries(example-${example} ${LIB_STATIC} ${LIBRARIES})
endforeach()

add_target_to_copy_dependencies(
  TARGET copy_example_dependencies
  DEPENDENCIES ${RUNTIME_DEPENDENCIES}
  BEFORE_TARGETS ${EXAMPLE_TARGETS})
