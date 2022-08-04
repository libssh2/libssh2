examples_c = [
    'direct_tcpip.c',
    'scp.c',
    'scp_nonblock.c',
    'scp_write.c',
    'scp_write_nonblock.c',
    'sftp.c',
    'sftp_RW_nonblock.c',
    'sftp_append.c',
    'sftp_mkdir.c',
    'sftp_mkdir_nonblock.c',
    'sftp_nonblock.c',
    'sftp_write.c',
    'sftp_write_nonblock.c',
    'sftp_write_sliding.c',
    'sftpdir.c',
    'sftpdir_nonblock.c',
    'ssh2.c',
    'ssh2_agent.c',
    'ssh2_echo.c',
    'ssh2_exec.c',
    'subsystem_netconf.c',
    'tcpip-forward.c'
]

example_libssh2_config = configuration_data()

check_example_headers = [
    'unistd.h',
    'inttypes.h',
    'stdlib.h',
    'sys/select.h',
    'sys/socket.h',
    'netinet/in.h',
    'arpa/inet.h',
    'sys/time.h',
    'winsock2.h',
]

foreach h : check_example_headers
    example_libssh2_config.set('HAVE_@0@'.format(h.underscorify().to_upper()), cc.has_header(h))
endforeach

foreach f : ['strcasecmp', '_stricmp', 'snprintf', '_snprintf']
    example_libssh2_config.set('HAVE_@0@'.format(f.underscorify().to_upper()), cc.has_function(f))
endforeach

example_libssh2_config_h = configure_file(
    input: 'libssh2_config_cmake.h.in',
    output: 'libssh2_config.h',
    configuration: example_libssh2_config,
    format: 'cmake',
)

x11_dep = dependency('x11', required: false)
if x11_dep.found()
    examples_c += 'x11.c'
endif

foreach example : examples_c
    executable(
        example.replace('.c', ''),
        [ example, example_libssh2_config_h ],
        include_directories: include_directories('.'),
        dependencies: libssh2_dep
    )
endforeach
