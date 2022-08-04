project('libssh2', 'c',
  version : '1.10.1-dev',
  license : 'BSD-3',
  meson_version : '>=0.58.0')

cc = meson.get_compiler('c')
pkgconfig = import('pkgconfig')

libssh2_sources = [
    'src/misc.c',
    'src/scp.c',
    'src/crypt.c',
    'src/hostkey.c',
    'src/version.c',
    'src/wincng.c',
    'src/blowfish.c',
    'src/mac.c',
    'src/os400qc3.c',
    'src/transport.c',
    'src/agent.c',
    'src/pem.c',
    'src/kex.c',
    'src/sftp.c',
    'src/knownhost.c',
    'src/publickey.c',
    'src/channel.c',
    'src/global.c',
    'src/packet.c',
    'src/bcrypt_pbkdf.c',
    'src/userauth.c',
    'src/keepalive.c',
    'src/comp.c',
    'src/session.c',
    'src/userauth_kbd_packet.c'
]

libssh2_deps = []
extra_flags = []

if get_option('crypto_backend') == 'openssl'
    libssh2_sources += ['src/openssl.c']
    libssh2_deps += dependency('openssl', version : '>= 1.0.0')
    extra_flags += ['-DLIBSSH2_OPENSSL']
elif get_option('crypto_backend') == 'mbedtls'
    libssh2_sources += ['src/mbedtls.c']

    mbedtls_dep = dependency('mbedtls', required: false)
    if mbedtls_dep.found()
        libssh2_deps += mbedtls_dep
    else
        libmbedtls = cc.find_library('mbedtls', has_headers: ['mbedtls/version.h'])
        libmbedx509 = cc.find_library('mbedx509')
        libmbedcrypto = cc.find_library('mbedcrypto')
        libssh2_deps += [libmbedtls, libmbedx509, libmbedcrypto]
    endif

    extra_flags += ['-DLIBSSH2_MBEDTLS']
elif get_option('crypto_backend') == 'gcrypt'
    libssh2_sources += ['src/libgcrypt.c']
    libssh2_deps += dependency('gcrypt')
    extra_flags += ['-DLIBSSH2_GCRYPT']
else
    error('No crypto backend specified')
endif

libssh2_config = configuration_data()

check_headers = [
    'unistd.h',
    'inttypes.h',
    'stdlib.h',
    'sys/select.h',
    'sys/uio.h',
    'sys/socket.h',
    'netinet/in.h',
    'arpa/inet.h',
    'sys/ioctl.h',
    'sys/time.h',
    'sys/un.h',
    'windows.h',
    'ws2tcpip.h',
    'winsock2.h',
    'ntdef.h',
    'ntstatus.h'
]

foreach h : check_headers
    libssh2_config.set('HAVE_@0@'.format(h.underscorify().to_upper()), cc.has_header(h))
endforeach

if cc.has_header('fcntl.h')
    libssh2_config.set('HAVE_O_NONBLOCK', cc.has_header_symbol('fcntl.h', 'O_NONBLOCK'))
endif

if libssh2_config.get('HAVE_SYS_IOCTL_H')
    libssh2_config.set('HAVE_FIONBIO', cc.has_header_symbol('sys/ioctl.h', 'FIONBIO'))
endif

check_funcs = [
    'EVP_aes_128_ctr',
    'gettimeofday',
    'poll',
    'select',
    'socket',
    'strtoll',
    'strtoi64',
    'snprintf'
]

foreach f : check_funcs
    libssh2_config.set('HAVE_@0@'.format(f.underscorify().to_upper()), cc.has_function(f))
endforeach

libssh2_config.set('HAVE_LONGLONG', 1)
libssh2_config.set('LIBSSH2DEBUG', get_option('buildtype') == 'debug')

libssh2_config_h = configure_file(
    input: 'src/libssh2_config_cmake.h.in',
    output: 'libssh2_config.h',
    configuration: libssh2_config,
    format: 'cmake',
    install: true,
    install_dir: 'include/'
)
libssh2_sources += [libssh2_config_h]

inc_dir = include_directories(['include', '.'])
abi_version = host_machine.system() == 'windows' ? '' : '1.0.1'
libssh2_lib = library('ssh2',
    libssh2_sources,
    include_directories: inc_dir,
    dependencies: libssh2_deps,
    c_args: extra_flags,
    install: true,
    version: abi_version
)
libssh2_dep = declare_dependency(
    include_directories: inc_dir,
    link_with: libssh2_lib
)

install_headers(
    'include/libssh2.h',
    'include/libssh2_publickey.h',
    'include/libssh2_sftp.h'
)

pkgconfig.generate(libssh2_lib,
    name: 'libssh2',
    description: 'Library for SSH-based communication'
)

if get_option('examples')
  subdir('example')
endif
