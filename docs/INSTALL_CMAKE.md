License: see COPYING

Source code: https://github.com/libssh2/libssh2

Web site source code: https://github.com/libssh2/www

Installation instructions are in docs/INSTALL
=======
To build libssh2 you will need CMake v3.1 or later [1] and one of the
following cryptography libraries:

* OpenSSL
* wolfSSL
* Libgcrypt
* WinCNG
* mbedTLS

Getting started
---------------

If you are happy with the default options, make a new build directory,
change to it, configure the build environment and build the project:

```
  mkdir bin
  cd bin
  cmake ..
  cmake --build .
```

libssh2 will be built as a static library and will use any
cryptography library available.  The library binary will be put in
`bin/src`, with the examples in `bin/example` and the tests in
`bin/tests`.

Customising the build
---------------------

You might want to customise the build options.  You can pass the options
to CMake on the command line:

  cmake -D<option>=<value> ..

The following options are available:

 * `LINT=ON`

    Enables running the source code linter when building. Can be `ON` or `OFF`.

 * `BUILD_STATIC_LIBS=ON`

    Determines whether to build a libssh2 static library.
    Can be `ON` or `OFF`.

 * `BUILD_SHARED_LIBS=OFF`

    Determines whether to build a libssh2 shared library (.dll/.so).
    Can be `ON` or `OFF`.

    If enabled, the optional static lib is also built with PIC enabled.

 * `CRYPTO_BACKEND=`

    Chooses a specific cryptography library to use for cryptographic
    operations.  Can be `OpenSSL` (https://www.openssl.org),
    `Libgcrypt` (https://www.gnupg.org/), `WinCNG` (Windows Vista+),
    `mbedTLS` (https://tls.mbed.org/) or blank to use any library available.

    CMake will attempt to locate the libraries automatically.  See [2]
    for more information.

 * `ENABLE_ZLIB_COMPRESSION=OFF`

    Will use zlib (https://zlib.net/) for payload compression.  Can
    be `ON` or `OFF`.

 * `ENABLE_DEBUG_LOGGING=ON` in Debug, `=OFF` in Release

    Will enable the libssh2_trace() function for showing debug traces.

 * `CLEAR_MEMORY=ON`

    Securely zero memory before freeing it (if the backend supports this).

Build tools
-----------

The previous examples used CMake to start the build using:

  cmake --build .

Alternatively, once CMake has configured your project, you can use
your own build tool, e.g GNU make, Visual Studio, etc., from that
point onwards.

Tests
-----

To test the build, run the appropriate test target for your build
system.  For example:

```
  cmake --build . --target test
```
or
```
  cmake --build . --target RUN_TESTS
```

How do I use libssh2 in my project if my project does not use CMake?
-------------------------------------------------------------------

If you are not using CMake for your own project, install libssh2
```
  cmake <libssh2 source location>
  cmake --build .
  cmake --build . --target install
```
or
```
  cmake --build . --target INSTALL
```

and then specify the install location to your project in the normal
way for your build environment.  If you do not like the default install
location, add `-DCMAKE_INSTALL_PREFIX=<chosen prefix>` when initially
configuring the project.

How can I use libssh2 in my project if it also uses CMake?
----------------------------------------------------------

If your own project also uses CMake, you do not need to worry about
setting it up with libssh2's location. Add the following lines and
CMake will find libssh2 on your system, set up the necessary paths and
link the library with your binary.

    find_package(Libssh2 REQUIRED CONFIG)
    target_link_libraries(my_project_target Libssh2::libssh2)

You still have to make libssh2 available on your system first.  You can
install it in the traditional way shown above, but you do not have to.
Instead you can build it, which will export its location to the user
package registry [3] where `find_package` will find it.

You can even combine the two steps using a so-called 'superbuild'
project [4] that downloads, builds and exports libssh2, and then
builds your project:

    include(ExternalProject)

    ExternalProject_Add(
        Libssh2
        URL <libssh2 download location>
        URL_HASH SHA1=<libssh2 archive SHA1>
        INSTALL_COMMAND "")

    ExternalProject_Add(
        MyProject DEPENDS Libssh2
        SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src
        INSTALL_COMMAND "")

[1] https://www.cmake.org/cmake/resources/software.html
[2] https://www.cmake.org/cmake/help/v3.0/manual/cmake-packages.7.html
[3] https://www.cmake.org/cmake/help/v3.0/manual/cmake-packages.7.html#package-registry
[4] https://blog.kitware.com/wp-content/uploads/2016/01/kitware_quarterly1009.pdf
