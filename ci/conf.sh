
set -ex

SOURCE_DIR=${SOURCE_DIR:-$( cd "$( dirname "${BASH_SOURCE[0]}" )" && dirname $( pwd ) )}
BUILD_DIR=$SOURCE_DIR/build

mkdir -p $BUILD_DIR/deps

BUILD_ROOT=$(realpath "$BUILD_DIR/deps")
echo "Dependencies will be installed to $BUILD_ROOT"

# Setup some defaults
if [ "x$ADDRESS_SIZE" = 'x' ]; then
    ADDRESS_SIZE='64'
fi
if [ "x$LEAK_CHECK" = 'x' ]; then
    LEAK_CHECK='none'
fi

# Default version used. Override with BACKEND_VERSION.
MBEDTLS_VERSION=2.4.0
OPENSSL_VERSION=1.1.1b

if [ x$CRYPTO_BACKEND = 'xOpenSSL' ]; then
    if [ x$BACKEND_VERSION = 'x' ]; then
        BACKEND_VERSION=$OPENSSL_VERSION
    fi

    BACKEND_ARCHIVE=openssl-$BACKEND_VERSION
elif [ x$CRYPTO_BACKEND = 'xmbedTLS' ]; then
    if [ x$BACKEND_VERSION = 'x' ]; then
        BACKEND_VERSION=$MBEDTLS_VERSION
    fi

    BACKEND_ARCHIVE=mbedtls-$BACKEND_VERSION
fi

if [ x$ADDRESS_SIZE = 'x32' ]; then
    export CMAKE_FLAGS="-DCMAKE_TOOLCHAIN_FILE=../cmake/Toolchain-Linux-32.cmake"
fi

export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:$BUILD_ROOT/lib"
if [ x$CRYPTO_BACKEND = 'xOpenSSL' ]; then
    export CMAKE_FLAGS="$CMAKE_FLAGS -DOPENSSL_ROOT_DIR=$BUILD_ROOT/include -DOPENSSL_CRYPTO_LIBRARY=$BUILD_ROOT/lib/libcrypto.so -DOPENSSL_SSL_LIBRARY=$BUILD_ROOT/lib/libssl.so"
elif [ x$CRYPTO_BACKEND = 'xmbedTLS' ]; then
    export CMAKE_FLAGS="$CMAKE_FLAGS -DCMAKE_PREFIX_PATH=$BUILD_ROOT"
fi
