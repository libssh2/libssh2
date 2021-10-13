#!/bin/bash

set -ex

PROJECT_NAME=libssh2

# Clone the oss-fuzz repository
git clone https://github.com/google/oss-fuzz.git /tmp/ossfuzz

if [[ ! -d /tmp/ossfuzz/projects/${PROJECT_NAME} ]]
then
    echo "Could not find the ${PROJECT_NAME} project in ossfuzz"

    # Exit with a success code while the libssh2 project is not expected to exist
    # on oss-fuzz.
    exit 0
fi

# Modify the oss-fuzz Dockerfile so that we're checking out the current branch in the CI system.
sed -i \
    -e "s@--depth 1@--no-checkout@" \
    -e "s@/src/libssh2@/src/libssh2 ; git -C /src/libssh2 fetch origin $GIT_REF:ci; git -C /src/libssh2 checkout ci@" \
    /tmp/ossfuzz/projects/${PROJECT_NAME}/Dockerfile

# Try and build the fuzzers
pushd /tmp/ossfuzz
python infra/helper.py build_image --pull ${PROJECT_NAME}
python infra/helper.py build_fuzzers ${PROJECT_NAME}
popd
