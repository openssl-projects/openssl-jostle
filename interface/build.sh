#!/bin/bash

set -e
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

if [ -z "$JAVA_HOME" ]; then
  echo "JAVA_HOME is unset, as a minimum it should point to a Java 25 JDK installation"
  exit 1
fi

if [ -z "$OPENSSL_PREFIX" ]; then
  echo "OPENSSL_PREFIX not set see README 'Build OpenSSL'"
  exit 1
fi


(
  cd "${SCRIPT_DIR}"

  rm -f  CMakeCache.txt
  cmake .
  make clean
  make
  make install
)

