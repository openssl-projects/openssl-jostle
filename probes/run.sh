#!/bin/bash
# Build the probes against one OpenSSL install and run them on mainline and on each FIPS module given.
#
# Usage: run.sh <openssl_prefix> <bin_dir> <out_dir> [<label> <module_dir> <fipsmodule.cnf>]...
#
# Each probe is linked against <openssl_prefix>/lib with an rpath there, so it runs on that install's libcrypto.
# Output: <out_dir>/<probe>.mainline.txt and <out_dir>/<probe>.<label>.txt, one file per probe per configuration,
# plus <out_dir>/versions.txt naming the libcrypto. The probe files carry no version, so the same configuration
# on two installs compares with cmp.
set -eu

if [ "$#" -lt 3 ] || [ $(( ($# - 3) % 3 )) -ne 0 ]; then
    echo "usage: $0 <openssl_prefix> <bin_dir> <out_dir> [<label> <module_dir> <fipsmodule.cnf>]..." >&2
    exit 2
fi
prefix=$1
bin=$2
out=$3
shift 3
src=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$bin" "$out"

for p in dhx_probe rsakem_probe; do
    cc -std=c99 -Wall -Werror -I"$prefix/include" -o "$bin/$p" "$src/$p.c" \
        -L"$prefix/lib" -Wl,-rpath,"$prefix/lib" -lcrypto
done
"$prefix/bin/openssl" version > "$out/versions.txt"

for p in dhx_probe rsakem_probe; do
    "$bin/$p" mainline > "$out/$p.mainline.txt"
done
while [ "$#" -gt 0 ]; do
    label=$1
    for p in dhx_probe rsakem_probe; do
        "$bin/$p" fips "$2" "$3" > "$out/$p.$label.txt"
    done
    echo "$label: $("$prefix/bin/openssl" version -v)" >> "$out/versions.txt"
    shift 3
done
