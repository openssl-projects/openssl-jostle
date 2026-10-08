#!/usr/bin/env bash
#
# Fails unless every native library under the given directory is a plain (non-OPS) build.
# Usage: assert-shipped-plain.sh <native resources directory>
#
# The directory is walked, not listed by name, so a renamed or added library is still checked.
# Each directory holding libraries must hold at least four interface libraries: one missing from
# the artifact is unknown, and unknown fails.
#
# The probes exist only under JOSTLE_OPS. set_ops_test is the shared util symbol; a Windows JNI
# DLL exports only its JNIEXPORT entries, so the JNI flag entry and the FFM flag entry are probed
# too (both survive the FIPS renames as substrings). A byte search needs no toolchain.
#
set -eu

root="${1:?usage: $0 <native resources directory>}"
probe='set_ops_test|setOpsTestFlag|JoOps_setFlag'

if [ ! -d "$root" ]; then
    echo "no native resources directory at $root" >&2
    exit 1
fi

libs=$(find "$root" -type f \( -name '*.so' -o -name '*.so.*' -o -name '*.dylib' -o -name '*.dll' \) | sort)
if [ -z "$libs" ]; then
    echo "no native library under $root" >&2
    find "$root" >&2 || true
    exit 1
fi

failed=0
for dir in $(printf '%s\n' "$libs" | xargs -n1 dirname | sort -u); do
    n=$(printf '%s\n' "$libs" | grep -c "^$dir/[^/]*interface[^/]*$" || true)
    if [ "$n" -lt 4 ]; then
        echo "$dir holds $n interface libraries, expected at least 4" >&2
        failed=1
    fi
done

checked=0
while IFS= read -r lib; do
    checked=$((checked + 1))
    if grep -qaE "$probe" "$lib"; then
        echo "$lib IS ops-instrumented" >&2
        failed=1
    else
        echo "plain: $lib"
    fi
done <<EOF
$libs
EOF

echo "checked $checked libraries under $root"
exit "$failed"
