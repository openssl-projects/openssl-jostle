#!/usr/bin/env bash
#
# Run Jostle's full test matrix with forced execution, then verify the result
# XML (green + no masked FIPS skips). Gradle treats env vars as invisible to
# up-to-date checks, so --rerun is mandatory when TEST_FIPS_LIB changed since
# the last run — a cached replay reports BUILD SUCCESSFUL in milliseconds with
# every FIPS class wholesale-skipped.
#
# Required env:
#   JAVA_HOME      Java 25 JDK (BC_JDK25 defaults to it)
# Recommended env:
#   TEST_FIPS_LIB  full path to the FIPS module library (fips.dylib / .so);
#                  unset => FIPS-gated classes skip and verification only
#                  enforces green, loudly noting the gap.
set -eu
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
cd "$SCRIPT_DIR/../../../.."   # repo root

if [ -z "${JAVA_HOME:-}" ]; then
  echo "JAVA_HOME must point at a Java 25 JDK" >&2
  exit 2
fi
export BC_JDK25="${BC_JDK25:-$JAVA_HOME}"

REQUIRE_FIPS=""
if [ -n "${TEST_FIPS_LIB:-}" ]; then
  if [ ! -f "$TEST_FIPS_LIB" ]; then
    echo "TEST_FIPS_LIB is set but does not exist: $TEST_FIPS_LIB" >&2
    exit 2
  fi
  REQUIRE_FIPS="--require-fips"
else
  echo "WARNING: TEST_FIPS_LIB unset — FIPS-gated classes will skip." >&2
fi

TASKS=(test unitTest25JNI unitTest25FFI integrationTest25JNI integrationTest25FFI)
for t in "${TASKS[@]}"; do
  echo "=== :jostle:$t --rerun ==="
  ./gradlew ":jostle:$t" --rerun
done

python3 "$SCRIPT_DIR/verify-results.py" $REQUIRE_FIPS "${TASKS[@]}"
