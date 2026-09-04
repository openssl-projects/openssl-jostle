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

# MT-37: name the FIPS module in the record. Both 3.1.2 and 3.5.8 are supported
# and the gate runs once per module, so a green must say which module it is.
# Read from the binary, not the path, so a wrongly-named directory cannot lie.
if [ -n "${TEST_FIPS_LIB:-}" ]; then
  echo "FIPS module: ${TEST_FIPS_LIB}"
  echo "FIPS module version (from the binary): $(strings -a "$TEST_FIPS_LIB" 2>/dev/null \
    | grep -oE '^3\.[0-9]+\.[0-9]+$' | sort -u | tr '\n' ' ')"
else
  echo "FIPS module: UNSET - FIPS classes will assumption-skip"
fi


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

# Task names may be given as arguments; the five-task matrix is the default.
# The OPS pass uses this to run only integrationTest25JNI/FFI, where every
# *OpsTest lives - repeating the 27-minute base `test` task would add nothing.
# JOSTLE_REQUIRE_OPS=1 additionally demands the OpsTest classes actually ran.
TASKS=("$@")
if [ "${#TASKS[@]}" -eq 0 ]; then
  TASKS=(test unitTest25JNI unitTest25FFI integrationTest25JNI integrationTest25FFI)
fi

REQUIRE_OPS=""
[ -n "${JOSTLE_REQUIRE_OPS:-}" ] && REQUIRE_OPS="--require-ops"

for t in "${TASKS[@]}"; do
  echo "=== :jostle:$t --rerun ==="
  ./gradlew ":jostle:$t" --rerun
done

python3 "$SCRIPT_DIR/verify-results.py" $REQUIRE_FIPS $REQUIRE_OPS "${TASKS[@]}"
