#!/usr/bin/env bash
#
# The two-pass OPS discipline, automated.
#
# A single test run cannot cover both things that need covering, because the
# two need DIFFERENT native builds:
#
#   pass 1  plain build          the library that actually ships. Every
#                                *OpsTest assumption-skips (the OPS_* macros
#                                expand to nothing), and the suite still says
#                                green - which is why a one-pass run silently
#                                under-covers.
#   pass 2  JOSTLE_OPS_TEST=1    the fault-injection paths: ~40 *OpsTest
#                                classes, 16 of them FIPS. Only the
#                                integration tasks carry them, so pass 2 skips
#                                the 27-minute base `test` task.
#
# build_osx.sh / build_linux.sh already do two native passes for exactly this
# reason; this script is the test-side counterpart, and it ALWAYS leaves a
# plain (shippable) build installed, including on Ctrl-C.
#
# Required env:
#   JAVA_HOME        Java 25 JDK (BC_JDK25 defaults to it)
#   OPENSSL_PREFIX   an OpenSSL install - this script rebuilds native code
# Recommended env:
#   TEST_FIPS_LIB    the FIPS module; unset => FIPS classes skip and pass 1
#                    only enforces green
#
# For a single configuration. To cover every FIPS module configuration too,
# run sweep-fips-configs.sh (pass 1 equivalent) and then this script's pass 2
# per config - see the skill.
set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
cd "$SCRIPT_DIR/../../../.." || exit 3

for v in JAVA_HOME OPENSSL_PREFIX; do
  if [ -z "${!v:-}" ]; then
    echo "$v must be set (this script rebuilds native code)" >&2
    exit 2
  fi
done
export BC_JDK25="${BC_JDK25:-$JAVA_HOME}"
export PATH="$JAVA_HOME/bin:$PATH"

# Whatever happens, leave a plain build installed. An instrumented library left
# behind is a shipping hazard: it exports the operations-test entry points.
restore_plain () {
  echo
  echo "=== restoring plain (shippable) native build ==="
  if ! ./interface/build.sh > /tmp/jostle-restore-build.log 2>&1; then
    echo "!! PLAIN REBUILD FAILED - the installed library may still be" >&2
    echo "!! instrumented. See /tmp/jostle-restore-build.log" >&2
    return 1
  fi
  python3 "$SCRIPT_DIR/verify-results.py" --require-fips 2>/dev/null |
    grep -E "^OPS build state" || true
}
trap restore_plain EXIT INT TERM

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

echo "################ pass 1: plain build (shipped library) ################"
./interface/build.sh > /tmp/jostle-pass1-build.log 2>&1 || {
  echo "plain native build failed; see /tmp/jostle-pass1-build.log" >&2; exit 1; }
bash "$SCRIPT_DIR/run-matrix.sh"
P1=$?

echo
echo "################ pass 2: JOSTLE_OPS_TEST=1 (fault injection) ################"
JOSTLE_OPS_TEST=1 ./interface/build.sh > /tmp/jostle-pass2-build.log 2>&1 || {
  echo "OPS native build failed; see /tmp/jostle-pass2-build.log" >&2; exit 1; }
# --require-ops turns "the OpsTest classes skipped" into a hard failure here:
# on this pass they have no excuse.
JOSTLE_REQUIRE_OPS=1 bash "$SCRIPT_DIR/run-matrix.sh" \
    integrationTest25JNI integrationTest25FFI
P2=$?

echo
echo "################ two-pass summary ################"
[ "$P1" -eq 0 ] && echo "  PASS  pass 1 (shipped build, full matrix)" \
                || echo "  FAIL  pass 1 (shipped build, full matrix) rc=$P1"
[ "$P2" -eq 0 ] && echo "  PASS  pass 2 (OPS build, integration tasks)" \
                || echo "  FAIL  pass 2 (OPS build, integration tasks) rc=$P2"
echo "TWO-PASS DONE"
[ "$P1" -eq 0 ] && [ "$P2" -eq 0 ]
