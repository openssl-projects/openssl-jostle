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
. "$SCRIPT_DIR/tasks-lib.sh"

for v in JAVA_HOME OPENSSL_PREFIX; do
  if [ -z "${!v:-}" ]; then
    echo "$v must be set (this script rebuilds native code)" >&2
    exit 2
  fi
done

# build.gradle drops unitTest<NN>/integrationTest<NN> from `test` when
# BC_JDK<NN> is unset, silently, so the gate refuses to start rather than cover
# less than it appears to. JOSTLE_ALLOW_PARTIAL_JDKS=1 proceeds and prints the
# legs it gives up.
# Set-but-broken is rejected too: a var pointing at a moved JDK passes a
# non-empty test and then fails obscurely inside gradle's toolchain resolution.
MISSING_JDKS=()
for v in $(jostle_env_vars); do
  if [ -z "${!v:-}" ]; then
    MISSING_JDKS+=("$v")
  elif ! jostle_jdk_home "${!v}" > /dev/null; then
    echo "REFUSING TO START: $v is set to '${!v}' but no bin/java is there" >&2
    echo "  (neither <root>/bin/java nor <root>/Contents/Home/bin/java)" >&2
    exit 2
  fi
done
if [ "${#MISSING_JDKS[@]}" -ne 0 ]; then
  if [ -z "${JOSTLE_ALLOW_PARTIAL_JDKS:-}" ]; then
    echo "REFUSING TO START: ${#MISSING_JDKS[@]} JDK toolchain var(s) unset:" >&2
    for v in "${MISSING_JDKS[@]}"; do
      echo "  $v  -> drops $(jostle_tasks verify | while read -r t; do
              [ "$(jostle_task_env "$t")" = "$v" ] && printf '%s ' "$t"; done)" >&2
    done
    echo "Set them, or run with JOSTLE_ALLOW_PARTIAL_JDKS=1 to proceed knowingly." >&2
    exit 2
  fi
  echo "!! PARTIAL RUN (JOSTLE_ALLOW_PARTIAL_JDKS set). Dropping legs for:"
  for v in "${MISSING_JDKS[@]}"; do
    echo "     $v  -> $(jostle_tasks verify | while read -r t; do
            [ "$(jostle_task_env "$t")" = "$v" ] && printf '%s ' "$t"; done)"
  done
fi


export BC_JDK25="${BC_JDK25:-$JAVA_HOME}"
export PATH="$JAVA_HOME/bin:$PATH"

# Whatever happens, leave a plain build installed. An instrumented library left
# behind is a shipping hazard: it exports the operations-test entry points.

# Two gate instances share build/test-results and src/main/resources/native, so
# only one may run. mkdir is the atomic primitive on both platforms; flock is
# absent on macOS. Fixed /tmp, NOT $TMPDIR: macOS gives each login session its
# own TMPDIR, so two sessions would not share the lock at all.
LOCK_DIR="/tmp/jostle-gate.lock"
# Set only once the lock is ours. The EXIT trap is installed BEFORE the lock is
# taken, so without this an instance that was refused would run restore_plain -
# a full interface/build.sh - and `make clean` the holder's build out from
# under it. A cleanup trap installed before its resource is acquired must be
# conditional on acquisition.
LOCK_HELD=0

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

release_lock () {
  if [ -f "$LOCK_DIR/pid" ] && [ "$(cat "$LOCK_DIR/pid" 2>/dev/null)" = "$$" ]; then
    rm -rf "$LOCK_DIR"
  fi
}

on_exit () {
  if [ "$LOCK_HELD" -eq 1 ]; then
    restore_plain
  fi
  release_lock
}
trap on_exit EXIT INT TERM

acquire_lock () {
  if mkdir "$LOCK_DIR" 2>/dev/null; then
    echo "$$" > "$LOCK_DIR/pid"
    LOCK_HELD=1
    return 0
  fi
  local holder
  holder=$(cat "$LOCK_DIR/pid" 2>/dev/null || echo "")
  # kill -0 cannot tell a live holder from a recycled pid; accepted.
  if [ -n "$holder" ] && kill -0 "$holder" 2>/dev/null; then
    echo "REFUSING TO START: another gate run holds $LOCK_DIR (pid $holder)." >&2
    echo "Wait for it, or stop it and confirm the process is gone." >&2
    return 1
  fi
  echo "!! stale lock at $LOCK_DIR (pid '${holder:-none}' not alive) - taking it"
  echo "$$" > "$LOCK_DIR/pid"
  LOCK_HELD=1
  return 0
}
acquire_lock || exit 2

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

# A red pass 1 means the tree is not green, so pass 2 is never attempted: it
# rebuilds the native libraries, which is destructive when another run is live.
# The cause of the failure does not matter - none warrants pass 2.
if [ "$P1" -ne 0 ] && [ -z "${JOSTLE_CONTINUE_AFTER_PASS1:-}" ]; then
  echo
  echo "################ ABORTING: pass 1 failed (rc=$P1) ################"
  echo "Pass 2 not attempted. Set JOSTLE_CONTINUE_AFTER_PASS1=1 to override."
  exit "$P1"
fi

echo
echo "################ pass 2: JOSTLE_OPS_TEST=1 (fault injection) ################"
JOSTLE_OPS_TEST=1 ./interface/build.sh > /tmp/jostle-pass2-build.log 2>&1 || {
  echo "OPS native build failed; see /tmp/jostle-pass2-build.log" >&2; exit 1; }
# --require-ops turns "the OpsTest classes skipped" into a hard failure here:
# on this pass they have no excuse.
JOSTLE_REQUIRE_OPS=1 bash "$SCRIPT_DIR/run-matrix.sh" $(jostle_tasks ops)
P2=$?

echo
echo "################ two-pass summary ################"
[ "$P1" -eq 0 ] && echo "  PASS  pass 1 (shipped build, full matrix)" \
                || echo "  FAIL  pass 1 (shipped build, full matrix) rc=$P1"
[ "$P2" -eq 0 ] && echo "  PASS  pass 2 (OPS build, integration tasks)" \
                || echo "  FAIL  pass 2 (OPS build, integration tasks) rc=$P2"
echo "TWO-PASS DONE"
[ "$P1" -eq 0 ] && [ "$P2" -eq 0 ]
