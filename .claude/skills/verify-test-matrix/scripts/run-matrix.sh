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

# Task names may be given as arguments; otherwise tasks.list decides.
# The OPS pass passes only integrationTest25JNI/FFI, where every *OpsTest
# lives - repeating the 27-minute base `test` task would add nothing.
# JOSTLE_REQUIRE_OPS=1 additionally demands the OpsTest classes actually ran.
#
# INVOKE and VERIFY differ when no arguments are given: `:jostle:test` already
# runs unitTest<NN>/integrationTest<NN> as dependencies, so those legs need no
# invocation but their XML must still be read. With explicit arguments the two
# lists are identical - naming tasks means those tasks and nothing else.
. "$SCRIPT_DIR/tasks-lib.sh"
TASKS=("$@")
if [ "${#TASKS[@]}" -eq 0 ]; then
  IFS=$'\n' read -r -d '' -a TASKS < <(jostle_tasks invoke && printf '\0')
  IFS=$'\n' read -r -d '' -a VERIFY_TASKS < <(jostle_tasks verify && printf '\0')
else
  VERIFY_TASKS=("${TASKS[@]}")
fi

REQUIRE_OPS=""
[ -n "${JOSTLE_REQUIRE_OPS:-}" ] && REQUIRE_OPS="--require-ops"

for t in "${TASKS[@]}"; do
  echo "=== :jostle:$t --rerun ==="
  ./gradlew ":jostle:$t" --rerun
done

# MT-64: keep this cycle's result XML somewhere the NEXT cycle cannot overwrite.
# build/test-results is reused by every run, so a three-cycle gate otherwise ends
# holding only cycle 3's evidence. Unset => nothing is copied and the output is
# byte-identical to before. Copied BEFORE verification, so a cycle that FAILS
# keeps the evidence you most want to read.
if [ -n "${JOSTLE_RESULT_SNAPSHOT_DIR:-}" ]; then
  # The two-pass gate runs the SAME task names twice - integrationTest25JNI/FFI
  # on the shipped library, then again on the instrumented one - so a flat
  # destination has pass 2 overwrite pass 1, and those are different evidence
  # (OpsTests skip on the shipped build, run on the instrumented one). Split by
  # the build state actually INSTALLED, probed the way verify-results.py probes
  # it, so no caller has to remember to vary the variable.
  BUILD_STATE=plain
  for _lib in jostle/src/main/resources/native/*/*/*interface_ffi*; do
    case "$_lib" in *.txt) continue;; esac
    [ -f "$_lib" ] || continue
    if grep -qa JoOps_setFlag "$_lib"; then BUILD_STATE=ops; fi
  done
  SNAP_DIR="$JOSTLE_RESULT_SNAPSHOT_DIR/$BUILD_STATE"
  echo "=== snapshotting result XML to $SNAP_DIR ==="
  # Provenance travels with the copy: XML alone cannot say which module made it.
  mkdir -p "$SNAP_DIR"
  {
    echo "date: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    echo "commit: $(git rev-parse HEAD 2>/dev/null || echo unknown)"
    echo "tasks: ${VERIFY_TASKS[*]}"
    # write_tree hashes the INDEX; a gate runs the WORKTREE. Those differed
    # while this line was being added, so it recorded a tree that was not
    # tested. worktree_dirty says whether they can differ, and when they do the
    # worktree's own tree is written through a temporary index.
    echo "write_tree: $(git write-tree 2>/dev/null || echo unknown)"
    if git diff --quiet 2>/dev/null; then
      echo "worktree_dirty: no"
    else
      echo "worktree_dirty: yes"
      _wt_index=$(mktemp)
      if GIT_INDEX_FILE="$_wt_index" git read-tree HEAD 2>/dev/null \
         && GIT_INDEX_FILE="$_wt_index" git add -A . 2>/dev/null; then
        echo "worktree_tree: $(GIT_INDEX_FILE="$_wt_index" git write-tree 2>/dev/null || echo unknown)"
      else
        echo "worktree_tree: unknown"
      fi
      rm -f "$_wt_index"
    fi
    echo "build_state: $BUILD_STATE"
    if [ -n "${TEST_FIPS_LIB:-}" ]; then
      echo "fips_module: ${TEST_FIPS_LIB}"
      echo "fips_module_version: $(strings -a "$TEST_FIPS_LIB" 2>/dev/null \
        | grep -oE '^3\.[0-9]+\.[0-9]+$' | sort -u | tr '\n' ' ')"
    else
      echo "fips_module: UNSET"
    fi
  } > "$SNAP_DIR/run-info.txt"
  for t in "${VERIFY_TASKS[@]}"; do
    src="jostle/build/test-results/$t"
    n=$(ls -1 "$src"/TEST-*.xml 2>/dev/null | wc -l | tr -d ' ')
    if [ "$n" -eq 0 ]; then
      echo "  $t: NO result files to snapshot" >&2
      continue
    fi
    mkdir -p "$SNAP_DIR/$t"
    cp "$src"/TEST-*.xml "$SNAP_DIR/$t/"
    echo "  $t: $n files"
  done
fi

python3 "$SCRIPT_DIR/verify-results.py" $REQUIRE_FIPS $REQUIRE_OPS "${VERIFY_TASKS[@]}"
