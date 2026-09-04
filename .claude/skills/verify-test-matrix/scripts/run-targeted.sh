#!/usr/bin/env bash
#
# TIER 1 — targeted iteration run. Runs ONLY the named test classes, on the
# named tasks, and then PROVES the restriction took.
#
# Why this exists rather than a bare `./gradlew ... --tests X`: passing several
# tasks and then a trailing --tests did NOT restrict them (measured
# 2026-08-31 — the run executed the whole suite while reporting as filtered).
# Gradle binds --tests to the task that PRECEDES it, so the filter has to be
# repeated per task. A filter that silently widens is the same class of
# instrument fault as a wrapper reporting exit 0 for a failed build, so this
# script does not trust the invocation: verify-targeted.py reads the result
# XML afterwards and fails if any unrequested class ran, or if any requested
# class ran zero tests.
#
# Result directories for the target tasks are DELETED first. Gradle leaves
# stale XML from previous runs in place, and a leg that did not execute this
# time otherwise serves last run's results as though they were fresh.
#
# Usage:
#   bash .../run-targeted.sh AESKeyWrapTest ChunkingContractTest
#   JOSTLE_TARGET_TASKS="unitTest25JNI" bash .../run-targeted.sh MDTest
#
# Required env:
#   JAVA_HOME      Java 25 JDK (BC_JDK25 defaults to it)
# Optional env:
#   JOSTLE_TARGET_TASKS  space-separated task list; defaults to the four
#                        Java-25 legs (both bridges, unit + integration).
#                        Narrow it only when the change is demonstrably not
#                        native or bridge-visible, and say so in the report.
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

if [ "$#" -eq 0 ]; then
  echo "usage: run-targeted.sh <TestClass> [TestClass...]" >&2
  exit 2
fi

CLASSES=("$@")
read -r -a TASKS <<< "${JOSTLE_TARGET_TASKS:-unitTest25JNI unitTest25FFI integrationTest25JNI integrationTest25FFI}"

# One task at a time, each with its OWN --tests flags. Two measured reasons:
#
#   * a trailing block of --tests after several tasks does not restrict them.
#     Gradle binds --tests to the task that PRECEDES it, and passing them all
#     at the end ran the entire suite while reporting as filtered.
#   * Gradle FAILS a task whose filter matches nothing ("No tests found for
#     given includes"). That is the normal case here, not an error: the
#     integration tasks carry their own include filter (*LimitTest, *OpsTest,
#     *IntegrationTest), so a plain unit class legitimately matches nothing
#     there. Per-task invocation lets that be tolerated for THAT task while a
#     genuine failure anywhere else still stops the run.
#
# Result directories are deleted first: Gradle leaves stale XML in place, so a
# leg that did not execute this time otherwise serves the previous run's
# results as though they were fresh.
GRADLE_FATAL=0
TASK_LOG=$(mktemp -t jostle-targeted)
trap 'rm -f "$TASK_LOG"' EXIT

echo "=== targeted run ==="
echo "  tasks   : ${TASKS[*]}"
echo "  classes : ${CLASSES[*]}"
echo

for t in "${TASKS[@]}"; do
  ARGS=(":jostle:$t" "--rerun")
  for c in "${CLASSES[@]}"; do
    # "*.$c" anchors on the package separator. A bare "*$c" is a SUFFIX match,
    # so requesting AESKeyWrapInvTest silently also ran FIPSAESKeyWrapInvTest
    # - measured, and caught by this script's own widening check on its first
    # falsification run. Ask for the twin by name if you want it.
    ARGS+=("--tests" "*.$c")
  done

  rm -rf "jostle/build/test-results/$t"

  echo "--- :jostle:$t ---"
  set +e
  ./gradlew "${ARGS[@]}" > "$TASK_LOG" 2>&1
  rc=$?
  set -e
  tail -n 40 "$TASK_LOG"

  if [ "$rc" -ne 0 ]; then
    if grep -q "No tests found for given includes" "$TASK_LOG"; then
      echo "note: none of the requested classes live in $t — not fatal"
    else
      echo "FAIL: :jostle:$t exited $rc" >&2
      GRADLE_FATAL="$rc"
    fi
  fi
  echo
done

VARGS=()
for t in "${TASKS[@]}"; do VARGS+=(--task "$t"); done
for c in "${CLASSES[@]}"; do VARGS+=(--class "$c"); done

echo
python3 "$SCRIPT_DIR/verify-targeted.py" "${VARGS[@]}"
VERIFY_RC=$?

# Gradle's own exit still matters — a compile failure never reaches the XML.
if [ "$GRADLE_FATAL" -ne 0 ]; then
  echo "FAIL: a gradle task failed for a reason other than an empty filter" >&2
  exit "$GRADLE_FATAL"
fi
exit "$VERIFY_RC"
