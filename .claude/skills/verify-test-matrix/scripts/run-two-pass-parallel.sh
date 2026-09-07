#!/usr/bin/env bash
#
# The two-pass OPS discipline, run concurrently.
#
# WHY THE SERIAL VERSION IS SERIAL, and what changes here:
#
#   The two passes need DIFFERENT NATIVE BUILDS OF THE SAME FILES
#   (jostle/src/main/resources/native/). In one working tree that forces
#   strict ordering - build plain, test, build OPS, test, rebuild plain - so
#   nothing can overlap and three native builds are needed rather than two.
#
#   Giving each pass its own tree copy dissolves the constraint. Two further
#   consequences, both good:
#
#     * NO EXIT TRAP. The serial script's trap exists solely to put a
#       shippable (plain) build back into the shared tree. Here the main tree
#       is never mutated, so there is nothing to restore - and the failure
#       mode where SIGKILL skips the trap and leaves an OPS-instrumented
#       library installed simply cannot happen.
#     * ONE FEWER NATIVE BUILD. No restore pass.
#
#   Pass 1 also drops work the serial version repeats: run-matrix.sh runs
#   `test unitTest25JNI unitTest25FFI integrationTest25JNI integrationTest25FFI`,
#   but :jostle:test ALREADY dependsOn all four (build.gradle ~line 990), and
#   --rerun makes them execute a second time. Pass 1 here is `:jostle:test`
#   alone, which covers the same set once.
#
# WHY ONLY TWO SHARDS, given a 14-core host: every Test task sets
# maxParallelForks = 8, so ONE gradle invocation already occupies ~8 cores.
# Two concurrent shards is ~16 forks on 14 cores - mild oversubscription and
# close to a clean 2x. Sharding pass 1 further by JDK level is possible and
# would help, but at 3-4 shards the box is 2-3x oversubscribed and the risk
# is flaky timeouts in a gate whose entire value is being trustworthy. Do that
# only with measurements showing it does not destabilise.
#
# Required env:
#   JAVA_HOME       Java 25 JDK
#   OPENSSL_PREFIX  an OpenSSL install - each shard rebuilds native code
# Recommended:
#   TEST_FIPS_LIB   the FIPS module; unset => FIPS classes skip
# Optional:
#   JOSTLE_TWOPASS_WORK  scratch root (default /tmp/jostle-two-pass)
set -u

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

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
REPO=$(cd "$SCRIPT_DIR/../../../.." && pwd)
cd "$REPO" || exit 3
. "$SCRIPT_DIR/tasks-lib.sh"

for v in JAVA_HOME OPENSSL_PREFIX; do
  if [ -z "${!v:-}" ]; then
    echo "$v must be set (each shard rebuilds native code)" >&2
    exit 2
  fi
done

WORK="${JOSTLE_TWOPASS_WORK:-/tmp/jostle-two-pass}"
echo "=== preparing $WORK ==="
rm -rf "$WORK"
mkdir -p "$WORK/plain" "$WORK/ops"

for shard in plain ops; do
  echo "    copying working tree -> $shard"
  tar -cf - --exclude=build --exclude=.git -C "$REPO" . | tar -xf - -C "$WORK/$shard"
done

run_shard() {
  # $1 = shard dir name, $2 = 1 to build with OPS instrumentation
  local shard="$1" ops="$2"
  cd "$WORK/$shard" || return 3

  # Stage 1 of the documented build: generate the JNI headers. The tree copy
  # excludes build/, where they live, so without this every *_jni.c fails on a
  # missing org_openssl_jostle_..._JNI.h. Cheap, and each shard needs its own.
  ./gradlew :jostle:compileJava -q > "$WORK/$shard-headers.log" 2>&1 || {
    echo "[$shard] header generation FAILED - see $WORK/$shard-headers.log"; return 1; }

  if [ "$ops" = "1" ]; then
    JOSTLE_OPS_TEST=1 ./interface/build.sh > "$WORK/$shard-build.log" 2>&1 || {
      echo "[$shard] native build FAILED - see $WORK/$shard-build.log"; return 1; }
    # JOSTLE_REQUIRE_OPS makes an OPS test that SKIPS a failure: against a
    # plain library every *OpsTest assumption-skips and the suite is green
    # without executing a single fault-injection path.
    export JOSTLE_REQUIRE_OPS=1
    for t in $(jostle_tasks ops); do
      echo "=== [$shard] :jostle:$t ==="
      ./gradlew ":jostle:$t" --rerun || return 1
    done
  else
    ./interface/build.sh > "$WORK/$shard-build.log" 2>&1 || {
      echo "[$shard] native build FAILED - see $WORK/$shard-build.log"; return 1; }
    echo "=== [$shard] :jostle:test ==="
    ./gradlew ":jostle:test" --rerun || return 1
  fi
}

echo
echo "=== launching both passes concurrently ==="
run_shard plain 0 > "$WORK/plain.log" 2>&1 &
p_plain=$!
run_shard ops 1 > "$WORK/ops.log" 2>&1 &
p_ops=$!
echo "  plain -> pid $p_plain, log $WORK/plain.log"
echo "  ops   -> pid $p_ops, log $WORK/ops.log"

rc=0
wait "$p_plain" || { echo "  plain: FAILED"; rc=1; }
wait "$p_ops"   || { echo "  ops:   FAILED"; rc=1; }
[ "$rc" -eq 0 ] && echo "  both shards: gradle OK"

echo
echo "=== verifying result XML (green is not enough - it must have RUN) ==="
for shard in plain ops; do
  python3 - "$WORK/$shard" "$shard" <<'PY' || rc=1
import glob, re, sys
root, name = sys.argv[1], sys.argv[2]
tests = fails = errors = skipped = classes = 0
ops_ran = 0
for f in glob.glob(root + "/jostle/build/test-results/*/TEST-*.xml"):
    head = open(f, errors="ignore").read(4000)
    m = re.search(r'<testsuite[^>]*tests="(\d+)"[^>]*skipped="(\d+)"[^>]*failures="(\d+)"[^>]*errors="(\d+)"', head)
    if not m:
        continue
    t, s, fl, e = (int(x) for x in m.groups())
    tests += t; skipped += s; fails += fl; errors += e; classes += 1
    if "OpsTest" in f:
        ops_ran += t - s
ran = tests - skipped
ok = fails == 0 and errors == 0 and ran > 0
print(f"  {name}: {classes} classes, {tests} tests, {ran} executed, {skipped} skipped, "
      f"{fails} failures, {errors} errors" + (f", {ops_ran} OPS executed" if name == "ops" else ""))
if not ok:
    print(f"  {name}: BAD")
    sys.exit(1)
if name == "ops" and ops_ran == 0:
    print("  ops: NO OPS TEST EXECUTED - the shard ran against a plain library, "
          "which is exactly the under-coverage the two-pass discipline exists to prevent")
    sys.exit(1)
PY
done

echo
if [ "$rc" -eq 0 ]; then
  echo "TWO-PASS GREEN (parallel). The repo's own native build was never touched."
else
  echo "TWO-PASS FAILED - see $WORK/{plain,ops}.log"
fi
exit "$rc"
