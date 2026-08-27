#!/usr/bin/env bash
#
# The FIPS module-configuration sweep, cut down and run concurrently.
#
# WHAT IT DOES DIFFERENTLY from sweep-fips-configs.sh, and why each is sound:
#
#   1. FIPS CLASSES ONLY. A fipsmodule.cnf switch can only change the FIPS
#      module's behaviour, and only JSLFIPS touches it. The other ~150 test
#      classes produce byte-identical results in every configuration, so
#      running them per config is pure cost. Selection is by NAME, which is
#      safe because FIPSTestNamingParityTest fails the build if a class drives
#      JSLFIPS without a FIPS name - without that guard this filter would
#      silently stop covering a mis-named class.
#
#   2. JAVA 25 ONLY. JDK level cannot interact with module configuration.
#      Running Java 8/11/17/21 once per config cannot distinguish anything the
#      Java 25 run does not, and the multi-JDK `test` task is the single
#      biggest cost in the old sweep. The full multi-JDK matrix still runs -
#      once - in run-two-pass.sh.
#
#   3. NO SHARED fipsmodule.cnf, SO NO SWAP AND NO TRAP. Each config gets its
#      own directory holding a COPY of the module plus its cnf. The module-mac
#      covers the module file's contents, not its path, so a copy is valid
#      (measured: all three configs resolve and pass the golden-surface test
#      from a copied directory). This is what makes concurrency possible - the
#      old script's exit trap existed solely to put a shared file back.
#
#   4. ONE WORKING-TREE COPY PER CONFIG. Three ./gradlew invocations in one
#      project directory contend on the project lock and clobber each other's
#      build/test-results. Copies are ~400MB each and carry staged-but-
#      uncommitted work, which a git worktree would NOT.
#
# The old sweep-fips-configs.sh remains the conservative full sweep. Prefer it
# when the change touches anything outside the FIPS surface, or when this
# script's result is being questioned.
#
# Required env:
#   JAVA_HOME   Java 25 JDK
# Optional:
#   JOSTLE_SWEEP_WORK   scratch root (default /tmp/fips-sweep)
set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
REPO=$(cd "$SCRIPT_DIR/../../../.." && pwd)
cd "$REPO" || exit 3

if [ -z "${JAVA_HOME:-}" ]; then
  echo "JAVA_HOME must point at a Java 25 JDK" >&2
  exit 2
fi

WORK="${JOSTLE_SWEEP_WORK:-/tmp/fips-sweep}"
OPENSSLS="${JOSTLE_OPENSSLS_DIR:-$HOME/openssl/openssls}"

# name|module file|cnf file   -- cnf empty means "use the install's own"
CONFIGS=(
  "3.1.2|$OPENSSLS/osx_3_1_2/lib/ossl-modules/fips.dylib|$OPENSSLS/osx_3_1_2/lib/ossl-modules/fipsmodule.cnf"
  "3.5.8-pedantic|$OPENSSLS/osx_3_5_8/lib/ossl-modules/fips.dylib|/tmp/cnf_3_5_8_pedantic.cnf"
  "3.5.8-default|$OPENSSLS/osx_3_5_8/lib/ossl-modules/fips.dylib|/tmp/cnf_3_5_8_default.cnf"
)

TASKS=(unitTest25JNI unitTest25FFI integrationTest25JNI integrationTest25FFI)

echo "=== preparing $WORK ==="
rm -rf "$WORK"
mkdir -p "$WORK"

for entry in "${CONFIGS[@]}"; do
  name="${entry%%|*}"; rest="${entry#*|}"
  module="${rest%%|*}"; cnf="${rest#*|}"

  for f in "$module" "$cnf"; do
    if [ ! -f "$f" ]; then
      echo "missing: $f" >&2
      exit 2
    fi
  done

  mkdir -p "$WORK/module/$name"
  cp "$module" "$WORK/module/$name/fips.dylib"
  cp "$cnf" "$WORK/module/$name/fipsmodule.cnf"

  # Record WHICH configuration this is, so the transcript never leaves it to
  # be inferred - the old script's rule, kept.
  echo "--- $name: $(grep -c '= 1$' "$cnf") switches on, module $(basename "$(dirname "$module")")"

  echo "    copying working tree..."
  mkdir -p "$WORK/tree/$name"
  # Exclude build outputs: large, stale, and each copy rebuilds its own.
  tar -cf - --exclude=build --exclude=.git -C "$REPO" . | tar -xf - -C "$WORK/tree/$name"
done

echo
echo "=== launching ${#CONFIGS[@]} configurations concurrently ==="
pids=()
names=()
for entry in "${CONFIGS[@]}"; do
  name="${entry%%|*}"
  (
    cd "$WORK/tree/$name" || exit 3
    export TEST_FIPS_LIB="$WORK/module/$name/fips.dylib"
    for t in "${TASKS[@]}"; do
      echo "=== [$name] :jostle:$t ==="
      ./gradlew ":jostle:$t" --rerun --tests '*FIPS*' || exit 1
    done
  ) > "$WORK/$name.log" 2>&1 &
  pid=$!
  pids+=($pid)
  names+=("$name")
  echo "  $name -> pid $pid, log $WORK/$name.log"
done

echo
rc=0
for i in "${!pids[@]}"; do
  if wait "${pids[$i]}"; then
    echo "  ${names[$i]}: gradle OK"
  else
    echo "  ${names[$i]}: gradle FAILED"
    rc=1
  fi
done

echo
echo "=== verifying result XML (green is not enough - it must have RUN) ==="
for name in "${names[@]}"; do
  python3 - "$WORK/tree/$name" "$name" <<'PY' || rc=1
import glob, re, sys
root, name = sys.argv[1], sys.argv[2]
tests = fails = errors = skipped = 0
classes = 0
for f in glob.glob(root + "/jostle/build/test-results/*/TEST-*.xml"):
    head = open(f, errors="ignore").read(4000)
    m = re.search(r'<testsuite[^>]*tests="(\d+)"[^>]*skipped="(\d+)"[^>]*failures="(\d+)"[^>]*errors="(\d+)"', head)
    if not m:
        m2 = re.search(r'tests="(\d+)"', head)
        if not m2:
            continue
        continue
    t, s, fl, e = (int(x) for x in m.groups())
    tests += t; skipped += s; fails += fl; errors += e
    classes += 1
ran = tests - skipped
status = "OK" if (fails == 0 and errors == 0 and ran > 0) else "BAD"
print(f"  {name}: {classes} classes, {tests} tests, {ran} executed, {skipped} skipped, "
      f"{fails} failures, {errors} errors  [{status}]")
if fails or errors:
    sys.exit(1)
if ran == 0:
    print(f"  {name}: NOTHING EXECUTED - TEST_FIPS_LIB was not seen, or the filter matched nothing")
    sys.exit(1)
PY
done

echo
if [ "$rc" -eq 0 ]; then
  echo "SWEEP GREEN across ${#names[@]} configurations"
else
  echo "SWEEP FAILED - see $WORK/<config>.log"
fi
exit "$rc"
