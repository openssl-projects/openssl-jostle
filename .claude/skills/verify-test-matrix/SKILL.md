---
name: verify-test-matrix
description: Run Jostle's full test matrix (base test, unitTest25JNI/FFI, integrationTest25JNI/FFI) with forced execution and the FIPS module wired, then verify the result XML proves it — zero failures AND no FIPS-gated class wholesale-skipped. Use this skill whenever the user wants the suite run and trusted — including phrases like "run the full test matrix", "run all the tests including FIPS", "verify everything is green", "did the FIPS tests actually run", "full verification pass", "declare the branch green", and similar. Exists because gradle does not treat TEST_FIPS_LIB as a task input: a cached green run silently replays wholesale-skipped FIPS classes in milliseconds.
---

# Run and verify the full test matrix

A green gradle exit does not prove the FIPS surface ran. Gradle's up-to-date check hashes task inputs (class files, classpaths) — **not environment variables** — so a test task last run without `TEST_FIPS_LIB` is UP-TO-DATE when re-invoked with it set, and the cached result (every FIPS class assumption-skipped in full) is replayed as `BUILD SUCCESSFUL` in ~300ms. This bit the 2026-07-12 review application: the first "green matrix" had every FIPS Limit/Ops class skipped. This skill runs the matrix with `--rerun` and then proves execution from the result XML rather than trusting the exit code.

## When to use this skill

1. "run the full test matrix" / "verify everything is green" before a commit or PR.
2. Whenever `TEST_FIPS_LIB` (or any env-gated test set) was toggled since the last run.
3. When a full suite "passed" suspiciously fast — sub-second green is the tell of a cached replay.
4. After multi-agent test sweeps, to arbitrate what actually runs.

## How to run

```bash
# Everything: five tasks with --rerun, then XML verification.
export JAVA_HOME=/path/to/jdk-25            # BC_JDK25 defaults to it
export TEST_FIPS_LIB=/path/to/ossl-modules/fips.dylib
bash .claude/skills/verify-test-matrix/scripts/run-matrix.sh

# Verification only (against whatever result XML exists):
python3 .claude/skills/verify-test-matrix/scripts/verify-results.py --require-fips
```

On this machine the canonical values are `JAVA_HOME=/Users/meganwoods/openjdk/zulu25.28.85-ca-jdk25.0.0-macosx_aarch64` and `TEST_FIPS_LIB=/Users/meganwoods/openssl/openssls/osx_3_1_2/lib/ossl-modules/fips.dylib`. The full run takes ~30 minutes (the base `test` task dominates); run it in the background and read the verifier's table at the end.

## What the verifier checks

1. **Green** — zero failures and zero errors across every `TEST-*.xml` in each task's `jostle/build/test-results/<task>/` directory, naming any failing class.
2. **No masked FIPS skips** (`--require-fips`, applied automatically when `TEST_FIPS_LIB` is set) — no class in a `.fips.` package with `tests == skipped > 0`. That signature means the class never executed: env unset in the JVM that ran it, or a cached replay.
3. **Presence** — a requested task with no result files at all is an error (exit 3), not a pass.

Exit codes: 0 verified; 1 failures/errors; 2 masked FIPS classes; 3 missing task results.

## Caveats

1. **Filtered runs replace the result set.** `--tests "Foo"` leaves only Foo's XML in the task's results directory, so verification after a filtered run reports a tiny (but honest) total. Always verify immediately after a FULL run; treat a low `tests=` count in the table as "this task's last run was filtered", not as coverage.
2. Expected skip patterns that are NOT flagged: JNI-only tests skipping under the FFI task (e.g. `OPS_FAILED_ACCESS_*` classes — partial skips are fine), and OPS classes skipping wholesale against a non-instrumented native build. If the native build lacks `JOSTLE_OPS_TEST=1`, rebuild it first — the verifier can't distinguish that from other assumption-skips unless the class is FIPS-gated.
3. The five default tasks are the practical gate. The older-JDK tasks (`testNN`, `unitTestNN`, `integrationTestNN` for 8/11/17/21) run when their `BC_JDKNN` env vars are set; pass task names explicitly to include them.
