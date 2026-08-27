---
name: verify-test-matrix
description: Run Jostle's full test matrix (base test, unitTest25JNI/FFI, integrationTest25JNI/FFI) with forced execution and the FIPS module wired, then verify the result XML proves it — zero failures AND no FIPS-gated class wholesale-skipped. Covers the TWO-PASS OPS discipline (run-two-pass.sh): the ~40 *OpsTest classes need a JOSTLE_OPS_TEST=1 native build and silently skip against the shipped one, so a single pass under-covers. Also sweeps every FIPS module CONFIGURATION (sweep-fips-configs.sh), since most strictness differences are fipsinstall config rather than module version and a default-config run leaves the capability gates unexercised. Use this skill whenever the user wants the suite run and trusted — including phrases like "run the full test matrix", "run all the tests including FIPS", "verify everything is green", "did the FIPS tests actually run", "did the OPS tests run", "test both FIPS modules", "full verification pass", "declare the branch green", and similar. Exists because gradle does not treat TEST_FIPS_LIB as a task input: a cached green run silently replays wholesale-skipped FIPS classes in milliseconds.
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

## The two-pass OPS discipline

**One test run cannot cover the suite, because two parts of it need different
native builds.** The `OPS_*` macros in `interface/*/util/ops.h` expand to
nothing unless the C was compiled with `JOSTLE_OPS_TEST=1`, so against an
ordinary build every one of the ~40 `*OpsTest` classes assumption-skips — and
the suite still reports green. `build_osx.sh` / `build_linux.sh` already do two
native passes for this reason; the test side needs the same.

| pass | native build | tasks | what it covers |
|---|---|---|---|
| 1 | plain `./interface/build.sh` | all five | the library that actually **ships** |
| 2 | `JOSTLE_OPS_TEST=1 ./interface/build.sh` | `integrationTest25JNI/FFI` only | the fault-injection paths — ~40 `*OpsTest` classes, 16 of them FIPS |

Pass 2 skips the base `test` and `unitTest25*` tasks deliberately: no `*OpsTest`
lives there, so repeating the 27-minute `test` task would add nothing. Pass 2
costs about 15 minutes, not another 90.

```bash
export JAVA_HOME=/path/to/jdk-25
export OPENSSL_PREFIX=/path/to/openssl        # pass 2 rebuilds native code
export TEST_FIPS_LIB=/path/to/ossl-modules/fips.dylib
bash .claude/skills/verify-test-matrix/scripts/run-two-pass.sh
```

`run-two-pass.sh` does both builds, both runs, and **always leaves a plain
build installed** — including on Ctrl-C, via an EXIT trap. An instrumented
library left behind is a shipping hazard: it exports the operations-test entry
points.

**Why this is in the skill rather than in someone's head.** A single-pass run
used to report `FAIL` with 16 wholly-skipped FIPS classes and no indication
that the cause was the missing OPS build — indistinguishable from a genuine
masked-skip regression. The verifier now detects which build is installed (it
looks for `JoOps_setFlag` as a raw byte string in the packaged interface
library, which works on Mach-O, ELF and PE without a toolchain) and reports:

1. **plain build, OpsTests skipped** → not a failure. Prints `OPS build state:
   NOT instrumented` and the exact second-pass commands. This pass legitimately
   verified the shipped library.
2. **instrumented build, OpsTests skipped on a JNI task** → exit 2. On an
   instrumented build they have no excuse.
3. **instrumented build, OpsTests skipped on an FFI task** → a note, not a
   failure. Some fault families are JNI-only — the `GetStringUTFChars` /
   `GetByteArrayElements` / int32-overflow guards have no FFI counterpart — so
   `KSServiceOpsTest` skips wholesale under FFI **by design**. Enforcement is
   scoped to JNI tasks for exactly this reason; do not widen it without
   re-checking that case.
4. `--require-ops` → exit 4 unless the installed build is instrumented. Pass 2
   uses it (via `JOSTLE_REQUIRE_OPS=1`), so "I forgot to rebuild" fails loudly
   instead of passing vacuously.

`run-matrix.sh` now takes task names as arguments (default: the five-task
matrix), which is what makes an OPS-only pass expressible.

**Combining with the config sweep.** `run-two-pass.sh` covers one FIPS module
configuration. For full coverage run `sweep-fips-configs.sh` (that is pass 1
across every config), then pass 2 per config — the OPS paths are
fault-injection sites rather than module-capability gates, but
`FIPSInitOpsTest` drives `jostle_fips_ctx.c`'s six injection sites through
`JoFIPS_set_openssl_module`, which is genuinely module-dependent.

## Sweeping every FIPS module configuration

`run-matrix.sh` runs ONE configuration — whatever `TEST_FIPS_LIB` points at,
with whatever `fipsmodule.cnf` happens to be installed. That is not enough to
trust a FIPS change, because **most of the strictness difference between modules
is `fipsinstall` config, not module version** (see the "A FIPS module's
strictness is mostly `fipsinstall` CONFIG" section of `testing.md`). At default
settings the 3.5.x capability gates never fire, so the suite goes green without
executing the code under test — the worst kind of passing build, and exactly how
a full matrix passed locally then failed on the first CI run.

```bash
export JAVA_HOME=/Users/meganwoods/openjdk/zulu25.28.85-ca-jdk25.0.0-macosx_aarch64
bash .claude/skills/verify-test-matrix/scripts/sweep-fips-configs.sh
```

With no `JOSTLE_FIPS_CONFIGS` it discovers every module under
`${JOSTLE_OPENSSLS_DIR:-$HOME/openssl/openssls}` and runs each with its installed
cnf. To pin the three configurations JSLFIPS must serve, be explicit — the
`name|module|cnf` third field swaps a cnf into place and restores it afterwards:

```bash
P=/Users/meganwoods/openssl/openssls
export JOSTLE_FIPS_CONFIGS="3.1.2-default|$P/osx_3_1_2/lib/ossl-modules/fips.dylib|
3.5.8-pedantic|$P/osx_3_5_8/lib/ossl-modules/fips.dylib|/tmp/cnf_3_5_8_pedantic.cnf
3.5.8-default|$P/osx_3_5_8/lib/ossl-modules/fips.dylib|/tmp/cnf_3_5_8_default.cnf"
bash .claude/skills/verify-test-matrix/scripts/sweep-fips-configs.sh
```

Generate the two 3.5.8 cnf variants once, with the matching `openssl` binary —
`-pedantic` is what turns the gates on:

```bash
cd $P/osx_3_5_8
./bin/openssl fipsinstall -module lib/ossl-modules/fips.dylib -provider_name fips \
    -out /tmp/cnf_3_5_8_default.cnf
./bin/openssl fipsinstall -module lib/ossl-modules/fips.dylib -provider_name fips \
    -pedantic -out /tmp/cnf_3_5_8_pedantic.cnf
```

Three properties worth knowing:

1. **It prints the switches in force** (`dsa-sign-disabled`,
   `rsa-pkcs15-pad-disabled`, `hmac-key-check`, `signature-digest-check`) before
   each run, so the transcript records which configuration was actually tested
   rather than leaving it to be inferred. Diffing two `fipsmodule.cnf` files is
   the one cheap step that separates a module-version difference from a config
   difference, and skipping it has caused a wrong write-up before.
2. **It restores every cnf it overwrites on any exit path**, including Ctrl-C —
   the cnf belongs to a shared OpenSSL install.
3. **A missing module or cnf is a FAIL, not a skip.** Exit 1 with the
   configuration named, so an absent install cannot read as a pass.

`JOSTLE_SWEEP_DRYRUN=1` exercises discovery, the swap and the restore without
running the matrix; it reports "NOT verified" and never counts as a sweep.

Budget roughly 30 minutes per configuration.

## What the verifier checks

1. **Green** — zero failures and zero errors across every `TEST-*.xml` in each task's `jostle/build/test-results/<task>/` directory, naming any failing class.
2. **No masked FIPS skips** (`--require-fips`, applied automatically when `TEST_FIPS_LIB` is set) — no class in a `.fips.` package with `tests == skipped > 0`. That signature means the class never executed: env unset in the JVM that ran it, or a cached replay.
3. **Presence** — a requested task with no result files at all is an error (exit 3), not a pass.
4. **OPS coverage** — which native build is installed, and whether the `*OpsTest` classes ran under it. See "The two-pass OPS discipline" above for the four cases and why FFI-task skips are not enforced.

Exit codes: 0 verified; 1 failures/errors; 2 masked FIPS classes (or OPS classes skipped on a JNI task despite an instrumented build); 3 missing task results; 4 OPS coverage missing while `--require-ops`.

## Caveats

1. **Filtered runs replace the result set.** `--tests "Foo"` leaves only Foo's XML in the task's results directory, so verification after a filtered run reports a tiny (but honest) total. Always verify immediately after a FULL run; treat a low `tests=` count in the table as "this task's last run was filtered", not as coverage.
2. Expected skip patterns that are NOT flagged: JNI-only tests skipping under the FFI task (`OPS_FAILED_ACCESS_*` classes; `KSServiceOpsTest` skips wholesale there by design), and OPS classes skipping wholesale against a non-instrumented native build. The verifier now distinguishes both cases from a genuine masked skip rather than guessing — see "The two-pass OPS discipline". A plain-build run that skips OpsTests is reported as an incomplete verification with the second-pass commands, not as a failure.
3. The five default tasks are the practical gate. The older-JDK tasks (`testNN`, `unitTestNN`, `integrationTestNN` for 8/11/17/21) run when their `BC_JDKNN` env vars are set; pass task names explicitly to include them.
