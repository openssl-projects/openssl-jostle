---
name: audit-jni-ops-coverage
description: Scan Jostle's JNI bridge sources for JVM access calls (GetStringUTFChars, GetByteArrayElements, load_bytearray_ctx, etc.) whose return values are checked in an `if (...)` but lack `OPS_FAILED_ACCESS_*` fault-injection instrumentation. Use this skill whenever the user wants to audit OPS test coverage of JNI access failure paths — including phrases like "find missing JNI OPS tests", "audit JNI OPS coverage", "which JNI access calls have no OPS instrumentation", "check for uninstrumented JNI access faults in <file>", "review JNI bridge for OPS gaps", "what JNI calls aren't covered by ops tests", "where do we need OPS_FAILED_ACCESS instrumentation", and similar. Also applies when the user wants to know if a specific JNI bridge file has full OPS coverage of its `(*env)->` access points before declaring a feature done.
---

# Audit JNI bridge code for missing OPS_FAILED_ACCESS instrumentation

Jostle's `*OpsTest` infrastructure fault-injects JVM access failures (failed `GetStringUTFChars`, failed `GetByteArrayElements`, failed `GetPrimitiveArrayCritical`, etc.) via the `OPS_FAILED_ACCESS_*` macros in `interface/util/ops.h`. Each fallible JNI access in `interface/jni/*.c` SHOULD be wrapped in one of those macros so a test can force the failure path. This skill is the JNI counterpart to `audit-openssl-ops-coverage`: where that one targets `OPS_OPENSSL_ERROR_*` around OpenSSL EVP calls in `interface/util/`, this one targets `OPS_FAILED_ACCESS_*` around JVM access calls in `interface/jni/`.

## When to use this skill

Trigger phrases (any of):

1. "audit JNI OPS coverage" / "find missing JNI OPS tests"
2. "which JNI calls don't have OPS_FAILED_ACCESS instrumentation"
3. "review `<filename>` for JNI OPS gaps"
4. "are all the JNI access failure paths covered" / "is this JNI bridge fully OPS-tested"
5. Before a major JNI bridge change is declared done — verify the new code's access failure paths are testable.

## How to run

The skill ships a Python script at `scripts/find-missing-jni-ops.py`. From the repo root:

```bash
# Scan the whole jni tree (default).
python3 .claude/skills/audit-jni-ops-coverage/scripts/find-missing-jni-ops.py

# Scan one file.
python3 .claude/skills/audit-jni-ops-coverage/scripts/find-missing-jni-ops.py interface/jni/ed_jni.c

# Scan one directory.
python3 .claude/skills/audit-jni-ops-coverage/scripts/find-missing-jni-ops.py interface/jni
```

Exit code is 0 when nothing is flagged, 1 when at least one candidate is found. Suitable for CI gating once the JNI bridge is fully instrumented.

## What the script flags

Two patterns:

1. **Direct call in if-condition** — `if (!load_bytearray_ctx(&out, env, _out))`, `if ((*env)->NewByteArray(env, len) == NULL)`. The JNI access call sits inside the if-condition itself, and the condition has no `OPS_*` prefix.

2. **After-assign check** — the previous non-blank line was `name = (*env)->GetStringUTFChars(env, _name, NULL)` and the current line is `if (name == NULL)` (or `!= NULL`, etc.) with no `OPS_*` prefix.

Each finding reports `file:line  [direct|after-assign]  <function-names>  if (snippet)`. Group by file in the output.

## What the script covers

Two families of access calls (full list in `JNI_HELPERS` and `JVM_JNI_CALLS` at the top of the script):

1. **Project helpers** in `interface/jni/bytearrays.{c,h}` and `byte_array_critical.{c,h}` — `load_bytearray_ctx`, `load_critical_ctx`, `load_bytearray_new`, `check_bytearray_in_range`, `check_critical_in_range`. Return 0/false on JNI access failure or range-check failure.
2. **JVM-direct calls** invoked as `(*env)->FuncName(...)` — `GetStringUTFChars`, `GetByteArrayElements`, `GetPrimitiveArrayCritical`, `NewByteArray`, `FindClass`, `GetMethodID`/`GetFieldID`, `NewObject`, `CallObjectMethod`, `NewLocalRef`/`NewGlobalRef`, `AttachCurrentThread`, etc. Return NULL or non-`JNI_OK` on failure.

## What the script ignores

1. **Cleanup / always-succeeding calls** — `ReleaseByteArrayElements`, `ReleasePrimitiveArrayCritical`, `ReleaseStringUTFChars`, `DeleteLocalRef`, `init_bytearray_ctx`, `release_bytearray_ctx`, etc. The full list is `NEVER_FAILS` in the script.
2. **Length / size getters** — `GetArrayLength`, `GetStringUTFLength`, `GetStringLength`. These don't fail in practice and the project doesn't check their returns.
3. **Discriminators** — `IsSameObject`, `IsInstanceOf`, `ExceptionCheck`. Return yes/no answers, not error codes.
4. **Already-instrumented calls** — anything where the `if (...)` condition contains `OPS_<anything>` is treated as covered.
5. **C++ / non-C files** — only `.c` is scanned.

## Interpreting findings

The script over-reports by design: false positives are easier to dismiss than silent gaps. For each finding, decide:

1. **Real gap** — the call can fail (or the range check is reachable only by OPS fault) and should be instrumented. Apply the fix in the section below.
2. **Range check exercised by Limit tests** — `check_bytearray_in_range` and `check_critical_in_range` failures are typically reachable by a Limit test passing an explicit out-of-range offset/length, so OPS instrumentation is redundant. Still, instrument the ones whose failure is **NOT** reachable from user input — e.g. `block_cipher_ni_jni.c:286` instruments `check_critical_in_range(&output, out_off, out_len)` where `out_len` is computed from `output.size`, so the user can't make it fail. The choice is per call site.
3. **Infrastructure file false positives** — `bytearrays.c` and `byte_array_critical.c` are the implementations of the helpers. Their JNI access checks are the bottom of the stack and aren't themselves instrumented (the wrappers around them in client files are). Findings in these two files are expected noise.
4. **Positive-logic check** — `if (array != NULL) { ...success... } else { ...failure... }` is the inverse of the usual pattern; the script flags both polarities, but only `== NULL` (failure-path) bodies need OPS instrumentation. Filter manually.
5. **Truly infallible** — add the function name to `NEVER_FAILS` in `scripts/find-missing-jni-ops.py` and re-run. Suppression is by function name, so it applies globally.

## Fix recipe — adding OPS_FAILED_ACCESS instrumentation

Two-part fix: instrument the JNI call, then add an OPS test that exercises the new fault-injection point.

### Part 1: instrument the JNI call

For a **direct call** in an if-condition, prepend an `OPS_FAILED_ACCESS_N` macro:

```c
// Before
if (!load_bytearray_ctx(&input, env, _input)) {
    ret_code = JO_FAILED_ACCESS_INPUT;
    goto exit;
}

// After
if (OPS_FAILED_ACCESS_N !load_bytearray_ctx(&input, env, _input)) {
    ret_code = JO_FAILED_ACCESS_INPUT;
    goto exit;
}
```

For an **after-assign** check, the macro goes on the `if`-line, not the assignment line:

```c
// Before
const char *name = (*env)->GetStringUTFChars(env, _name, NULL);
if (name == NULL) {
    ret_code = JO_UNABLE_TO_ACCESS_NAME;
    goto exit;
}

// After
const char *name = (*env)->GetStringUTFChars(env, _name, NULL);
if (OPS_FAILED_ACCESS_N name == NULL) {
    ret_code = JO_UNABLE_TO_ACCESS_NAME;
    goto exit;
}
```

Unlike the OpenSSL audit fix, `OPS_FAILED_ACCESS_*` has **no companion `OPS_OFFSET_FAILED_ACCESS_*` macro**. The return code stays as the typed `JO_FAILED_ACCESS_*` / `JO_UNABLE_TO_ACCESS_*` value (e.g. `JO_FAILED_ACCESS_INPUT`, `JO_UNABLE_TO_ACCESS_NAME`) — there is no per-site offset to disambiguate one failure from another. Two sites in the same function that both fire on `OPS_FAILED_ACCESS_1` and return the same `JO_*` code are indistinguishable from the test's perspective. When you need to distinguish them, use a different `_FAILED_ACCESS_<N>` slot.

### Part 2: pick the OPS slot

The `OPS_FAILED_ACCESS_N` macros are defined in `interface/util/ops.h` (currently `_1` through `_4`). Two strategies:

1. **Reuse an existing slot** (preferred when possible). A slot can be reused for a new fault-injection point if it does NOT fire on any other code path reachable during the test for the new point. The same rule as `OPS_OPENSSL_ERROR_*` reuse: walk the call graph from the test's entry point and confirm no earlier code on the path uses the slot.

   Example from `kdf_jni.c`: `OPS_FAILED_ACCESS_1` fires on the password buffer load (line 39), `_2` on the salt (line 50), `_3` on the output (line 86), `_4` on the digest string (line 223). Each is a distinct slot because all four can fire in the same function call.

2. **Add a new slot** to `ops.h`. Append `OPS_FAILED_ACCESS_<N+1>`, increment `OPS_MAX_TEST`, and add the matching enum entry to `OperationsTestNI.OpsTestFlag`. Only do this when no existing slot is reusable. Currently `_1` through `_4` cover all in-tree call sites — a new slot is rarely needed.

### Part 3: add the OPS test

Write the test in the matching `*OpsTest.java`. Pattern:

```java
@Test
public void <feature>_<accessSite>_failure() throws Exception {
    Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

    long ref = 0;
    try {
        ref = <serviceNI>.allocate*();
        // ... pre-conditions ...

        operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_N);
        int code = <serviceNI>.ni_<operation>(ref, ...);
        // The expected code is the typed JO_FAILED_ACCESS_* / JO_UNABLE_TO_ACCESS_*
        // value for the call site (no offset arithmetic — these flags have no offsets).
        Assertions.assertEquals(JO_FAILED_ACCESS_INPUT, code);
    } finally {
        operationsTestNI.resetFlags();
        <serviceNI>.dispose*(ref);
    }
}
```

Unlike OPS_OPENSSL_ERROR tests, the assertion compares against the typed `JO_*` constant (e.g. `JO_FAILED_ACCESS_INPUT`, `JO_UNABLE_TO_ACCESS_NAME`) rather than a computed negative integer like `-1046`. Pin the message text in any catch block — see CLAUDE.md "Pin the exception message in OPS / Limit-test catch blocks" for the typed-exception assertion pattern.

## Build / verify

The OPS macros are no-ops in a regular build. To run OPS tests you need a native rebuild with `JOSTLE_OPS_TEST=1`:

```bash
export JOSTLE_OPS_TEST=1
./interface/build.sh
./gradlew :jostle:integrationTest25FFI :jostle:integrationTest25JNI \
    --tests "org.openssl.jostle.test.<package>.<NewOpsTest>"
```

Note: `OPS_FAILED_ACCESS_*` fault-injection is JNI-specific. The FFI bridge in `interface/ffi/` doesn't have JVM access calls — it receives raw pointers from the caller — so OPS tests for these slots only run meaningfully on the JNI side. The `*OpsTest` files still run on both `integrationTest25FFI` and `integrationTest25JNI` tasks, but the FFI runs of an `OPS_FAILED_ACCESS_*` test typically pass trivially because the FFI path doesn't take the instrumented code branch. Verify that the new test fails (or skips) cleanly on FFI rather than asserting against an unrelated code path.

Without `JOSTLE_OPS_TEST=1`, the new test will skip via `Assumptions.assumeTrue(opsTestAvailable())` rather than fail — handy for the regular `:jostle:test` task that doesn't require an OPS build.

## Limitations

1. **Regex-based** — the script doesn't parse C. Macro-heavy or unusual formatting can confuse it. The `(*env)->Func(` detection requires the standard parenthesisation; an aliased `JNIEnv *e = env;` would slip past.
2. **Polarity unaware** — the script flags both `== NULL` (failure-path) and `!= NULL` (success-path) checks against an assigned variable. The success-path findings are typically false positives — only `== NULL`-style failure handling needs OPS instrumentation.
3. **Helper-implementation noise** — `bytearrays.c` and `byte_array_critical.c` ARE the helper layer. Their internal JNI access checks aren't themselves instrumented (the wrappers around them in client files are). Expect ~5 findings in these two files that are not real gaps.
4. **`check_*_in_range` is dual-purpose** — range-check failures reachable from user input (most common) need no OPS instrumentation because Limit tests exercise them directly; range-check failures unreachable from user input (rarer, e.g. when length is computed from buffer size) DO need OPS instrumentation. The script can't distinguish the two — judge per call site.
5. **Indirect failure paths** — a JNI call whose result is stored in a struct field and checked elsewhere (multiple lines later, or in a different function) is missed by the "after-assign" heuristic. Manual review for these.
6. **`OPS_*` macros that aren't `OPS_FAILED_ACCESS`** — the script treats any `OPS_*` prefix as "instrumented". So `OPS_OPENSSL_ERROR_*` (OpenSSL fault), `OPS_LEN_CHANGE_*` (length-change guard), etc. all count as covered. That's correct — those macros also force the if-body to execute.

## Reference

`scripts/find-missing-jni-ops.py` is self-documenting. The `JNI_HELPERS`, `JVM_JNI_CALLS`, and `NEVER_FAILS` sets near the top of the file are the curated catalogues — extend them as new JNI access functions are introduced in the codebase.
