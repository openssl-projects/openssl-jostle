---
name: audit-openssl-ops-coverage
description: Scan Jostle's C sources for OpenSSL function calls whose return values are checked in an `if (...)` but lack `OPS_*` fault-injection instrumentation. Use this skill whenever the user wants to audit OPS test coverage of error paths in C code — including phrases like "find missing OPS tests", "audit OPS coverage", "which OpenSSL calls have no OPS instrumentation", "check for uninstrumented error paths in rsa.c", "review C code for OPS gaps", "what OpenSSL calls aren't covered by ops tests", "where do we need more OPS tests", and similar. Also applies when the user wants to know if a specific .c file has full OPS coverage before declaring a feature done.
---

# Audit C code for missing OPS instrumentation

Jostle's `*OpsTest` infrastructure fault-injects OpenSSL failures via the `OPS_*` macros in `interface/util/ops.h`. Each fallible OpenSSL call in `interface/util/*.c` SHOULD be wrapped in one of those macros so a test can force the failure path. This skill finds calls where the return value IS being checked (the developer cares about failure) but no OPS macro is in front of the check (the failure is currently untestable).

## When to use this skill

Trigger phrases (any of):

1. "audit OPS coverage" / "find missing OPS tests"
2. "which OpenSSL calls don't have OPS instrumentation"
3. "review `<filename>` for OPS gaps"
4. "are all the EVP failure paths covered" / "is this file fully OPS-tested"
5. Before a major C change is declared done — verify the new code's failure paths are testable.

## How to run

The skill ships a Python script at `scripts/find-missing-ops.py`. From the repo root:

```bash
# Scan the whole util tree (default).
python3 .claude/skills/audit-openssl-ops-coverage/scripts/find-missing-ops.py

# Scan one file.
python3 .claude/skills/audit-openssl-ops-coverage/scripts/find-missing-ops.py interface/util/rsa.c

# Scan one directory.
python3 .claude/skills/audit-openssl-ops-coverage/scripts/find-missing-ops.py interface/util
```

Exit code is 0 when nothing is flagged, 1 when at least one candidate is found. Suitable for CI gating once the codebase is fully instrumented.

## What the script flags

Two patterns:

1. **Direct call in if-condition** — `if (1 != EVP_X(...))` or `if (EVP_X(...) == NULL)`. The OpenSSL call sits inside the if-condition itself, and the condition has no `OPS_*` prefix.

2. **After-assign check** — the previous non-blank line was `var = EVP_X(...)` and the current line is `if (var == NULL)` (or `!= NULL`, `< 0`, etc.) with no `OPS_*` prefix.

Each finding reports `file:line  [direct|after-assign]  <function-names>  if (snippet)`. Group by file in the output.

## What the script ignores

1. **Cleanup / always-succeeding calls** — `EVP_*_free`, `BN_free`, `ERR_clear_error`, `OPENSSL_zalloc` (which `jo_assert`s on failure), and a curated list of getters that never fail (`EVP_PKEY_get_id`, `BN_num_bytes`, ...). The full list is `NEVER_FAILS` in the script.
2. **Type discriminators** — `EVP_PKEY_is_a`, `EVP_MD_xof`, `BN_cmp`, etc. These return a yes/no answer, not an error code, and are typically used as boolean conditions (no error handling needed).
3. **Already-instrumented calls** — anything where the `if (...)` condition contains `OPS_<anything>` is treated as covered.
4. **C++ / non-C files** — only `.c` is scanned.

## Interpreting findings

The script over-reports by design: false positives are easier to dismiss than silent gaps. For each finding, decide:

1. **Real gap** — the call can fail and should be instrumented. Apply the fix in the section below.
2. **False positive (truly infallible)** — add the function name to `NEVER_FAILS` in `scripts/find-missing-ops.py` and re-run. Suppression is by function name, so it applies globally.
3. **False positive (discriminator)** — same fix as #2, but conceptually different: the function returns a boolean answer rather than an error code.
4. **Intentionally unstrumented** — for example, a call whose failure is impossible-in-practice because the inputs are pre-validated by the bridge layer. Add to `NEVER_FAILS` with a comment explaining why.

## Fix recipe — adding OPS instrumentation

Two-part fix: instrument the C call, then add an OPS test that exercises the new fault-injection point.

### Part 1: instrument the C call

For a **direct call** in an if-condition, prepend an `OPS_OPENSSL_ERROR_N` macro and append an `OPS_OFFSET_OPENSSL_ERROR_N(offset)`:

```c
// Before
if (1 != EVP_X_op(ctx, ...)) {
    return JO_OPENSSL_ERROR;
}

// After
if (OPS_OPENSSL_ERROR_N 1 != EVP_X_op(ctx, ...)) {
    return JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_N(offset);
}
```

For an **after-assign** check, the macro goes on the `if`-line, not the assignment line:

```c
// Before
ctx = EVP_PKEY_CTX_new_from_name(libctx, "RSA", NULL);
if (ctx == NULL) {
    return JO_OPENSSL_ERROR;
}

// After
ctx = EVP_PKEY_CTX_new_from_name(libctx, "RSA", NULL);
if (OPS_OPENSSL_ERROR_N ctx == NULL) {
    return JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_N(offset);
}
```

### Part 2: pick the OPS slot and offset

The `OPS_OPENSSL_ERROR_N` macros are defined in `interface/util/ops.h` (currently `_1` through `_12`). Two strategies:

1. **Reuse an existing slot** (preferred when possible). A slot can be reused for a new fault-injection point if it does NOT fire on any other code path reachable during the test for the new point. Walk the call graph: from the test's first NI call, trace which functions are entered before the new instrumentation site is reached, and confirm none of them use the same slot.

   Example from `rsa.c`: `OPS_OPENSSL_ERROR_6` was originally used only in `configure_padding`'s PSS-saltlen check. It's now ALSO used in `rsa_generate_key` line 148 because `rsa_generate_key` doesn't call `configure_padding`. Two distinct call sites, one shared slot, two independent tests.

2. **Add a new slot** to `ops.h`. Append `OPS_OPENSSL_ERROR_<N+1>` and its matching `OPS_OFFSET_OPENSSL_ERROR_<N+1>(x)`, increment `OPS_MAX_TEST`, and add the matching enum entry to `OperationsTestNI.OpsTestFlag`. Only do this when no existing slot is reusable.

The **offset number** must be unique within the file's offset block. Inspect existing offsets in the file:

```bash
grep -nE "OPS_OFFSET_OPENSSL_ERROR_[0-9]+\([0-9]+\)" interface/util/<file>.c
```

Pick the next free integer within the file's block. Per-file blocks (from CLAUDE.md): `rsa.c` uses 1000s, `rsa_oaep.c` 2000s, `rsa_pkcs1.c` 2100s, `ec.c` 3000s, etc. The offset becomes part of the test contract — the test asserts the exact return code `-(JO_OPENSSL_ERROR_MAG + offset)`, so a future renumber breaks the test loudly.

### Part 3: add the OPS test

Write the test in the matching `*OpsTest.java`. Pattern:

```java
@Test
public void <feature>_<failureSite>_failure() throws Exception {
    Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

    long ref = 0;
    try {
        // Set up state required to reach the fault-injection site.
        // Do NOT set the OPS flag until everything else has succeeded.
        ref = <serviceNI>.allocate*();
        // ... pre-conditions ...

        operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_N);
        int code = <serviceNI>.ni_<operation>(ref, ...);
        // Computed as -(2 + offset). For offset=1044: -1046.
        Assertions.assertEquals(-<computed>, code);
    } finally {
        operationsTestNI.resetFlags();
        <serviceNI>.dispose*(ref);
    }
}
```

Pin the exact integer return code in the assertion — that's how the OPS infrastructure verifies the right call site fired. CLAUDE.md "Pin the exception message in OPS / Limit-test catch blocks" applies the same idea at the JCE layer.

## Build / verify

The OPS macros are no-ops in a regular build. To run OPS tests you need a native rebuild with `JOSTLE_OPS_TEST=1`:

```bash
export JOSTLE_OPS_TEST=1
./interface/build.sh
./gradlew :jostle:integrationTest25FFI :jostle:integrationTest25JNI \
    --tests "org.openssl.jostle.test.<package>.<NewOpsTest>"
```

Without `JOSTLE_OPS_TEST=1`, the new test will skip via `Assumptions.assumeTrue(opsTestAvailable())` rather than fail — handy for the regular `:jostle:test` task that doesn't require an OPS build.

## Limitations

1. **Regex-based** — the script doesn't parse C. Macro-heavy or unusual formatting can confuse it.
2. **Multi-line if-conditions** — the script collects across lines until matching paren, but very long conditions get truncated in the displayed snippet.
3. **Indirect failure paths** — calls whose result is stored in a struct field and checked elsewhere (multiple lines later, or in a different function) are missed by the "after-assign" heuristic. Manual review for these.
4. **Functions that LOOK like OpenSSL but aren't** — e.g. `EVP_*` macros defined locally in `bc_err_codes.h` would be matched. Inspect findings before fixing.
5. **`OPS_*` macros that aren't `OPS_OPENSSL_ERROR`** — the script treats any `OPS_*` prefix as "instrumented". So `OPS_FAILED_ACCESS_*` (JNI access fault), `OPS_LEN_CHANGE_*` (length-change guard), etc. all count as covered. That's correct — those macros also force the if-body to execute.

## Reference

`scripts/find-missing-ops.py` is self-documenting. The `NEVER_FAILS` set near the top of the file is the curated list of "ignore these" function names — extend it as new infallible functions are introduced in the codebase.
