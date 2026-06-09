---
name: annotate-ops-tests
description: Add a one-line `// Exercises interface/util/<file>.c:<line>` comment to each Java OPS test linking it to the exact C-side fault-injection site it drives. Use this skill whenever the user wants to make the OPS test → C source mapping traceable — including phrases like "annotate OPS tests", "link OPS tests to their C sites", "add file:line comments to ops tests", "show which OpenSSL call each ops test fires", "document the C location each ops test exercises", "trace ops tests back to C", and similar. Useful after adding new OPS instrumentation, or after C-side edits shift line numbers and existing annotations need refreshing.
---

# Annotate OPS tests with their C source location

OPS tests assert exact integer return codes (e.g. `-1046`) that encode a specific `OPS_OFFSET_OPENSSL_ERROR_N(offset)` site in a C file. The mapping is recoverable from the test's `setFlag(OPS_OPENSSL_ERROR_N)` + `assertEquals(-code, ...)` pair, but reading the test alone doesn't tell you WHICH C line the test exercises — you have to compute `offset = -code - 2`, grep the C tree for the matching `OPS_OFFSET_*(offset)`, and walk backwards to the `if (OPS_OPENSSL_ERROR_N ...)` line.

This skill automates that lookup and inserts a single comment in the test:

```java
            // Exercises interface/util/rsa.c:589
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
```

The comment points at the **if-line** (the call site whose return value the OPS flag short-circuits), not the error-return line. That's the line readers care about — it names the EVP function being faulted.

## When to use this skill

Trigger phrases:

1. "annotate OPS tests" / "link OPS tests to C source"
2. "add file:line comments to ops tests"
3. "show which OpenSSL call each ops test fires"
4. "trace OPS tests back to C"
5. After adding new OPS instrumentation to a C file — re-run to add comments for the new tests.
6. After a C-side refactor that shifted line numbers — re-run to refresh stale comments (the script updates existing `// Exercises ...` lines in place).

## How to run

The script is at `scripts/annotate-ops-tests.py`. From the repo root:

```bash
# Annotate all OPS tests across the test tree.
python3 .claude/skills/annotate-ops-tests/scripts/annotate-ops-tests.py \
    jostle/src/test/java/org/openssl/jostle/test

# Annotate just one file.
python3 .claude/skills/annotate-ops-tests/scripts/annotate-ops-tests.py \
    jostle/src/test/java/org/openssl/jostle/test/rsa/RSAOpsTest.java

# Dry run — show what would change without writing.
python3 .claude/skills/annotate-ops-tests/scripts/annotate-ops-tests.py \
    jostle/src/test/java/org/openssl/jostle/test --dry-run

# Use a non-default C source directory.
python3 .claude/skills/annotate-ops-tests/scripts/annotate-ops-tests.py \
    <java-path> --c-dir interface/util
```

The script is re-runnable. If a comment already exists above the `setFlag` line, it gets updated in place (so stale line numbers after a C edit are corrected, not duplicated).

## What gets matched

For each `@Test` method:

1. Find the first `operationsTestNI.setFlag(OpsTestFlag.OPS_OPENSSL_ERROR_<N>)` — gives the slot `N`.
2. Find the first `Assertions.assertEquals(-<code>, ...)` inside the method body — gives the offset via `offset = -code - 2`.
3. Look up `(N, offset)` in the C-side index → C path + line number.
4. Insert (or update) `// Exercises <relative-c-path>:<line>` immediately above the `setFlag` line, at the same indent.

The C index is built per-file. The script restricts matches to candidate C files based on the Java test class name (`TEST_TO_C_FILES` map at the top of the script):

```python
TEST_TO_C_FILES = {
    "RSAOpsTest":            ["rsa.c"],
    "RSAOAEPCipherOpsTest":  ["rsa_oaep.c"],
    "RSAPKCS1CipherOpsTest": ["rsa_pkcs1.c"],
    "MLDSOpsTest":           ["mldsa.c"],
    ...
}
```

Without this scoping, the same `(slot, offset)` pair appears in multiple C files (each numbers its offsets independently from a 1000-block / 2000-block / 3000-block) and the script would link `RSAOpsTest` tests to `slhdsa.c` just because both happen to define `OPS_OPENSSL_ERROR_1` with offset `1000`. The scoping table prevents that.

A fallback heuristic also runs: strip `OpsTest` from the test class name, lowercase, match the resulting basename against indexed C files. If neither resolves, the file is skipped with a printed warning.

## What gets skipped

1. **Tests that assert only an exception type, not a numeric code.** Without an `assertEquals(-N, ...)` inside the method body, there's no offset to look up.
2. **Tests using non-`OPS_OPENSSL_ERROR_*` flags.** `OPS_FAILED_ACCESS_*`, `OPS_INT32_OVERFLOW_*`, `OPS_LEN_CHANGE_*`, `OPS_POINTER_CHANGE` etc. don't have an associated `OPS_OFFSET_*` macro in the C code, so the (slot, offset) index doesn't cover them.
3. **Tests whose candidate C file has no `OPS_OFFSET_OPENSSL_ERROR_*` sites.** Some C files (e.g. `asn1_util.c`, `md.c`, `block_cipher_ctx.c`) return bare `JO_OPENSSL_ERROR` (no offset) for all their OpenSSL failures. Their tests rely on exception-type matching alone; there's nothing for the script to link to. Reported as "skipped" in the script's output.
4. **Ambiguous (slot, offset) pairs.** If two candidate C files for the same test class both define the same `(slot, offset)`, the script reports no match rather than guessing. (In practice this hasn't been observed because the test→C mapping is usually 1:1.)

## Comment format and style

The emitted comment is intentionally minimal — just `// Exercises <path>:<line>`. No function name, no snippet, no extra explanation. Rationale:

1. **Stable under refactor.** A bare `path:line` is the smallest target — the only thing that can go stale is the integer line number, and re-running the script fixes it.
2. **Easy to spot.** All annotations share the same `// Exercises ` prefix — `grep "// Exercises"` enumerates every linked test in seconds.
3. **Non-intrusive.** One line per test, at the same indent as the `setFlag` call it precedes.

If you want richer information (function name, snippet of the if-line), edit the comment manually after the script runs. The script's "update in place" logic compares the full new comment to the previous one — if they differ, it overwrites — so manual additions get clobbered on the next re-run. Keep enrichment outside the auto-generated single-line comment, e.g. in the test's surrounding javadoc.

## Verifying after a C-side edit

After editing C code that shifts line numbers, the comments go stale. Re-run the script to refresh:

```bash
python3 .claude/skills/annotate-ops-tests/scripts/annotate-ops-tests.py \
    jostle/src/test/java/org/openssl/jostle/test
```

Existing `// Exercises ...` lines are updated in place rather than duplicated. Use `git diff` to see which line numbers shifted.

## Maintenance

1. **Adding a new test class.** If you add `FooOpsTest.java` targeting `foo.c`, add an entry to `TEST_TO_C_FILES` near the top of the script. Without it, the script falls back to the basename heuristic (strip `OpsTest`, lowercase, match) which works if the names align, but the explicit map is more reliable.
2. **Adding a new offset slot in C.** Just re-run the script — it rebuilds the index every invocation, so new `OPS_OFFSET_OPENSSL_ERROR_N(offset)` sites get picked up automatically.
3. **Re-running after every C edit.** Cheap (~milliseconds) and idempotent. Worth wiring into a pre-commit check if drift becomes a problem.

## Limitations

1. **Regex-based.** Doesn't parse Java or C. Heavy macros or unusual formatting can confuse the matchers.
2. **Single comment per test.** Each test gets exactly one annotation — the one for the first `setFlag` + first `assertEquals(-N,...)` pair. Tests that drive multiple OPS sites in one method are under-documented; consider splitting them into separate tests.
3. **No support for non-offset OPS sites.** Tests using `OPS_FAILED_ACCESS_*`, `OPS_LEN_CHANGE_*`, etc. aren't auto-linked because there's no `OPS_OFFSET_*` companion in the C code to provide a unique key.
4. **Index-shift handling.** The script iterates test methods in reverse (bottom-up) so insertions don't shift indices for unprocessed methods. If you reorder tests in the file by hand, re-running the script will reposition all annotations correctly.
