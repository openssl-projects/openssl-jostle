---
name: audit-error-branch-coverage
description: Map every instrumented (OPS_*) and typed (JO_*) error-handling branch in Jostle's C trees to concrete test evidence — errorAt offsets, raw-code literals, JO_* constant references, and `// Exercises` anchors — and report orphaned branches no test drives. Use this skill whenever the user wants to verify error-path test coverage — including phrases like "are all the error handling blocks tested", "which error branches have no test", "audit error branch coverage", "find untested OPS sites", "is every typed error code covered by a limit or ops test", "orphaned error branches", and similar. Complements audit-openssl-ops-coverage / audit-jni-ops-coverage (which find UNinstrumented checks): this skill finds instrumented-but-untested ones. Run before declaring a C change done, after adding error codes, and after review-application sweeps.
---

# Audit error-branch test coverage

`audit-openssl-ops-coverage` and `audit-jni-ops-coverage` find fallible calls with **no OPS instrumentation**. This skill answers the complementary question: for every branch that IS instrumented (an `OPS_*` fault-injection site) or returns a typed `JO_*` code, does anything in the Java test tree actually drive it? An instrumented-but-untested site passes every audit that only looks at the C, yet is one refactor away from silently regressing — the 2026-07-12 review application found exactly two such orphans (`rsa_pkcs1.c`'s implicit-rejection `set_params` site and `rand.c`'s `enable_locking` site), both discovered only by a manual audit this skill mechanizes.

## When to use this skill

1. "are all the error handling blocks tested?" / "audit error branch coverage"
2. After adding a new `JO_*` code or OPS site — verify the paired test landed.
3. Before declaring a C change done (the test-side half of the OPS-coverage audits).
4. After a multi-agent test-writing sweep — agents die mid-run; this catches what they dropped.

## How to run

```bash
# Scan the whole nonfips tree (default; the fips tree is a twin — same offsets).
python3 .claude/skills/audit-error-branch-coverage/scripts/find-untested-branches.py

# Scan one file or directory.
python3 .claude/skills/audit-error-branch-coverage/scripts/find-untested-branches.py interface/nonfips/util/dh.c
```

Exit code 0 when every branch has evidence, 1 when at least one orphan is found.

## What counts as evidence

The script indexes the whole test tree (`src/test/java` + `src/test/java25`) for four evidence forms, then marks a C site covered if ANY matches:

1. **`errorAt(<offset>)`** — the OPS-test convention for offset sites; also the `JO_OPENSSL_ERROR - <offset>` arithmetic form.
2. **Raw-code literals** — `assertEquals(-2113, ...)` style; the script computes each site's expected raw code(s) as `JO base value + (-offset)`, resolving `return base OPS_OFFSET_*(n)` ternaries by scanning the preceding lines for candidate `JO_*` names.
3. **`JO_*` constant names** anywhere in the test tree (`ErrorCode.JO_X`, local `private static final int JO_X = ...` mirrors).
4. **`// Exercises <path>:<line>` anchors**, matched tree-agnostically (`interface/<tree>/` stripped, so a FIPS test anchors the nonfips twin too) with a ±3-line drift window.

## Interpreting findings

An orphan means one of three things — adjudicate each:

1. **Missing test** — the branch has never been driven. Write the Limit/OPS test per the testing.md rules (pin the exact message; add the Exercises comment). This is the defect class the skill exists for.
2. **Test exists but is unlinked** — common for `OPS_FAILED_ACCESS_*` sites, whose tests assert `AccessException` messages without numeric codes and which the annotate-ops-tests skill cannot auto-anchor. Fix by adding the `// Exercises <path>:<line>` comment to the existing test — the linkage is required by testing.md anyway, so this is a real (if smaller) gap, not a false positive.
3. **Deliberately untested defensive branch** — e.g. plain checks in functions with no OPS instrumentation at all, or `OSSL_PARAM_set_*` failure returns that no configuration can trigger. Leave them, but say so in the report; if one recurs noisily, extend the script's `IGNORE_CODES`.

The evidence matching is deliberately loose (a raw literal or JO name anywhere in the test tree counts), so a "covered" verdict is weaker than an "orphan" verdict — the tool is a gap-finder, not a coverage certifier. For load-bearing branches, confirm the matched test pins the exact type + message per the "Pin the exception message" rule.

## Known baseline

As of 2026-07-12 the scan reports ~24 orphans, all in class (2) above — pre-existing `OPS_FAILED_ACCESS_*` tests missing Exercises anchors (kdf, ed, ks, asn1, rand_upcall JNI glue). Burning that list down is safe incremental work; anything NEW appearing above that baseline is a regression in test discipline.
