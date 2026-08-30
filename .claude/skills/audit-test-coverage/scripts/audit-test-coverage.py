#!/usr/bin/env python3
"""
audit-test-coverage.py — heuristic scan of Jostle's unit-test tree for
two recurring gap classes:

1. **Random-input gaps** — roundtrip tests (sign/verify, encrypt/decrypt,
   MAC, digest, encap/decap, KDF) that supply keys, messages, IVs, or
   salts as hardcoded `byte[]` literals / hex strings / `"...".getBytes()`
   instead of deriving them from a SecureRandom.
2. **Negative-path gaps** — files that contain roundtrip tests for a
   primitive but no accompanying test that proves the operation actually
   transforms its input (tampered ciphertext / tampered message / wrong
   key / distinct inputs → distinct outputs).

The script is intentionally heuristic — it doesn't parse Java. False
positives are easier to dismiss than silent gaps. KAT-style tests that
pin published vectors are NOT meant to be flagged; the script tries to
recognise them by their structure (multiple `Hex.decode("...")` pairs
within a single method).

Usage:
    audit-test-coverage.py [paths ...]

Default scan path: jostle/src/test/java/org/openssl/jostle/test/
relative to CWD, and also java25 variants if present.

Exit code: 0 if no findings, 1 otherwise.
"""

import re
import sys
from pathlib import Path

# ---------------------------------------------------------------
# File-level exclusions: classes whose suffix marks them as
# scoped to a different concern (input validation, fault injection,
# integration ordering).
# ---------------------------------------------------------------
EXCLUDED_SUFFIXES = ("LimitTest.java", "OpsTest.java", "IntegrationTest.java")

# ---------------------------------------------------------------
# Patterns that mark a test method body as a roundtrip / correctness
# check on a security primitive. ANY of these classifies the method
# as a roundtrip candidate.
# ---------------------------------------------------------------
ROUNDTRIP_PATTERNS = [
    # Signature primitives
    (re.compile(r"\.initSign\s*\("), "sign/verify"),
    (re.compile(r"Signature\.getInstance\("), "sign/verify"),
    # Cipher primitives
    (re.compile(r"Cipher\.getInstance\("), "cipher"),
    (re.compile(r"\.doFinal\s*\("), "cipher"),
    # MAC primitives
    (re.compile(r"Mac\.getInstance\("), "mac"),
    # Digest primitives
    (re.compile(r"MessageDigest\.getInstance\("), "digest"),
    (re.compile(r"\.digest\s*\("), "digest"),
    # KEM primitives
    (re.compile(r"KEM\.getInstance\("), "kem"),
    (re.compile(r"\.encapsulate\s*\("), "kem"),
    (re.compile(r"\.decapsulate\s*\("), "kem"),
    # KDF primitives
    (re.compile(r"SecretKeyFactory\.getInstance\("), "kdf"),
    (re.compile(r"\.generateSecret\s*\("), "kdf"),
    # KeyAgreement
    (re.compile(r"KeyAgreement\.getInstance\("), "key-agreement"),
    (re.compile(r"\.generateSecret\s*\(\)"), "key-agreement"),
]

# Patterns indicating the test uses random inputs.
RANDOM_INPUT_PATTERNS = [
    re.compile(r"\.nextBytes\s*\("),
    re.compile(r"\.nextInt\s*\("),
    re.compile(r"\.nextLong\s*\("),
    re.compile(r"KeyGenerator\.getInstance\("),
    re.compile(r"KeyPairGenerator\.getInstance\("),
    re.compile(r"\bseededRandom\s*\("),
    re.compile(r"new\s+SecureRandom\s*\("),
    re.compile(r"\.generateKey\s*\(\)"),
    re.compile(r"\.generateKeyPair\s*\(\)"),
]

# Patterns that indicate hardcoded literal inputs (potential random gap
# when a roundtrip test contains these).
HARDCODED_LITERAL_PATTERNS = [
    # `"foo bar".getBytes()` — a string used as a byte buffer
    re.compile(r"\"[^\"]+\"\s*\.\s*getBytes\s*\("),
    # `Hex.decode("...")` — only flag when there's exactly one or two
    # decode calls in the method (KAT-style tests use many).
    re.compile(r"Hex\.decode\s*\(\s*\"[A-Fa-f0-9]+\"\s*\)"),
    # `new byte[]{0x01, 0x02, ...}` — literal byte arrays
    re.compile(r"new\s+byte\s*\[\s*\]\s*\{"),
]

# Patterns indicating negative-path coverage at the FILE level (any
# match anywhere in the file).
NEGATIVE_PATH_PATTERNS = [
    re.compile(r"\bassertFalse\b[^;]*\b(?:verify|areEqual|equals)\b", re.DOTALL),
    re.compile(r"assertNotEquals\s*\("),
    re.compile(r"\bvandalised\b", re.IGNORECASE),
    re.compile(r"\bvandalized\b", re.IGNORECASE),
    re.compile(r"\btampered\b", re.IGNORECASE),
    re.compile(r"BadPaddingException"),
    re.compile(r"InvalidCipherTextException"),
    re.compile(r"AEADBadTagException"),
    re.compile(r"\[\s*0\s*\]\s*\^="),  # `msg[0] ^= ...` bit flip
    re.compile(r"\bwrongKey\b"),
    re.compile(r"_doesNotRoundTrip"),
    re.compile(r"_doesNotVerify"),
]

# Test-method name patterns whose existence in the file proves the
# file has negative-path coverage for a primitive.
NEGATIVE_TEST_NAME_HINTS = (
    "vandalis", "tampered", "wrongkey", "doesnotroundtrip", "doesnotverify",
    "rejectincorrect", "invalidkey", "differentpeers", "differentkeys",
    "_failedaccess", "_failure", "fails", "nondeterministic",
    "rejects", "_reject",
)

# Skip these specific test methods — they're already meta / setup /
# negative-only / error-path / KAT-by-name.
SKIP_TEST_NAME_HINTS = (
    "before", "beforeall", "beforeeach", "setup", "teardown",
    "reject", "invalid", "fails", "destroy",
    "genfails", "initfails",
    # State-machine error-path tests intentionally use fixed garbage.
    "throws", "withoutinit", "wrongclass", "wrongkey",
    "rejected", "_failure", "failed",
    # KAT-style tests intentionally pin a published vector.
    "vector", "kat", "known", "rfc", "nistsp",
    # Equivalence / structural tests (one-shot vs incremental etc.).
    "alias", "aliasesresolve", "_clone",
    # Empty-input edge cases.
    "empty",
    # Tests of mid-stream / reset / lifecycle behaviour — hardcoded
    # input is fine, output is compared between two parallel computations.
    "midstream", "afterreset", "resetmidstream", "useaftertaking",
)

# If the body catches one of these typed exceptions, it's either an
# error-path test or a test that already includes negative-path
# coverage — skip the random-input flag regardless of literal content.
ERROR_PATH_CATCH_PATTERNS = [
    re.compile(r"catch\s*\(\s*IllegalStateException\b"),
    re.compile(r"catch\s*\(\s*InvalidKeyException\b"),
    re.compile(r"catch\s*\(\s*InvalidAlgorithmParameterException\b"),
    re.compile(r"catch\s*\(\s*UnsupportedOperationException\b"),
    re.compile(r"catch\s*\(\s*ProviderException\b"),
    re.compile(r"catch\s*\(\s*ClassCastException\b"),
    re.compile(r"catch\s*\(\s*CloneNotSupportedException\b"),
    re.compile(r"catch\s*\(\s*DigestException\b"),
    re.compile(r"catch\s*\(\s*ShortBufferException\b"),
    # Crypto-specific failure modes — when the test catches these, it's
    # a negative-path test that uses fixed inputs deliberately.
    re.compile(r"catch\s*\(\s*BadPaddingException\b"),
    re.compile(r"catch\s*\(\s*AEADBadTagException\b"),
    re.compile(r"catch\s*\(\s*InvalidCipherTextException\b"),
    re.compile(r"catch\s*\(\s*IllegalBlockSizeException\b"),
    re.compile(r"assertThrows\s*\(\s*IllegalStateException"),
    re.compile(r"assertThrows\s*\(\s*InvalidKeyException"),
    re.compile(r"assertThrows\s*\(\s*UnsupportedOperationException"),
    re.compile(r"assertThrows\s*\(\s*BadPaddingException"),
    re.compile(r"assertThrows\s*\(\s*AEADBadTagException"),
    re.compile(r"assertThrows\s*\(\s*InvalidCipherTextException"),
]

# If the body contains assertions against a hardcoded hex/byte expected
# output, treat the test as KAT-style and don't flag.
KAT_ASSERTION_PATTERNS = [
    # assertArrayEquals(Hex.decode("..."), ...) — comparing against a
    # pinned expected output.
    re.compile(r"assertArrayEquals\s*\(\s*Hex\.decode\s*\("),
    re.compile(r"assertEquals\s*\(\s*[^)]*Hex\.decode\s*\("),
    # `expected` / `expectedCt` / `expectedHex` style variables paired
    # with comparison.
    re.compile(r"assertArrayEquals\s*\(\s*expected\w*\s*,"),
    # `Hex.toHexString(...)` compared to a string literal — also KAT.
    re.compile(r"assertEquals\s*\(\s*\"[A-Fa-f0-9]{16,}\"\s*,\s*Hex\.toHexString"),
]


# ---------------------------------------------------------------
# Java method extraction. Crude but robust enough for this codebase:
# find lines starting with `@Test`, then collect everything up to the
# matching closing `}` at method indent.
# ---------------------------------------------------------------
TEST_ANNOTATION_RE = re.compile(r"^\s*@Test\b")
METHOD_DECL_RE = re.compile(r"(?:public|protected|private)?\s*(?:static\s+)?\S+\s+(\w+)\s*\([^)]*\)\s*(?:throws\s+[^{]+)?\{")
METHOD_END_RE = re.compile(r"^    \}\s*$")  # closing brace at method indent


def find_test_methods(lines):
    """Yield (name, start_idx, end_idx, body_text) for each @Test method."""
    i = 0
    while i < len(lines):
        if TEST_ANNOTATION_RE.match(lines[i]):
            # Skip any further annotations and javadoc.
            j = i + 1
            while j < len(lines):
                stripped = lines[j].strip()
                if (not stripped) or stripped.startswith("//") or stripped.startswith("@") or stripped.startswith("*") or stripped.startswith("/*"):
                    j += 1
                    continue
                break
            if j >= len(lines):
                return
            # Collect the method signature (might span lines).
            sig_buf = []
            while j < len(lines):
                sig_buf.append(lines[j])
                if "{" in lines[j]:
                    break
                j += 1
            sig = " ".join(sig_buf)
            m = METHOD_DECL_RE.search(sig)
            if not m:
                i += 1
                continue
            name = m.group(1)
            body_start = j + 1
            k = body_start
            while k < len(lines) and not METHOD_END_RE.match(lines[k]):
                k += 1
            body = "\n".join(lines[body_start:k])
            yield (name, i, k, body)
            i = k + 1
        else:
            i += 1


def classify_roundtrip(body):
    """Return the set of roundtrip primitives appearing in `body`."""
    prims = set()
    for pat, label in ROUNDTRIP_PATTERNS:
        if pat.search(body):
            prims.add(label)
    return prims


def has_random_inputs(body):
    """True if the method body shows any sign of random input derivation."""
    return any(p.search(body) for p in RANDOM_INPUT_PATTERNS)


def has_hardcoded_input(body):
    """True if the method body contains hardcoded literal patterns suggestive
    of a hardcoded key / message / IV. Filters out KAT-style methods that
    have many Hex.decode pairs (≥4)."""
    hex_decodes = len(re.findall(r"Hex\.decode\s*\(", body))
    if hex_decodes >= 4:
        # KAT-style — multiple paired vectors. Don't flag.
        return False
    # `"...".getBytes()` is a strong signal regardless of context.
    if re.search(r"\"[^\"]+\"\s*\.\s*getBytes\s*\(", body):
        return True
    # `new byte[]{...}` with explicit values inside (not just `new byte[N]`).
    if re.search(r"new\s+byte\s*\[\s*\]\s*\{[^{}]*\d+", body):
        return True
    # 1-3 Hex.decode calls plus no random source nearby — likely a hardcoded
    # key/message pair.
    if 1 <= hex_decodes <= 3 and not has_random_inputs(body):
        return True
    return False


def file_has_negative_coverage(text, primitive):
    """Coarse file-level check: does the file as a whole prove the primitive
    actually transforms its inputs?

    `primitive` is one of the labels produced by ROUNDTRIP_PATTERNS.
    """
    # Any global negative-path pattern.
    for p in NEGATIVE_PATH_PATTERNS:
        if p.search(text):
            return True
    # Any test method whose name hints at negative-path purpose.
    lower = text.lower()
    for hint in NEGATIVE_TEST_NAME_HINTS:
        if hint in lower:
            return True
    return False


def should_skip_test_name(name):
    lower = name.lower()
    for h in SKIP_TEST_NAME_HINTS:
        if h.lower() in lower:
            return True
    return False


def is_error_path_test(body):
    """True if the test body catches an error-path exception type or uses
    assertThrows on one — error-path tests intentionally use fixed garbage
    inputs."""
    return any(p.search(body) for p in ERROR_PATH_CATCH_PATTERNS)


def is_kat_style(body):
    """True if the body contains assertions against a hardcoded expected
    output (Hex.decode in assert, or comparison to a long hex literal)."""
    return any(p.search(body) for p in KAT_ASSERTION_PATTERNS)


# --- MT-7 shapes: assertions that cannot fire ---------------------------------
#
# Both shapes are green-by-default: the test passes whether or not the property
# holds. Measured across the tree 2026-08-30 — 106 raw candidates, of which 79
# were NOT defects — so each shape is keyed on what the call can DO, never on a
# site list. An allowlist of sites would need maintaining and would go stale;
# these rules stay correct for code written tomorrow.

# Calls that THROW on failure and can also return a WRONG-but-non-null result.
# assertNotNull on one of these asserts nothing while the operation may have
# produced garbage — the shape that let a KTS wrap test assert only that wrap()
# returned something.
VACUOUS_NOTNULL_CALLEES = (
    "generateKeyPair", "generatePublic", "generatePrivate", "generateSecret",
    "generateKey", "unwrap", "wrap", "doFinal", "translateKey",
)

# Calls that THROW on failure and CANNOT return a wrong answer: the returned
# object either resolves or the call throws. assertNotNull on these is
# redundant, not vacuous — the test still fails when the property is false — so
# it is deliberately NOT flagged. 61 such sites exist and deleting them would
# be churn that buries the real findings.
REDUNDANT_NOTNULL_CALLEES = (
    "getInstance",
)

VACUOUS_NOTNULL_RE = re.compile(
    r"assertNotNull\s*\(([^;]*)", re.S
)

# A catch block that names a broad type and never inspects what it caught. The
# legitimate form is the offset-write contract's shifted-window negative, where
# ANY failure confirms the property — those methods are recognised by name
# rather than exempted individually, and each carries its own positive control
# asserting the UNSHIFTED window round-trips (e.g.
# FIPSDSALimitTest.sign_writesAtOffsetWithoutClobberingPrefix step (2), which
# requires JO_SUCCESS), so "any exception confirms it" cannot pass against a
# bridge that throws on everything.
SWALLOWED_CATCH_RE = re.compile(
    r"catch\s*\(\s*(?:Exception|Throwable)\s+(\w+)\s*\)\s*\{(.*?)\n\s*\}", re.S
)
SHIFTED_WINDOW_HINTS = ("shifted", "writesatoffset", "clobber")


def _enclosing_method_body(lines, idx):
    """The body of the method containing line index `idx`, as one string."""
    start = 0
    for k in range(idx, -1, -1):
        t = lines[k].strip()
        if t.startswith(("public ", "private ", "protected ", "void ", "static ")) and "(" in t:
            start = k
            break
    end = start
    for k in range(start, min(len(lines), start + 200)):
        if METHOD_END_RE.match(lines[k]):
            end = k
            break
    return "\n".join(lines[start:end])


def vacuous_notnull_sites(lines):
    """Yield (line_no, callee) for assertNotNull on a can-return-wrong call.

    Suppressed when the enclosing method asserts something ELSE: the non-null
    is then incidental to a property the test does check, which was true of 14
    of the 25 vacuous-shaped sites measured 2026-08-30. Keying on "does this
    method assert anything else" is a semantic rule, like the callee rule
    above — not a list of sites that would go stale.
    """
    for i, line in enumerate(lines):
        if "assertNotNull" not in line:
            continue
        expr = line
        if i + 1 < len(lines) and line.rstrip().endswith(("(", ",")):
            expr += " " + lines[i + 1].strip()
        if any(c + "(" in expr for c in REDUNDANT_NOTNULL_CALLEES):
            continue
        for callee in VACUOUS_NOTNULL_CALLEES:
            if callee + "(" in expr:
                body = _enclosing_method_body(lines, i)
                others = len(re.findall(r"\bassert\w+\s*\(", body)) \
                    - len(re.findall(r"\bassertNotNull\s*\(", body))
                if others == 0:
                    yield (i + 1, callee)
                break


def swallowed_catch_sites(text, lines):
    """Yield (line_no,) for a broad catch that inspects nothing, excluding the
    shifted-window negative where any failure legitimately confirms."""
    for m in SWALLOWED_CATCH_RE.finditer(text):
        var, body = m.group(1), m.group(2)
        if var in body or "fail" in body or "assert" in body.lower():
            continue
        # A catch whose whole body RETURNS a sentinel is PROPAGATING the
        # failure to its caller, not eating it — the caller then null-checks or
        # compares the error code. Same reasoning as the shifted-window
        # exclusion (`return ErrorCode.JO_FAIL.getCode()`), and it covers the
        # `return null` probe helpers whose callers do `if (x == null) continue`
        # inside a floored loop.
        if re.fullmatch(r"\s*return\s+[^;]+;\s*", body):
            continue
        lineno = text[:m.start()].count("\n") + 1
        context = "\n".join(lines[max(0, lineno - 30):lineno]).lower()
        if any(h in context for h in SHIFTED_WINDOW_HINTS):
            continue
        # A loop that skips on failure is safe when the method asserts a
        # NON-VACUITY FLOOR: some counter is incremented per successful
        # iteration and asserted at the end, so an all-skipped run fails.
        # This is the difference between the sibling loops in ECCurveTableTest
        # (which carry `generated >= MIN_CURVES_RESOLVED` and `checked > 0`)
        # and FIPSECCurveTableTest.bothProvidersDescribeACurveIdentically,
        # which carried none and could pass having compared nothing.
        body = _enclosing_method_body(lines, lineno - 1)
        counters = set(re.findall(r"\b(\w+)\s*\+\+", body))
        floored = any(re.search(r"\bassert\w+\s*\([^;]*\b%s\b" % re.escape(c), body)
                      for c in counters)
        if floored:
            continue
        yield (lineno,)


def scan_file(path):
    """Yield findings for one file.

    Findings are tuples (kind, test_name, line_no, detail) where kind is
    one of "RANDOM" or "NEGATIVE".
    """
    try:
        text = path.read_text()
    except (OSError, UnicodeDecodeError):
        return
    lines = text.splitlines()

    primitives_in_file = set()
    random_gaps = []
    test_methods = list(find_test_methods(lines))

    for name, start, end, body in test_methods:
        if should_skip_test_name(name):
            continue
        prims = classify_roundtrip(body)
        if not prims:
            continue
        primitives_in_file.update(prims)

        # Skip error-path / KAT-style tests — those intentionally use
        # fixed inputs and aren't gaps.
        if is_error_path_test(body):
            continue
        if is_kat_style(body):
            continue

        # Random-input gap: roundtrip + hardcoded literal AND
        # (a) no SecureRandom anywhere in the body OR
        # (b) SecureRandom present for the key but a hardcoded message
        #     literal still appears (e.g. `"foo".getBytes()`).
        # We use `"..".getBytes()` as the strongest signal of "the test
        # author baked a literal message into a randomized-key test" —
        # this catches the MEDIUM finding pattern we saw in the audits.
        has_string_getBytes = bool(re.search(r"\"[^\"]+\"\s*\.\s*getBytes\s*\(", body))
        if has_string_getBytes:
            random_gaps.append((name, start + 1, sorted(prims)))
            continue
        if has_hardcoded_input(body) and not has_random_inputs(body):
            random_gaps.append((name, start + 1, sorted(prims)))

    # File-level negative-path check, per primitive.
    negative_gaps = []
    for prim in sorted(primitives_in_file):
        if not file_has_negative_coverage(text, prim):
            negative_gaps.append(prim)

    for name, lineno, prims in random_gaps:
        yield ("RANDOM", name, lineno, ", ".join(prims))
    for prim in negative_gaps:
        yield ("NEGATIVE", None, None, prim)
    for lineno, callee in vacuous_notnull_sites(lines):
        yield ("VACUOUS", None, lineno,
               "assertNotNull on %s() — it throws on failure, so this asserts "
               "nothing while a wrong result passes" % callee)
    for (lineno,) in swallowed_catch_sites(text, lines):
        yield ("SWALLOWED", None, lineno,
               "catch of a broad type that inspects nothing — a state error "
               "here would be eaten and the test would go dead silently")


def main(argv):
    args = argv[1:]
    if args:
        roots = [Path(p) for p in args]
    else:
        roots = [
            Path("jostle/src/test/java/org/openssl/jostle/test"),
            Path("jostle/src/test/java25/org/openssl/jostle/test"),
        ]
        roots = [r for r in roots if r.is_dir()]
        if not roots:
            print("usage: audit-test-coverage.py [paths ...]", file=sys.stderr)
            print("default paths not found from CWD", file=sys.stderr)
            return 2

    targets = []
    for r in roots:
        if r.is_file() and r.suffix == ".java":
            targets.append(r)
            continue
        if r.is_dir():
            for jf in sorted(r.rglob("*Test.java")):
                if any(jf.name.endswith(suf) for suf in EXCLUDED_SUFFIXES):
                    continue
                targets.append(jf)

    if not targets:
        print("no *Test.java files matched (after excluding Limit/Ops/Integration)", file=sys.stderr)
        return 2

    total_random = 0
    total_negative = 0
    total_assertion = 0
    findings_by_file = {}
    for t in targets:
        findings = list(scan_file(t))
        if findings:
            findings_by_file[t] = findings
            for kind, _, _, _ in findings:
                if kind == "RANDOM":
                    total_random += 1
                elif kind in ("VACUOUS", "SWALLOWED"):
                    total_assertion += 1
                else:
                    total_negative += 1

    if not findings_by_file:
        print(f"scanned {len(targets)} file(s); no random-input, negative-path or "
              f"cannot-fire-assertion gaps found")
        return 0

    print(f"scanned {len(targets)} file(s); {total_random} random-input gap(s), "
          f"{total_negative} negative-path gap(s) and {total_assertion} "
          f"cannot-fire assertion(s) in {len(findings_by_file)} file(s):\n")
    for path in sorted(findings_by_file):
        print(f"== {path}")
        for kind, name, lineno, detail in findings_by_file[path]:
            if kind == "VACUOUS":
                print(f"  VACUOUS  {path}:{lineno}")
                print(f"    {detail}")
                continue
            if kind == "SWALLOWED":
                print(f"  SWALLOW  {path}:{lineno}")
                print(f"    {detail}")
                continue
            if kind == "RANDOM":
                print(f"  RANDOM   {path}:{lineno}  {name}  [{detail}]")
                print(f"    test body contains hardcoded literal AND no SecureRandom/KeyGenerator")
            else:
                print(f"  NEGATIVE {path}  primitive: {detail}")
                print(f"    file has roundtrip(s) for this primitive but no obvious negative-path coverage")
        print()

    print("Triage:")
    print("  RANDOM   findings: tests likely use a hardcoded key / message / IV.")
    print("           Fix: derive each input from a SecureRandom (nextBytes / KeyGenerator).")
    print("           False positives: KAT tests that pin a published vector — exempt.")
    print("  VACUOUS  findings: assertNotNull on a call that THROWS on failure and can")
    print("           return a WRONG result — the assertion cannot fail while the")
    print("           property is false. Fix: assert the property (round-trip,")
    print("           re-encode equality, expected value).")
    print("           NOT flagged: getInstance and kin, where the throw IS the assertion.")
    print("  SWALLOW  findings: a broad catch that never inspects what it caught, so a")
    print("           state error is eaten and the test can go dead silently. Fix: catch")
    print("           the narrow type, or count iterations and assert a non-vacuity floor.")
    print("           NOT flagged: the offset-write shifted-window negative, where ANY")
    print("           failure legitimately confirms and a positive control asserts the")
    print("           unshifted window round-trips.")
    print("  NEGATIVE findings: file's roundtrip primitive has no obvious tamper / wrong-key /")
    print("           distinct-input differentiator. Fix: add at least one test that proves")
    print("           the operation actually transforms input. KAT vectors alone don't count.")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
