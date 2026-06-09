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
    findings_by_file = {}
    for t in targets:
        findings = list(scan_file(t))
        if findings:
            findings_by_file[t] = findings
            for kind, _, _, _ in findings:
                if kind == "RANDOM":
                    total_random += 1
                else:
                    total_negative += 1

    if not findings_by_file:
        print(f"scanned {len(targets)} file(s); no random-input or negative-path gaps found")
        return 0

    print(f"scanned {len(targets)} file(s); {total_random} random-input gap(s) and "
          f"{total_negative} negative-path gap(s) in {len(findings_by_file)} file(s):\n")
    for path in sorted(findings_by_file):
        print(f"== {path}")
        for kind, name, lineno, detail in findings_by_file[path]:
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
    print("  NEGATIVE findings: file's roundtrip primitive has no obvious tamper / wrong-key /")
    print("           distinct-input differentiator. Fix: add at least one test that proves")
    print("           the operation actually transforms input. KAT vectors alone don't count.")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
