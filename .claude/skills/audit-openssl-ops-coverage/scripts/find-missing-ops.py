#!/usr/bin/env python3
"""
find-missing-ops.py — scan Jostle C sources for OpenSSL function calls
whose return values are checked in an if-statement but lack an OPS_*
fault-injection macro on the check.

A "missing OPS" finding looks like one of these patterns where the
if-statement has no `OPS_*` macro prefixing the condition:

    if (1 != EVP_X_op(...)) { ... }
    if (X == NULL) { ... }       (when X was just assigned an OpenSSL result)
    if (NULL == EVP_X_alloc(...)) { ... }

The script intentionally over-reports. False positives are easier to
dismiss than silent gaps. Suppress a finding by either:
  - adding an OPS macro to the check (the recommended fix), or
  - adding the function name to NEVER_FAILS below if it truly can't fail.

Usage:
    find-missing-ops.py [paths ...]

Default scan path: interface/util/*.c relative to CWD.
Exit code: 0 if no findings, 1 otherwise.
"""

import re
import sys
from pathlib import Path

# OpenSSL function-name prefixes worth auditing. Anything matching one
# of these prefixes is considered an "OpenSSL function" for the purpose
# of OPS-coverage checks.
OPENSSL_PREFIXES = (
    "EVP_",
    "OSSL_",
    "BN_",
    "RSA_",
    "DH_",
    "DSA_",
    "EC_",
    "ECDSA_",
    "ECDH_",
    "RAND_",
    "PEM_",
    "ASN1_",
    "X509_",
    "PKCS5_",
    "PKCS7_",
    "PKCS8_",
    "PKCS12_",
    "i2d_",
    "d2i_",
)

# Functions that never fail (cleanup, getters that return void or
# always succeed). Add to this set rather than letting them pollute
# the findings.
NEVER_FAILS = {
    # Cleanup / free
    "EVP_PKEY_free", "EVP_PKEY_CTX_free", "EVP_MD_CTX_free",
    "EVP_CIPHER_free", "EVP_CIPHER_CTX_free",
    "EVP_MAC_CTX_free", "EVP_MAC_free",
    "EVP_KDF_free", "EVP_KDF_CTX_free",
    "EVP_RAND_free", "EVP_RAND_CTX_free",
    "EVP_KEM_free", "EVP_KEM_CTX_free",
    "EVP_SIGNATURE_free", "EVP_SIGNATURE_CTX_free",
    "EVP_ASYM_CIPHER_free", "EVP_ASYM_CIPHER_CTX_free",
    "BN_free", "BN_clear_free",
    "OSSL_PARAM_free", "OSSL_PARAM_BLD_free",
    "OPENSSL_free", "OPENSSL_clear_free",
    "EC_GROUP_free", "EC_KEY_free", "EC_POINT_free",
    "X509_free",
    # Infallible getters / accessors
    "EVP_PKEY_get_id", "EVP_PKEY_get0_type_name", "EVP_PKEY_size",
    "EVP_PKEY_get_size",
    "EVP_MD_size", "EVP_MD_block_size",
    "EVP_CIPHER_block_size", "EVP_CIPHER_iv_length",
    "EVP_CIPHER_CTX_block_size", "EVP_CIPHER_CTX_iv_length",
    "EVP_CIPHER_CTX_get_block_size", "EVP_CIPHER_CTX_get_iv_length",
    "EVP_MD_CTX_get0_md", "EVP_PKEY_get0_RSA",
    "BN_num_bytes", "BN_num_bits", "BN_is_zero", "BN_is_one", "BN_cmp",
    "BN_is_odd", "BN_is_negative", "BN_is_word",
    # Type discriminators — return a yes/no answer, not an error.
    "EVP_PKEY_is_a", "EVP_MD_xof", "EVP_MD_is_a",
    "EVP_CIPHER_is_a", "EVP_KDF_is_a", "EVP_MAC_is_a",
    "EVP_SIGNATURE_is_a", "EVP_KEM_is_a", "EVP_RAND_is_a",
    "EVP_ASYM_CIPHER_is_a",
    # ERR queue management
    "ERR_clear_error", "ERR_set_mark", "ERR_pop_to_mark",
    "ERR_clear_last_mark", "ERR_get_error", "ERR_peek_error",
    "ERR_peek_last_error",
    # Allocation that asserts via jo_assert on caller
    "OPENSSL_zalloc", "OPENSSL_malloc",
}


def find_openssl_calls(text):
    """Return the set of unique OpenSSL function names called in `text`."""
    funcs = set()
    # Match a bare function call: identifier immediately followed by '('.
    for m in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", text):
        name = m.group(1)
        if any(name.startswith(p) for p in OPENSSL_PREFIXES):
            funcs.add(name)
    return funcs


def collect_if_condition(lines, start_line_idx):
    """Collect a (possibly multi-line) if-statement condition.

    `start_line_idx` should be the index of a line beginning with whitespace +
    `if (`. Returns (condition_text, end_line_idx) where condition_text is the
    interior of the outermost if(...) parens, and end_line_idx is the line
    holding the closing paren.
    """
    line = lines[start_line_idx]
    m = re.search(r"\bif\s*\(", line)
    if not m:
        return None
    depth = 1
    out = []
    line_idx = start_line_idx
    char_idx = m.end()
    while line_idx < len(lines):
        cur = lines[line_idx]
        while char_idx < len(cur):
            ch = cur[char_idx]
            if ch == "(":
                depth += 1
                out.append(ch)
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    return ("".join(out), line_idx)
                out.append(ch)
            else:
                out.append(ch)
            char_idx += 1
        out.append("\n")
        line_idx += 1
        char_idx = 0
    return ("".join(out), line_idx - 1)


def previous_nonblank_noncomment(lines, idx):
    """Return (line_index, stripped_line) for the line above idx that is
    non-blank and not a pure comment line. Returns (None, None) if none."""
    i = idx - 1
    while i >= 0:
        s = lines[i].strip()
        if s and not s.startswith("//") and not s.startswith("/*") and not s.startswith("*"):
            return (i, s)
        i -= 1
    return (None, None)


def scan_file(path):
    """Yield (path, line_no, funcs, snippet) for each missing-OPS finding."""
    try:
        text = path.read_text()
    except (OSError, UnicodeDecodeError):
        return
    lines = text.splitlines()

    i = 0
    while i < len(lines):
        line = lines[i]
        # Match an `if (` at the start of a (potentially indented) line.
        if re.match(r"\s*if\s*\(", line):
            collected = collect_if_condition(lines, i)
            if collected is None:
                i += 1
                continue
            cond, end_idx = collected

            # Skip the entire if-condition span on the next iteration.
            next_i = end_idx + 1

            funcs_in_cond = find_openssl_calls(cond)
            funcs_to_audit = set()
            reason = None

            if funcs_in_cond:
                # Direct OpenSSL call in the if-condition.
                funcs_to_audit = funcs_in_cond
                reason = "direct"
            else:
                # Check whether the previous non-blank line was an
                # assignment from an OpenSSL function (pattern: assign
                # then check on next line).
                prev_idx, prev_line = previous_nonblank_noncomment(lines, i)
                if prev_line is not None:
                    prev_calls = find_openssl_calls(prev_line)
                    if prev_calls:
                        # Heuristic: only flag when the if-condition
                        # looks like a result check on the assigned
                        # variable (== NULL, != NULL, == 0, etc.) or
                        # an int-overflow guard on a returned size_t.
                        if re.search(r"(==|!=|<|>|>=|<=)\s*(NULL|0|INT_MAX|INT32_MAX)", cond):
                            funcs_to_audit = prev_calls
                            reason = "preceding-assignment"

            if funcs_to_audit:
                # Filter out functions that can never fail.
                funcs_to_audit = {f for f in funcs_to_audit if f not in NEVER_FAILS}
            if funcs_to_audit:
                # Look for an OPS_* macro anywhere in the condition.
                # If present, the call is instrumented — don't flag.
                if not re.search(r"\bOPS_\w+", cond):
                    snippet = cond.replace("\n", " ").strip()
                    snippet = re.sub(r"\s+", " ", snippet)
                    if len(snippet) > 90:
                        snippet = snippet[:87] + "..."
                    yield (path, i + 1, sorted(funcs_to_audit), snippet, reason)

            i = next_i
        else:
            i += 1


def main(argv):
    paths = [Path(p) for p in argv[1:]]
    if not paths:
        default = Path("interface/util")
        if default.is_dir():
            paths = [default]
        else:
            print("usage: find-missing-ops.py [paths ...]", file=sys.stderr)
            print("default path interface/util/ not found from CWD", file=sys.stderr)
            return 2

    targets = []
    for p in paths:
        if p.is_dir():
            targets.extend(sorted(p.glob("*.c")))
        elif p.is_file() and p.suffix == ".c":
            targets.append(p)

    if not targets:
        print("no .c files matched", file=sys.stderr)
        return 2

    findings = []
    for t in targets:
        findings.extend(scan_file(t))

    if not findings:
        print(f"scanned {len(targets)} file(s); no missing OPS instrumentation found")
        return 0

    # Group by file for readability.
    by_file = {}
    for f in findings:
        by_file.setdefault(f[0], []).append(f)

    print(f"scanned {len(targets)} file(s); {len(findings)} potentially uninstrumented OpenSSL "
          f"call check(s) in {len(by_file)} file(s):\n")
    for fpath in sorted(by_file):
        print(f"== {fpath}")
        for _, lineno, funcs, snippet, reason in by_file[fpath]:
            tag = "direct" if reason == "direct" else "after-assign"
            print(f"  {fpath}:{lineno}  [{tag}]  {', '.join(funcs)}")
            print(f"    if ({snippet})")
        print()
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
