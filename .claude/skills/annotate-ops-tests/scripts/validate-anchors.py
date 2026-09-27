#!/usr/bin/env python3
"""Validate every `// Exercises <path>:<line>` anchor against its C target.

Stronger than anchor_remap.py's in-range check: for each anchor that sits
directly above a `setFlag(OPS_X)` call, the referenced C line MUST contain
the bare flag `OPS_X` (the if-line the anchor names), not a comment, blank,
brace, or the OPS_OFFSET return line. Catches the doc-rot where earlier C
edits shifted lines and left anchors pointing at the wrong place.

Usage:
  python3 validate-anchors.py            # report stale anchors, exit 1 if any
  python3 validate-anchors.py --fix      # rewrite each stale anchor to the
                                         # nearest bare-flag occurrence, then
                                         # re-validate

--fix disambiguates multi-site flags by nearest-line, which is only right when
the drift is small. For OPS_OPENSSL_ERROR_* anchors run annotate-ops-tests.py
FIRST: it keys on the asserted offset, and nearest-line was measured choosing the
wrong site after shifts of a few hundred lines. Always re-run without --fix (and
the audit + compile) after fixing.

A flag counts only in C CODE. A flag named inside a // or /* */ comment (or a string) is
neither accepted as an anchor target nor chosen by --fix: a comment such as
"// Reuses OPS_OPENSSL_ERROR_5 / _6" above the real if-line otherwise passes
validation and attracts nearest-line fixes. `--self-check` runs the comment
stripper against fixed cases and exits non-zero on any mismatch.
"""

import os
import re
import sys

ANCHOR = re.compile(r'(//\s*Exercises\s+)(\S+?):(\d+)')
SETFLAG = re.compile(r'setFlag\(OperationsTestNI\.OpsTestFlag\.(OPS_[A-Z_0-9]+)\)')
OFFSET = re.compile(r'OPS_OFFSET_[A-Z_0-9]+\([^)]*\)')
TEST_ROOTS = ["jostle/src/test/java", "jostle/src/test/java25"]
WINDOW = 4  # setFlag may sit up to this many lines below the anchor

_cache = {}


def strip_comments(lines):
    """Return the lines with // and /* */ comments and string contents blanked, keeping the line count."""
    out = []
    in_block = False
    for line in lines:
        buf = []
        i = 0
        in_str = None
        while i < len(line):
            c = line[i]
            nxt = line[i + 1] if i + 1 < len(line) else ""
            if in_block:
                if c == "*" and nxt == "/":
                    in_block = False
                    i += 2
                else:
                    i += 1
                continue
            if in_str:
                # String contents are not code either; only the closing quote is kept.
                if c == "\\" and nxt:
                    i += 2
                    continue
                if c == in_str:
                    buf.append(c)
                    in_str = None
                i += 1
                continue
            if c in "\"'":
                in_str = c
                buf.append(c)
                i += 1
                continue
            if c == "/" and nxt == "/":
                break
            if c == "/" and nxt == "*":
                in_block = True
                i += 2
                continue
            buf.append(c)
            i += 1
        out.append("".join(buf))
    return out


def clines(path):
    if path not in _cache:
        try:
            _cache[path] = strip_comments(open(path, errors="replace").read().splitlines())
        except OSError:
            _cache[path] = None
    return _cache[path]


def self_check():
    cases = [
        (["    // Reuses OPS_OPENSSL_ERROR_5 / _6.", "    if (OPS_OPENSSL_ERROR_5 x == NULL) {"],
         "OPS_OPENSSL_ERROR_5", [2]),
        (["/* OPS_FAILED_INIT_1 is", "   reused here */", "if (OPS_FAILED_INIT_1 1 != f()) {"],
         "OPS_FAILED_INIT_1", [3]),
        (["if (OPS_LEN_CHANGE_1 a) { /* OPS_LEN_CHANGE_1 */ }", "s = \"// OPS_LEN_CHANGE_1\";"],
         "OPS_LEN_CHANGE_1", [1]),
        (["x = 1; /* start", " OPS_INT32_OVERFLOW_1 */ if (OPS_INT32_OVERFLOW_1 y) {"],
         "OPS_INT32_OVERFLOW_1", [2]),
    ]
    bad = 0
    for lines, flag, want in cases:
        code = strip_comments(lines)
        got = [i + 1 for i, line in enumerate(code) if re.search(rf"\b{flag}\b", OFFSET.sub("", line))]
        if got != want:
            bad += 1
            print(f"SELF-CHECK FAILED: {lines!r} {flag}: got {got}, want {want}")
    print(f"self-check: {len(cases) - bad}/{len(cases)} passed")
    return 1 if bad else 0


def line_has_flag(path, ln, flag):
    L = clines(path)
    if L is None or ln < 1 or ln > len(L):
        return False
    return re.search(rf"\b{re.escape(flag)}\b", OFFSET.sub("", L[ln - 1])) is not None


def bare_flag_lines(path, flag):
    L = clines(path)
    if L is None:
        return []
    pat = re.compile(rf"\b{re.escape(flag)}\b")
    return [i + 1 for i, line in enumerate(L) if pat.search(OFFSET.sub("", line))]


def iter_anchors():
    for root in TEST_ROOTS:
        for dp, _, fs in os.walk(root):
            for f in fs:
                if "OpsTest" not in f or not f.endswith(".java"):
                    continue
                yield os.path.join(dp, f)


def main():
    if "--self-check" in sys.argv:
        return self_check()
    fix = "--fix" in sys.argv
    stale = 0
    fixed = 0
    for jf in iter_anchors():
        L = open(jf).readlines()
        changed = False
        for i, l in enumerate(L):
            a = ANCHOR.search(l)
            if not a:
                continue
            flag = None
            for j in range(i + 1, min(i + 1 + WINDOW, len(L))):
                m = SETFLAG.search(L[j])
                if m:
                    flag = m.group(1)
                    break
            if not flag:
                continue
            cpath, cln = a.group(2), int(a.group(3))
            if line_has_flag(cpath, cln, flag):
                continue
            stale += 1
            if fix:
                cands = bare_flag_lines(cpath, flag)
                if cands:
                    best = min(cands, key=lambda c: abs(c - cln))
                    L[i] = ANCHOR.sub(rf"\g<1>{cpath}:{best}", l, count=1)
                    fixed += 1
                    changed = True
                    continue
            print(f"STALE: {jf}:{i + 1} -> {cpath}:{cln} expects {flag}")
        if changed:
            open(jf, "w").writelines(L)

    if fix:
        print(f"fixed {fixed} stale anchors")
        return 0
    print(f"{stale} stale anchor(s)")
    return 1 if stale else 0


if __name__ == "__main__":
    sys.exit(main())
