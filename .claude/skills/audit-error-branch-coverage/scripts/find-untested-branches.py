#!/usr/bin/env python3
"""Map every error-handling branch in the C trees to test evidence.

The existing audit skills find UNinstrumented checks. This one answers the
complementary question: for each branch that IS instrumented (OPS_* site) or
returns a typed JO_* code, does any test in the Java test tree actually drive
it? An instrumented-but-untested site is one refactor away from silently
regressing (found twice in the 2026-07-12 review application: the rsa_pkcs1
set_params site and the rand.c enable_locking site were both instrumented and
both orphaned).

Evidence considered (heuristic, over-reports by design):
  1. errorAt(<offset>) calls in *OpsTest files        -> covers the OPS site
  2. assertEquals(-<raw>, ...) literals               -> covers raw code
                                                         (raw = JO base + offset,
                                                          or plain JO value)
  3. the JO_* constant name appearing anywhere in the
     test tree (ErrorCode.JO_X / local constants)     -> covers the typed code
  4. `// Exercises <path>:<line>` comments, matched
     tree-agnostically with a +/-3 line drift window  -> covers that C site

Usage:
  python3 find-untested-branches.py                   # scan interface/nonfips
  python3 find-untested-branches.py interface/fips/util/dh.c
  python3 find-untested-branches.py interface/nonfips/util

Exit code 0 = no orphans, 1 = at least one orphaned branch.
"""

import os
import re
import sys
from collections import defaultdict

REPO = os.getcwd()
ERR_HEADER = os.path.join(REPO, "interface/nonfips/util/bc_err_codes.h")
FIPS_ERR_HEADER = os.path.join(REPO, "interface/fips/util/bc_err_codes.h")
TEST_ROOTS = [
    os.path.join(REPO, "jostle/src/test/java"),
    os.path.join(REPO, "jostle/src/test/java25"),
]
DEFAULT_SCAN = [os.path.join(REPO, "interface/nonfips")]

# Codes that are contract plumbing rather than independently-drivable error
# branches (success, general fail used as state sentinel).
IGNORE_CODES = {"JO_SUCCESS", "JO_FAIL"}

OFFSET_RE = re.compile(r"OPS_OFFSET_[A-Z_0-9]+\((\d+)\)")
JO_RE = re.compile(r"\b(JO_[A-Z_0-9]+)\b")
FLAG_RE = re.compile(r"\bOPS_(?!OFFSET_)[A-Z_]+_?\d*\b")


def parse_err_codes():
    codes = {}
    for header in (ERR_HEADER, FIPS_ERR_HEADER):
        if not os.path.exists(header):
            continue
        for line in open(header):
            m = re.match(r"#define (JO_[A-Z_0-9]+) (-?\d+)", line)
            if m:
                codes[m.group(1)] = int(m.group(2))
                continue
            m = re.match(r"#define (JO_[A-Z_0-9]+) (JO_[A-Z_0-9]+)", line)
            if m and m.group(2) in codes:
                codes[m.group(1)] = codes[m.group(2)]
    return codes


def norm_site(path):
    """interface/<tree>/util/x.c -> util/x.c so fips/nonfips twins match."""
    return re.sub(r"^interface/(nonfips|fips)/", "", path)


def collect_test_evidence():
    """Return (offsets, raw_codes, jo_names, exercised) across the test tree."""
    offsets, raws, names, exercised = set(), set(), set(), set()
    for root in TEST_ROOTS:
        for dirpath, _, files in os.walk(root):
            for f in files:
                if not f.endswith(".java"):
                    continue
                text = open(os.path.join(dirpath, f), errors="replace").read()
                for m in re.finditer(r"errorAt\((\d+)\)", text):
                    offsets.add(int(m.group(1)))
                for m in re.finditer(r"assertEquals\(\s*(-\d+)", text):
                    raws.add(int(m.group(1)))
                for m in re.finditer(r"\b(JO_[A-Z_0-9]+)\b", text):
                    names.add(m.group(1))
                # JO_OPENSSL_ERROR - 3032 style arithmetic
                for m in re.finditer(r"JO_OPENSSL_ERROR\s*-\s*(\d+)", text):
                    offsets.add(int(m.group(1)))
                for m in re.finditer(r"//\s*Exercises\s+(\S+?):(\d+)", text):
                    exercised.add((norm_site(m.group(1)), int(m.group(2))))
    return offsets, raws, names, exercised


def statement_at(lines, i):
    """Join lines from i until the statement terminator ';' (max 4 lines)."""
    stmt = ""
    for j in range(i, min(i + 4, len(lines))):
        stmt += lines[j]
        if ";" in lines[j]:
            break
    return stmt


def base_codes_for(lines, i, stmt, codes):
    """JO_* base candidates for an OPS_OFFSET statement (handles `base` vars)."""
    found = [n for n in JO_RE.findall(stmt) if n in codes and n not in IGNORE_CODES]
    if found:
        return found
    # `return base OPS_OFFSET_X(n);` — look back for the ternary / assignment.
    for j in range(i - 1, max(i - 6, -1), -1):
        cands = [n for n in JO_RE.findall(lines[j]) if n in codes and n not in IGNORE_CODES]
        if cands:
            return cands
    return []


def scan_file(path, codes):
    """Yield (line_no, kind, flag, offset_or_None, jo_names, snippet)."""
    lines = open(path, errors="replace").readlines()
    seen_stmts = set()
    for i, line in enumerate(lines):
        m = OFFSET_RE.search(line)
        if m:
            stmt = statement_at(lines, i)
            key = (i,)
            if key in seen_stmts:
                continue
            seen_stmts.add(key)
            offset = int(m.group(1))
            bases = base_codes_for(lines, i, stmt, codes)
            # locate the guarding flag on the nearest preceding if-line
            flag = ""
            for j in range(i, max(i - 6, -1), -1):
                fm = FLAG_RE.search(lines[j])
                if fm:
                    flag = fm.group(0)
                    break
            yield (i + 1, "ops-offset", flag, offset, bases, line.strip())
            continue
        # OPS flag guarding a plain typed return (no offset macro in statement)
        fm = FLAG_RE.search(line)
        if fm and "if" in line.split(fm.group(0))[0]:
            stmt = statement_at(lines, i)
            block = "".join(lines[i:min(i + 4, len(lines))])
            if OFFSET_RE.search(block):
                continue  # handled above when we reach that line
            jos = [n for n in JO_RE.findall(block)
                   if n in parse_err_codes.cache and n not in IGNORE_CODES]
            if jos:
                yield (i + 1, "ops-plain", fm.group(0), None, jos, line.strip())


def main():
    codes = parse_err_codes()
    parse_err_codes.cache = codes
    offsets, raws, names, exercised = collect_test_evidence()

    targets = sys.argv[1:] or DEFAULT_SCAN
    files = []
    for t in targets:
        t = os.path.join(REPO, t) if not os.path.isabs(t) else t
        if os.path.isfile(t):
            files.append(t)
        else:
            for dirpath, _, fs in os.walk(t):
                files.extend(os.path.join(dirpath, f) for f in fs if f.endswith(".c"))

    orphans = defaultdict(list)
    total = 0
    for path in sorted(files):
        rel = os.path.relpath(path, REPO)
        for (ln, kind, flag, offset, jos, snippet) in scan_file(path, codes):
            total += 1
            covered = False
            if offset is not None:
                if offset in offsets:
                    covered = True
                for base in jos:
                    if codes[base] - offset in raws:
                        covered = True
            for base in jos:
                if base in names or codes[base] in raws:
                    covered = True
            site = norm_site(rel)
            for d in range(-3, 4):
                if (site, ln + d) in exercised:
                    covered = True
                    break
            if not covered:
                detail = f"offset {offset}" if offset is not None else "no offset"
                exp = ", ".join(f"{b}={codes[b] - (offset or 0)}" for b in jos) or "?"
                orphans[rel].append(f"  :{ln}  [{kind}] {flag} ({detail}) expected raw {exp}\n      {snippet}")

    print(f"scanned {len(files)} C files, {total} instrumented/typed branches")
    print(f"test evidence: {len(offsets)} errorAt offsets, {len(raws)} raw literals, "
          f"{len(names)} JO_* names, {len(exercised)} Exercises anchors\n")
    if not orphans:
        print("no orphaned branches — every instrumented/typed site has test evidence")
        return 0
    print("ORPHANED BRANCHES (no errorAt/raw-literal/JO-name evidence in the test tree):\n")
    for rel in sorted(orphans):
        print(rel)
        for o in orphans[rel]:
            print(o)
        print()
    return 1


if __name__ == "__main__":
    sys.exit(main())
