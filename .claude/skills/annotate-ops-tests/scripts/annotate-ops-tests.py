#!/usr/bin/env python3
"""annotate-ops-tests.py — link each Java OPS test to the C-side
fault-injection site it exercises by inserting (or updating) a comment
of the form:

    // Exercises interface/util/<file>.c:<line>

immediately before the `operationsTestNI.setFlag(...)` call that drives
the test.

Matching is by (OPS slot, OPS offset) pair:

  1. The Java test sets one slot via `setFlag(OpsTestFlag.OPS_OPENSSL_ERROR_<N>)`.
  2. The Java test asserts a specific return code via
     `Assertions.assertEquals(-<code>, ...)`. The offset is
     `(-code) - 2` (because `JO_OPENSSL_ERROR == -2`).
  3. The C side returns `JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_<N>(<offset>)`
     on the error-return line, with the corresponding `OPS_OPENSSL_ERROR_<N>`
     macro one or two lines above on the `if (...)` line.
  4. The comment we emit points at the if-line (the call site that's
     being short-circuited), not the error-return line.

Tests that don't have a uniquely-locatable site are skipped:
  - Tests asserting only the exception type (no integer return-code check).
  - Tests using non-offset OPS macros (`OPS_INT32_OVERFLOW_*`, `OPS_LEN_CHANGE_*`,
    `OPS_FAILED_ACCESS_*`, etc.) — these would need a different index.

Usage:
    annotate-ops-tests.py <java-test-file-or-dir> [--c-dir interface/util]
                                                  [--dry-run]

`--dry-run` prints the proposed annotations without modifying files.
Re-running the script updates stale annotations in place (useful after
C-side edits shift line numbers).
"""

import re
import sys
from pathlib import Path

C_OFFSET_RE = re.compile(
    r"OPS_OFFSET_OPENSSL_ERROR_(\d+)\s*\(\s*(\d+)\s*\)"
)
JAVA_FLAG_RE = re.compile(
    r"operationsTestNI\.setFlag\s*\(\s*[^)]*?OpsTestFlag\.OPS_OPENSSL_ERROR_(\d+)\s*\)"
)
JAVA_EQ_RE = re.compile(
    r"Assertions\.assertEquals\s*\(\s*(-?\d+)\s*,"
)
TEST_METHOD_END_RE = re.compile(r"^    \}\s*$")  # closing brace at method indent
COMMENT_PREFIX = "Exercises "

# Map Java test class name (filename minus .java) to the candidate C
# files it can plausibly target. The same (slot, offset) pair is reused
# across different C files — without restricting the match by test
# class, the script would link e.g. RSAOpsTest entries to slhdsa.c just
# because both happen to use OPS_OPENSSL_ERROR_1 with offset 1000.
TEST_TO_C_FILES = {
    "RSAOpsTest":            ["rsa.c"],
    "RSAOAEPCipherOpsTest":  ["rsa_oaep.c"],
    "RSAPKCS1CipherOpsTest": ["rsa_pkcs1.c"],
    "MLDSOpsTest":           ["mldsa.c"],
    "MLKEMOpsTest":          ["mlkem.c"],
    "SLHDSAOpsTest":         ["slhdsa.c"],
    "EdDSAOpsTest":          ["edec.c"],
    "ECOpsTest":             ["ec.c"],
    "MacOpsTest":            ["mac.c"],
    "MDOpsTest":             ["md.c"],
    "BlockCipherOpsTest":    ["block_cipher_ctx.c"],
    "CCMOpsTest":            ["ccm_ctx.c"],
    "ASN1UtilOpsTest":       ["asn1_util.c"],
    "SpecOpsTest":           ["encapdecap.c"],
    "PBKdf2OpsTest":         ["kdf.c"],
    "ScryptOpsTest":         ["kdf.c"],
}


def build_c_index(c_paths):
    """Build dict {c_path: {(slot, offset): if_line_no_1based}}.

    Per-file index. The same (slot, offset) pair is reused across
    different C files (each file numbers its offsets independently),
    so callers MUST restrict matches to one file via the
    test→C-file map.

    Locates each `OPS_OFFSET_OPENSSL_ERROR_N(offset)` in C, then walks
    backwards up to 5 lines for the matching `OPS_OPENSSL_ERROR_N`
    macro that fires the fault. The if-line is the canonical pointer
    for the test comment.
    """
    index = {}
    for c_path in c_paths:
        try:
            lines = c_path.read_text().splitlines()
        except (OSError, UnicodeDecodeError):
            continue
        per_file = {}
        for idx, line in enumerate(lines):
            m = C_OFFSET_RE.search(line)
            if not m:
                continue
            slot = int(m.group(1))
            offset = int(m.group(2))
            # Look back for the if-line containing the matching slot macro.
            if_line_no = idx + 1  # fallback to the offset line itself
            for back_idx in range(idx, max(-1, idx - 6), -1):
                if re.search(rf"\bOPS_OPENSSL_ERROR_{slot}\b", lines[back_idx]):
                    if_line_no = back_idx + 1
                    break
            per_file[(slot, offset)] = if_line_no
        if per_file:
            index[c_path] = per_file
    return index


def candidate_c_files(java_path, c_index):
    """Return the list of C paths to search for matches for this Java test.

    Resolution order:
      1. Explicit mapping in TEST_TO_C_FILES for the test class name.
      2. Heuristic: strip "OpsTest" from filename, lowercase, match by
         basename to any indexed C path.
      3. Empty — caller skips this Java file with a warning.
    """
    class_name = java_path.stem  # filename without .java
    explicit = TEST_TO_C_FILES.get(class_name)
    if explicit:
        wanted = set(explicit)
        return [p for p in c_index if p.name in wanted]
    # Heuristic fallback.
    base = class_name.removesuffix("OpsTest").lower()
    if not base:
        return []
    return [p for p in c_index if p.stem == base]


def find_test_methods(java_lines):
    """Yield (start_idx, end_idx) inclusive ranges for each @Test method
    in the file. End is the closing `    }` at method indent."""
    i = 0
    while i < len(java_lines):
        line = java_lines[i]
        if line.lstrip().startswith("@Test"):
            # Find method body open-brace (next `{` at end of line).
            j = i + 1
            while j < len(java_lines) and not java_lines[j].rstrip().endswith("{"):
                j += 1
            # Body starts after the opening brace line. End at next `    }`.
            k = j + 1
            while k < len(java_lines) and not TEST_METHOD_END_RE.match(java_lines[k]):
                k += 1
            yield (i, k)
            i = k + 1
        else:
            i += 1


def annotate_java_file(java_path, c_index, repo_root, dry_run=False):
    """Annotate one Java test file. Returns (count_changed, skipped_unmapped).

    Looks up only the C files in the test class's candidate scope.
    """
    candidates = candidate_c_files(java_path, c_index)
    if not candidates:
        return (0, True)  # no candidate C file — skip

    # Merge candidate (slot, offset) -> (c_path, line_no) lookups.
    # Because candidates are restricted by class name, ambiguity is
    # rare; if two candidates do define the same (slot, offset) we
    # report the first-listed and warn.
    merged = {}
    ambiguous = {}
    for c_path in candidates:
        for key, line_no in c_index[c_path].items():
            if key in merged:
                ambiguous[key] = ambiguous.get(key, [merged[key]]) + [(c_path, line_no)]
            else:
                merged[key] = (c_path, line_no)

    text = java_path.read_text()
    lines = text.splitlines()
    out = list(lines)

    changes = 0
    # Iterate test methods in REVERSE order. Each insertion into `out`
    # shifts indices below by 1, so processing from the bottom up keeps
    # the indices for earlier methods stable.
    test_methods = list(find_test_methods(lines))
    for start, end in reversed(test_methods):
        flag_line_idx = None
        flag_slot = None
        offset = None
        for idx in range(start, end + 1):
            if flag_line_idx is None:
                fm = JAVA_FLAG_RE.search(lines[idx])
                if fm:
                    flag_line_idx = idx
                    flag_slot = int(fm.group(1))
            elif offset is None:
                em = JAVA_EQ_RE.search(lines[idx])
                if em:
                    code = int(em.group(1))
                    if code < 0:
                        offset = (-code) - 2
                    break
        if flag_line_idx is None or offset is None:
            continue
        key = (flag_slot, offset)
        if key not in merged:
            continue
        if key in ambiguous:
            # Skip ambiguous matches — emitting a wrong link is worse
            # than emitting none.
            continue
        c_path, c_line_no = merged[key]
        try:
            rel = c_path.relative_to(repo_root)
        except ValueError:
            rel = c_path
        flag_line = lines[flag_line_idx]
        indent_match = re.match(r"(\s*)", flag_line)
        indent = indent_match.group(1) if indent_match else "            "
        new_comment = f"{indent}// {COMMENT_PREFIX}{rel}:{c_line_no}"

        above_idx = flag_line_idx - 1
        if above_idx >= 0 and out[above_idx].strip().startswith("// " + COMMENT_PREFIX):
            if out[above_idx] != new_comment:
                out[above_idx] = new_comment
                changes += 1
        else:
            out.insert(flag_line_idx, new_comment)
            changes += 1

    if changes > 0 and not dry_run:
        java_path.write_text("\n".join(out) + ("\n" if text.endswith("\n") else ""))
    return (changes, False)


def main(argv):
    args = argv[1:]
    if not args:
        print(__doc__, file=sys.stderr)
        return 2

    c_dir = Path("interface/util")
    dry_run = False
    targets = []
    i = 0
    while i < len(args):
        if args[i] == "--c-dir":
            c_dir = Path(args[i + 1])
            i += 2
        elif args[i] == "--dry-run":
            dry_run = True
            i += 1
        else:
            targets.append(Path(args[i]))
            i += 1

    if not c_dir.is_dir():
        print(f"C dir not found: {c_dir}", file=sys.stderr)
        return 2
    c_paths = sorted(c_dir.glob("*.c"))
    if not c_paths:
        print(f"no .c files in {c_dir}", file=sys.stderr)
        return 2

    # repo_root is the parent of `interface/` if that's the c-dir's grandparent;
    # otherwise fall back to CWD.
    repo_root = Path.cwd().resolve()
    c_index = build_c_index(c_paths)
    if not c_index:
        print("no (slot, offset) pairs found in C — nothing to link", file=sys.stderr)
        return 2

    # Collect target Java files.
    java_files = []
    for t in targets:
        tp = t.resolve()
        if tp.is_dir():
            java_files.extend(sorted(tp.rglob("*OpsTest.java")))
        elif tp.is_file() and tp.suffix == ".java":
            java_files.append(tp)
    if not java_files:
        print("no *OpsTest.java files matched", file=sys.stderr)
        return 2

    total = 0
    unmapped = []
    for jf in java_files:
        added, skipped = annotate_java_file(jf, c_index, repo_root, dry_run=dry_run)
        try:
            rel = jf.relative_to(repo_root)
        except ValueError:
            rel = jf
        if skipped:
            unmapped.append(rel)
            continue
        if added > 0:
            tag = "would add/update" if dry_run else "added/updated"
            print(f"{rel}: {tag} {added} annotation(s)")
        total += added

    if unmapped:
        print("\nSkipped — no matching C file has OPS_OFFSET_OPENSSL_ERROR_N "
              "sites for these tests to link to:")
        for rel in unmapped:
            print(f"  {rel}")
        print("(These tests likely use exception-type assertions rather than "
              "offset-based return codes, so they can't be auto-linked. "
              "Add a TEST_TO_C_FILES entry if the candidate C file mapping "
              "is wrong.)")

    total_sites = sum(len(per_file) for per_file in c_index.values())
    summary = "would change" if dry_run else "changed"
    print(f"\nC sites indexed: {total_sites} across {len(c_index)} file(s); "
          f"Java files scanned: {len(java_files)}; "
          f"{summary}: {total} annotation(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
