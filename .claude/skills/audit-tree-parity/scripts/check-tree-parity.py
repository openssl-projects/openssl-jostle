#!/usr/bin/env python3
"""Check the interface/nonfips <-> interface/fips twin discipline.

The two native trees are independent copies by design, but MOST files are
required to stay byte-identical twins: a fix applied to one and not the
other is the classic cross-tree defect. A small, deliberate set diverges.
This script knows the sanctioned divergence list and reports everything
else: content drift in files that must match, and file-set differences
outside the sanctioned lists.

Usage:
  python3 check-tree-parity.py            # full report
  python3 check-tree-parity.py --quiet    # only violations

Exit code 0 = clean, 1 = unsanctioned drift or file-set difference.
On drift the report prints the diff stat and the cp commands for BOTH
directions — the human/agent picks the direction; the script never writes.
"""

import os
import subprocess
import sys

REPO = os.getcwd()
NONFIPS = "interface/nonfips"
FIPS = "interface/fips"

# --- sanctioned divergences -------------------------------------------------

# Files present in both trees whose CONTENT is allowed to differ.
DIVERGENT_CONTENT = {
    "util/rand.c",                    # rand_init_fips added in the fips tree
    "util/rand.h",                    # rand_init_fips declaration
    "util/rand/jostle_lib_ctx.c",     # nonfips: jrand bridge + RAND_set_DRBG_type;
                                      # fips: bridge excised (2026-07-12), bridge-less init
    "util/bc_err_codes.h",            # fips adds the -400 JO_FIPS_* block
}

# Basenames/patterns that legitimately exist in only ONE tree.
NONFIPS_ONLY_PREFIXES = (
    # algorithm families the FIPS provider does not ship
    "util/edec", "util/ks", "util/mldsa", "util/mlkem", "util/slhdsa",
    "jni/ed_", "jni/edec", "jni/ks_", "jni/mldsa", "jni/mlkem",
    "jni/slhdsa", "jni/slh_dsa",
    "ffi/ed_", "ffi/edec", "ffi/ks_", "ffi/mldsa", "ffi/mlkem",
    "ffi/slhdsa", "ffi/slh_dsa",
    # base-provider init/diagnostic glue with fips-tree counterparts under
    # different names (openssl_fips_jni.c) or no FIPS equivalent at all
    "jni/open_ssl_jni", "jni/native_info",
    # memory-hard password KDFs (scrypt, Argon2). Neither is served by the
    # OpenSSL FIPS provider (both build only into libdefault.a; neither appears
    # in fipsprov.c) and neither is registered by ProvFIPSKDF, so their bridges
    # are kept out of the FIPS interface library entirely — that library then
    # exports no symbols for algorithms outside the validated boundary. kdf.c /
    # kdf_jni.c / kdf_ffi.c keep the approved KDFs (PBKDF2, HKDF) and remain
    # byte-identical twins.
    "util/kdf_memhard", "jni/kdf_memhard", "ffi/kdf_memhard",
)
FIPS_ONLY_PREFIXES = (
    "util/rand/jostle_fips_ctx",      # FIPS lib ctx configuration
)
# fips/jni holds the rename-re-include wrappers (<x>_fips_jni.c) — fips-only.
def fips_only(rel):
    return (rel.startswith(FIPS_ONLY_PREFIXES)
            or (rel.startswith("jni/") and rel.endswith("_fips_jni.c"))
            or (rel.startswith("ffi/") and "_fips_" in rel))


def tree_files(root):
    out = {}
    for dirpath, _, files in os.walk(os.path.join(REPO, root)):
        for f in files:
            if not f.endswith((".c", ".h")):
                continue
            full = os.path.join(dirpath, f)
            rel = os.path.relpath(full, os.path.join(REPO, root))
            out[rel] = full
    return out


def main():
    quiet = "--quiet" in sys.argv
    a = tree_files(NONFIPS)
    b = tree_files(FIPS)
    violations = 0
    ok_twins = 0

    for rel in sorted(set(a) | set(b)):
        in_a, in_b = rel in a, rel in b
        if in_a and not in_b:
            if rel.startswith(NONFIPS_ONLY_PREFIXES):
                continue
            print(f"FILE-SET: {rel} exists only in nonfips (not in the sanctioned nonfips-only list)")
            violations += 1
            continue
        if in_b and not in_a:
            if fips_only(rel):
                continue
            print(f"FILE-SET: {rel} exists only in fips (not in the sanctioned fips-only list)")
            violations += 1
            continue
        # present in both
        same = open(a[rel], "rb").read() == open(b[rel], "rb").read()
        if rel in DIVERGENT_CONTENT:
            if same and not quiet:
                print(f"NOTE: {rel} is sanctioned-divergent but currently identical "
                      f"(fine, but check the sanction list is still accurate)")
            continue
        if same:
            ok_twins += 1
            continue
        violations += 1
        print(f"DRIFT: {rel} differs between trees but is required to be a byte-identical twin")
        diff = subprocess.run(
            ["diff", "--brief" if quiet else "-u",
             os.path.join(NONFIPS, rel), os.path.join(FIPS, rel)],
            capture_output=True, text=True, cwd=REPO)
        if not quiet:
            lines = diff.stdout.splitlines()
            for line in lines[:20]:
                print("    " + line)
            if len(lines) > 20:
                print(f"    ... ({len(lines) - 20} more diff lines)")
        print(f"    sync nonfips->fips: cp {NONFIPS}/{rel} {FIPS}/{rel}")
        print(f"    sync fips->nonfips: cp {FIPS}/{rel} {NONFIPS}/{rel}")

    print(f"\n{ok_twins} twin files identical, {violations} violation(s)")
    if violations == 0:
        print("tree parity clean")
    return 1 if violations else 0


if __name__ == "__main__":
    sys.exit(main())
