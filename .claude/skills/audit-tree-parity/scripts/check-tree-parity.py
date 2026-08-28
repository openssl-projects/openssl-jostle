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

import difflib
import os
import sys

REPO = os.getcwd()
NONFIPS = "interface/nonfips"
FIPS = "interface/fips"

# --- sanctioned UNIFORM renames --------------------------------------------

# The FIPS tree names its lib ctx accessors apart from the base tree's, so that
# no symbol of either name exists in both interface libraries - see the
# name-separation note in interface/fips/util/rand/jostle_lib_ctx.h. Every call
# site in the FIPS tree spells the fips name directly (deliberately: an alias
# in the header would hide the very fact the separation exists to make visible).
#
# That is a uniform, mechanical rename, not drift. Normalising it away before
# comparing keeps the ~20 affected util files under full twin discipline for
# every OTHER difference - which is the point. Listing them in
# DIVERGENT_CONTENT instead would stop checking them entirely, and a fix
# applied to one tree and not the other is exactly what this script exists to
# catch.
ACCESSOR_ALIASES = (
    (b"get_global_jostle_fips_ossl_lib_ctx", b"get_global_jostle_ossl_lib_ctx"),
    (b"set_global_jostle_fips_lib_ctx", b"set_global_jostle_lib_ctx"),
)


def normalise(data):
    """Map the fips-named accessors back onto the base names. A no-op on base
    tree content, which never mentions the fips names."""
    for fips_name, base_name in ACCESSOR_ALIASES:
        data = data.replace(fips_name, base_name)
    return data


def renamed(data):
    """True if this file carries the accessor rename, so a raw cp between the
    trees would clobber it (and break the FIPS build at link time)."""
    return any(f in data for f, _ in ACCESSOR_ALIASES)

# --- sanctioned divergences -------------------------------------------------

# Files present in both trees whose CONTENT is allowed to differ.
DIVERGENT_CONTENT = {
    "util/rand.c",                    # rand_init_fips added in the fips tree
    "util/rand.h",                    # rand_init_fips declaration
    "util/rand/jostle_lib_ctx.c",     # nonfips: jrand bridge + RAND_set_DRBG_type;
                                      # fips: bridge excised (2026-07-12), bridge-less init;
                                      # fips-named accessors + static (2026-08-23)
    "util/rand/jostle_lib_ctx.h",     # fips: declares the fips-named lib ctx accessors and
                                      # redirects the base names onto them, so the FIPS
                                      # libraries define neither base symbol. Keeps the ~20
                                      # util callers byte-identical twins; see the
                                      # name-separation note in the fips header.
    "util/bc_err_codes.h",            # fips adds the -400 JO_FIPS_* block
}

# Basenames/patterns that legitimately exist in only ONE tree.
NONFIPS_ONLY_PREFIXES = (
    # algorithm families the FIPS provider does not ship.
    #
    # ML-DSA / ML-KEM / SLH-DSA were here until 2026-08-23. They were correct
    # to exclude while 3.1.2 was the only target - it implements no PQC, so the
    # bridges would have been unreachable code inside the FIPS library. The
    # 3.5.x module implements all three (probe:
    # fips-c-review/probes/pqc_op_probe.c), so they are now byte-identical
    # twins like every other shared family, and ProvFIPS{MLDSA,MLKEM,SLHDSA}
    # gate registration on the loaded module actually serving them.
    #
    # The Ed family (util/edec, jni/ed_, ffi/ed_) came off this list on the
    # same date and for the same reason, in the opposite direction to xec:
    # 3.1.2 refuses ED25519/ED448 outright while 3.5.7 serves both (probe:
    # fips-c-review/probes/ed_gate_probe.c), so they are ordinary twins now and
    # ProvFIPSED gates registration per NAME on the loaded module - which also
    # excludes ED25519CTX, the one member 3.5.7 does not register.
    "util/ks",
    "jni/ks_",
    "ffi/ks_",
    # base-provider init/diagnostic glue with fips-tree counterparts under
    # different names (openssl_fips_{jni,ffi}.c) or no FIPS equivalent at all.
    #
    # ffi/openssl_ffi was a twin until 2026-08-23: the FIPS library re-included
    # it for JoOpenSSL_getErrors and thereby also exported JoOpenSSL_setModule,
    # which installs a lib ctx built by jostle_ctx_init_new - no fipsinstall
    # config, no fips=yes properties - as the FIPS global. Nothing bound it, but
    # its only possible effect was to make FIPS fetches resolve to mainline.
    # openssl_fips_ffi.c now owns JoFIPS_get_openssl_errors, matching what
    # jni/open_ssl_jni had always done. Do not restore the twin.
    "jni/open_ssl_jni", "jni/native_info", "ffi/openssl_ffi",
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
    # The two capability probes that only mean something against a loaded FIPS
    # module: capability_module_version (loads the "fips" provider) and
    # capability_implementing_provider (would only ever answer "default" in the
    # base ctx). The SHARED fetch probe, util/capability.{c,h}, is an ordinary
    # twin — both providers gate registrations on it — and is deliberately NOT
    # listed here.
    "util/capability_fips",
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
        # present in both. Compared after normalising the sanctioned accessor
        # rename, so those files stay under twin discipline for everything else.
        raw_a = open(a[rel], "rb").read()
        raw_b = open(b[rel], "rb").read()
        same = normalise(raw_a) == normalise(raw_b)
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
        if not quiet:
            # Diff the NORMALISED content: the accessor rename is sanctioned, so
            # showing it here would bury the real drift in noise.
            lines = list(difflib.unified_diff(
                normalise(raw_a).decode("utf-8", "replace").splitlines(),
                normalise(raw_b).decode("utf-8", "replace").splitlines(),
                fromfile=f"{NONFIPS}/{rel}", tofile=f"{FIPS}/{rel}", lineterm=""))
            for line in lines[:20]:
                print("    " + line)
            if len(lines) > 20:
                print(f"    ... ({len(lines) - 20} more diff lines)")
        if renamed(raw_b):
            print(f"    NOTE: the fips copy carries the lib ctx accessor rename; a raw cp"
                  f" either way clobbers it and breaks the FIPS build. Port the real"
                  f" change by hand, keeping the fips accessor names.")
        else:
            print(f"    sync nonfips->fips: cp {NONFIPS}/{rel} {FIPS}/{rel}")
            print(f"    sync fips->nonfips: cp {FIPS}/{rel} {NONFIPS}/{rel}")

    print(f"\n{ok_twins} twin files identical, {violations} violation(s)")
    if violations == 0:
        print("tree parity clean")
    return 1 if violations else 0


if __name__ == "__main__":
    sys.exit(main())
