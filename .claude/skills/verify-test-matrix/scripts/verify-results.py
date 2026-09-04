#!/usr/bin/env python3
"""Aggregate gradle test-result XML and fail on masked skips.

Verifies three things a green gradle exit does NOT prove:
  1. zero failures/errors across every requested task's result files;
  2. (--require-fips) no env-gated FIPS class was wholesale-skipped —
     the signature of a run whose TEST_FIPS_LIB was unset or of a cached
     UP-TO-DATE replay (gradle does not treat env vars as task inputs);
  3. that the *OpsTest classes ran at all — they need a native build made
     with JOSTLE_OPS_TEST=1, and against a plain build every one of them
     assumption-skips while the suite still reports green.

Point 3 is why verification is a TWO-PASS job (see the skill's "The two-pass
OPS discipline"). This script detects which build is installed by looking for
an OPS-only symbol in the packaged interface library, so it can tell "you have
not run the OPS pass yet" apart from "the OPS pass ran and something is
broken" — a distinction the earlier version could not make, which made a
correct single-pass run report FAIL with no indication of what to do.

Usage:
  python3 verify-results.py [--require-fips] [--require-ops] [task ...]

  --require-ops  the OPS classes MUST have run: fails if the installed build
                 is not instrumented, or if OPS classes skipped despite it.
                 The two-pass driver passes this on the second pass.
  --require-fips run-matrix.sh:38-46 passes this ONLY after confirming the
                 module file exists, so its ABSENCE is a recorded run-time
                 fact: no FIPS module was present. A hand-runner who types it
                 without a module, or omits it with one, breaks that contract.

Default tasks: test unitTest25JNI unitTest25FFI integrationTest25JNI integrationTest25FFI
Exit codes: 0 ok, 1 failures/errors present, 2 gated classes fully skipped,
3 a requested task has no result files at all (never ran), 4 OPS coverage
missing while --require-ops.
"""

import glob
import os
import sys
import xml.etree.ElementTree as ET

DEFAULT_TASKS = ["test", "unitTest25JNI", "unitTest25FFI",
                 "integrationTest25JNI", "integrationTest25FFI"]
RESULTS_ROOT = "jostle/build/test-results"
NATIVE_ROOT = "jostle/src/main/resources/native"

# An entry point that exists ONLY under JOSTLE_OPS (ffi/ops_ffi.c is wrapped in
# #ifdef JOSTLE_OPS). Searched as a raw byte string rather than via nm: symbol
# names appear literally in Mach-O, ELF and PE alike, so one code path covers
# every platform we build for and the check needs no toolchain.
OPS_MARKER = b"JoOps_setFlag"


def ops_build_installed():
    """(instrumented, evidence) for the packaged interface library.

    instrumented is None when no library is present at all - a source-only
    checkout, where the question is unanswerable rather than answered 'no'.
    """
    libs = sorted(glob.glob(os.path.join(NATIVE_ROOT, "*", "*", "*interface_ffi*")))
    libs = [p for p in libs if not p.endswith(".txt")]
    if not libs:
        return None, f"no interface library under {NATIVE_ROOT}"
    for path in libs:
        with open(path, "rb") as fh:
            if OPS_MARKER in fh.read():
                return True, path
    return False, libs[0]


def main():
    args = sys.argv[1:]
    require_fips = "--require-fips" in args
    require_ops = "--require-ops" in args
    # run-matrix.sh:38-46 passes --require-fips only after confirming the module
    # file exists, so its absence is a recorded run-time fact, not a guess.
    # Naming it keeps require_fips' double duty (policy + fact) visible here.
    fips_module_absent = not require_fips
    tasks = [a for a in args if not a.startswith("--")] or DEFAULT_TASKS

    ops_installed, ops_evidence = ops_build_installed()

    rc = 0
    grand = [0, 0, 0, 0]
    ops_skipped_total = 0
    fips_excused_total = 0
    for task in tasks:
        files = sorted(glob.glob(os.path.join(RESULTS_ROOT, task, "TEST-*.xml")))
        if not files:
            print(f"{task}: NO RESULT FILES — task never ran")
            rc = max(rc, 3)
            continue
        t = f = e = s = 0
        masked_fips = []
        masked_ops = []
        masked_fips_ops = []
        for path in files:
            r = ET.parse(path).getroot()
            ct, cf, ce, cs = (int(r.get(k, 0)) for k in ("tests", "failures", "errors", "skipped"))
            t += ct; f += cf; e += ce; s += cs
            cls = os.path.basename(path)[len("TEST-"):-len(".xml")]
            if cf or ce:
                print(f"{task}: FAILURES in {cls} (failures={cf} errors={ce})")
            if ct == 0 or cs != ct:
                continue
            # An OpsTest skipping wholesale is EXPECTED against a plain build
            # and a real defect against an instrumented one, so it is counted
            # separately from other gated classes rather than lumped in.
            if cls.endswith("OpsTest"):
                # A FIPS OpsTest with no module present skipped at its
                # class-level gate (@BeforeAll assumeFalse(skipFipsTests())),
                # not for want of instrumentation - so an instrumented build
                # gives it no case to answer. Bucketed, never dropped: the run
                # must say what it excused.
                if ".fips." in path and fips_module_absent:
                    masked_fips_ops.append(cls)
                else:
                    masked_ops.append(cls)
            elif ".fips." in path:
                masked_fips.append(cls)

        # Some OPS fault families exist only on the JNI bridge - the
        # GetStringUTFChars / GetByteArrayElements / int32-overflow guards have
        # no FFI counterpart - so a class like KSServiceOpsTest skips wholesale
        # under an FFI task BY DESIGN, on an instrumented build. Enforcing
        # "instrumented, therefore it must run" only on JNI tasks keeps that
        # legitimate case from reading as a defect; every OpsTest can run there.
        ops_enforceable = "JNI" in task
        for i, v in enumerate((t, f, e, s)):
            grand[i] += v
        ops_skipped_total += len(masked_ops)
        fips_excused_total += len(masked_fips_ops)

        flag = ""
        if f or e:
            rc = max(rc, 1)
            flag = "  <-- FAILED"
        if masked_fips:
            if require_fips:
                rc = max(rc, 2)
                flag += f"  <-- {len(masked_fips)} FIPS classes fully skipped"
            else:
                flag += f"  (note: {len(masked_fips)} FIPS classes skipped — TEST_FIPS_LIB unset?)"
        if masked_ops:
            if ops_installed and ops_enforceable:
                # Instrumented build, JNI task: they had no excuse to skip.
                rc = max(rc, 2)
                flag += (f"  <-- {len(masked_ops)} OPS classes skipped DESPITE an"
                         f" instrumented build")
            elif ops_installed:
                flag += f"  (note: {len(masked_ops)} JNI-only OpsTest classes, expected)"
            else:
                flag += f"  (OPS pass not run: {len(masked_ops)} OpsTest classes skipped)"
        if masked_fips_ops:
            flag += f"  ({len(masked_fips_ops)} FIPS OpsTests excused: module absent)"
        print(f"{task}: tests={t} failures={f} errors={e} skipped={s}{flag}")
        if masked_fips and require_fips:
            for m in masked_fips:
                print(f"    fully skipped: {m}")
        if masked_ops and ops_installed and ops_enforceable:
            for m in masked_ops:
                print(f"    fully skipped: {m}")

    print(f"TOTAL: tests={grand[0]} failures={grand[1]} errors={grand[2]} skipped={grand[3]}")

    # --- the two-pass verdict ------------------------------------------------
    if ops_installed is None:
        print(f"OPS build state: UNKNOWN ({ops_evidence})")
        if require_ops:
            rc = max(rc, 4)
    elif ops_installed:
        print(f"OPS build state: INSTRUMENTED ({ops_evidence})")
    else:
        print(f"OPS build state: NOT instrumented ({ops_evidence})")
        if ops_skipped_total or fips_excused_total:
            if fips_excused_total:
                print(f"  {ops_skipped_total} OpsTest class(es) did not run, plus"
                      f" {fips_excused_total} excused (module absent). This pass covers the"
                      f" SHIPPED library; it does not cover the OPS fault-injection paths.")
            else:
                print(f"  {ops_skipped_total} OpsTest class(es) did not run. This pass covers the"
                      f" SHIPPED library; it does not cover the OPS fault-injection paths.")
            print("  Second pass:  JOSTLE_OPS_TEST=1 ./interface/build.sh"
                  "  &&  run-matrix.sh integrationTest25JNI integrationTest25FFI")
            print("  Then rebuild plain so the tree is left shipping-clean.")
        if require_ops:
            rc = max(rc, 4)

    if rc == 0:
        note = "green"
        note += ", no gated class masked" if require_fips else " (FIPS gating not enforced)"
        if require_ops:
            note += ", OPS classes ran"
            if fips_excused_total:
                note += f" ({fips_excused_total} FIPS excused: module absent)"
        print(f"matrix verified: {note}")
    return rc


if __name__ == "__main__":
    sys.exit(main())
