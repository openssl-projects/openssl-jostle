#!/usr/bin/env python3
"""Aggregate gradle test-result XML and fail on masked skips.

Verifies two things a green gradle exit does NOT prove:
  1. zero failures/errors across every requested task's result files;
  2. (--require-fips) no env-gated FIPS class was wholesale-skipped —
     the signature of a run whose TEST_FIPS_LIB was unset or of a cached
     UP-TO-DATE replay (gradle does not treat env vars as task inputs).

Usage:
  python3 verify-results.py [--require-fips] [task ...]

Default tasks: test unitTest25JNI unitTest25FFI integrationTest25JNI integrationTest25FFI
Exit codes: 0 ok, 1 failures/errors present, 2 gated classes fully skipped,
3 a requested task has no result files at all (never ran).
"""

import glob
import os
import sys
import xml.etree.ElementTree as ET

DEFAULT_TASKS = ["test", "unitTest25JNI", "unitTest25FFI",
                 "integrationTest25JNI", "integrationTest25FFI"]
RESULTS_ROOT = "jostle/build/test-results"


def main():
    args = sys.argv[1:]
    require_fips = "--require-fips" in args
    tasks = [a for a in args if not a.startswith("--")] or DEFAULT_TASKS

    rc = 0
    grand = [0, 0, 0, 0]
    for task in tasks:
        files = sorted(glob.glob(os.path.join(RESULTS_ROOT, task, "TEST-*.xml")))
        if not files:
            print(f"{task}: NO RESULT FILES — task never ran")
            rc = max(rc, 3)
            continue
        t = f = e = s = 0
        masked = []
        for path in files:
            r = ET.parse(path).getroot()
            ct, cf, ce, cs = (int(r.get(k, 0)) for k in ("tests", "failures", "errors", "skipped"))
            t += ct; f += cf; e += ce; s += cs
            cls = os.path.basename(path)[len("TEST-"):-len(".xml")]
            if cf or ce:
                print(f"{task}: FAILURES in {cls} (failures={cf} errors={ce})")
            if ".fips." in path and ct > 0 and cs == ct:
                masked.append(cls)
        for i, v in enumerate((t, f, e, s)):
            grand[i] += v
        flag = ""
        if f or e:
            rc = max(rc, 1)
            flag = "  <-- FAILED"
        if masked:
            if require_fips:
                rc = max(rc, 2)
                flag += f"  <-- {len(masked)} FIPS classes fully skipped"
            else:
                flag += f"  (note: {len(masked)} FIPS classes skipped — TEST_FIPS_LIB unset?)"
        print(f"{task}: tests={t} failures={f} errors={e} skipped={s}{flag}")
        if masked and require_fips:
            for m in masked:
                print(f"    fully skipped: {m}")
    print(f"TOTAL: tests={grand[0]} failures={grand[1]} errors={grand[2]} skipped={grand[3]}")
    if rc == 0:
        print("matrix verified: green, and no gated class was masked" if require_fips
              else "matrix verified: green (FIPS gating not enforced)")
    return rc


if __name__ == "__main__":
    sys.exit(main())
