#!/usr/bin/env python3
"""
Emit the OPS injection leg's machine-readable record.

One OPSRECORD line per task and one OPSSUMMARY line for the leg, each a single
line of key=value fields, so an aggregator needs no XML parsing and no
knowledge of Gradle's layout.

verdict=PASS requires all three of: every task rc=0, zero failures and errors,
and a NON-ZERO count of *OpsTest classes that actually ran. The last one is the
point of the leg — a pass in which every OPS class assumption-skipped is the
false green this whole mechanism exists to prevent, and it must not read as
success.
"""
import glob
import os
import re
import subprocess
import sys

RESULT = "jostle/build/test-results/%s/TEST-*.xml"
HEAD = re.compile(r'tests="(\d+)"[^>]*skipped="(\d+)" failures="(\d+)" errors="(\d+)"')
NAME = re.compile(r'name="([^"]+)"')


def module_version():
    """Read the module version from the BINARY, never from its path."""
    lib = os.environ.get("TEST_FIPS_LIB", "")
    if not lib or not os.path.exists(lib):
        return "unset"
    try:
        out = subprocess.run(["strings", "-a", lib], capture_output=True,
                             text=True, timeout=60).stdout
    except Exception:
        return "unreadable"
    seen = sorted({m for m in re.findall(r"^3\.\d+\.\d+$", out, re.M)})
    return seen[0] if len(seen) == 1 else ("ambiguous:" + ",".join(seen) if seen else "unknown")


def main():
    tasks = sys.argv[1:-2]
    build_sec, run_sec = sys.argv[-2], sys.argv[-1]
    if not tasks:
        print("OPSSUMMARY verdict=FAIL reason=no-tasks-named")
        return 1

    total_tests = total_fail = total_err = ops_classes = 0
    bad = False
    for task in tasks:
        files = glob.glob(RESULT % task)
        if not files:
            # A task with no result files did not run. Reporting it as 0/0/0
            # would read exactly like a clean leg.
            print("OPSRECORD task=%s rc=? classes=0 tests=0 skipped=0 "
                  "failures=0 errors=0 note=NO-RESULT-FILES" % task)
            bad = True
            continue
        t = k = f = e = 0
        for path in files:
            body = open(path, encoding="utf-8", errors="replace").read()
            m = HEAD.search(body)
            if not m:
                continue
            t += int(m.group(1)); k += int(m.group(2))
            f += int(m.group(3)); e += int(m.group(4))
            n = NAME.search(body)
            if n and n.group(1).endswith("OpsTest") and int(m.group(1)) > int(m.group(2)):
                ops_classes += 1
        rc = 0 if (f == 0 and e == 0) else 1
        if rc:
            bad = True
        total_tests += t; total_fail += f; total_err += e
        print("OPSRECORD task=%s rc=%d classes=%d tests=%d skipped=%d failures=%d errors=%d"
              % (task, rc, len(files), t, k, f, e))

    verdict = "PASS" if (not bad and ops_classes > 0) else "FAIL"
    print("OPSSUMMARY build=ops module=%s tasks=%d tests=%d failures=%d errors=%d "
          "opsclasses=%d buildsec=%s runsec=%s verdict=%s"
          % (module_version(), len(tasks), total_tests, total_fail, total_err,
             ops_classes, build_sec, run_sec, verdict))
    return 0 if verdict == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
