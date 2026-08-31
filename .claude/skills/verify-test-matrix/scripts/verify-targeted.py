#!/usr/bin/env python3
"""
Verify that a TARGETED test run actually ran what was asked and nothing else.

A filter that silently WIDENS is the same instrument fault as a wrapper
reporting exit 0 for a failed build: the run looks scoped and is not, so the
"iteration run" quietly becomes a full suite and its speed claim is a fiction.
A filter that silently DROPS a requested class is worse — it reports green for
a class that never executed, which is the presence-checker fault.

This refuses both, by exactness rather than by a count heuristic:

  * every requested class must have >= 1 executed test in at least one task
    (a class can legitimately live in only the unit or only the integration
    tasks, so "in at least one" is the right quantifier, not "in each");
  * no class OUTSIDE the requested set may have executed at all.

Exit 0 only when both hold and there are no failures or errors.
"""
import argparse
import glob
import os
import sys
import xml.etree.ElementTree as ET


def simple_name(fqcn):
    return fqcn.rsplit(".", 1)[-1]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--task", action="append", required=True,
                    help="gradle test task whose results to inspect (repeatable)")
    ap.add_argument("--class", dest="classes", action="append", required=True,
                    help="simple class name that was requested (repeatable)")
    ap.add_argument("--results-root", default="jostle/build/test-results")
    args = ap.parse_args()

    requested = set(args.classes)
    ran = {}          # simple name -> executed count, summed across tasks
    failures = 0
    unrequested = {}  # simple name -> executed count
    missing_dirs = []

    for task in args.task:
        d = os.path.join(args.results_root, task)
        files = glob.glob(os.path.join(d, "TEST-*.xml"))
        if not files:
            missing_dirs.append(task)
            continue
        for f in files:
            root = ET.parse(f).getroot()
            fqcn = root.get("name") or ""
            name = simple_name(fqcn)
            total = int(root.get("tests") or 0)
            skipped = int(root.get("skipped") or 0)
            executed = total - skipped
            failures += int(root.get("failures") or 0) + int(root.get("errors") or 0)
            if name in requested:
                ran[name] = ran.get(name, 0) + executed
            elif executed > 0:
                unrequested[name] = unrequested.get(name, 0) + executed

    problems = []

    # A task with no result XML is NORMAL here and not by itself a fault: the
    # integration tasks carry their own include filter (*LimitTest, *OpsTest,
    # *IntegrationTest), so a plain unit class legitimately matches nothing
    # there and gradle runs no tests at all. What must never be tolerated is a
    # requested class running NOWHERE, and that is the never_ran check below —
    # which stays fatal precisely so demoting this one cannot let an empty run
    # pass as green.
    notes = []
    if missing_dirs:
        notes.append("no result XML for task(s): %s — expected when no requested "
                     "class lives there" % ", ".join(missing_dirs))

    never_ran = sorted(c for c in requested if ran.get(c, 0) == 0)
    if never_ran:
        problems.append("requested but ZERO tests executed: %s — the filter "
                        "dropped them (a misspelt class name reports exactly "
                        "like this, and would otherwise pass as green)"
                        % ", ".join(never_ran))

    if unrequested:
        top = sorted(unrequested.items(), key=lambda kv: -kv[1])[:8]
        problems.append("the filter WIDENED: %d unrequested class(es) executed, "
                        "e.g. %s — this was not a targeted run"
                        % (len(unrequested),
                           ", ".join("%s(%d)" % (k, v) for k, v in top)))

    if failures:
        problems.append("%d test failure(s)/error(s)" % failures)

    print("targeted-run verification")
    print("  tasks     : %s" % ", ".join(args.task))
    print("  requested : %s" % ", ".join(sorted(requested)))
    for c in sorted(requested):
        print("      %-42s executed=%d" % (c, ran.get(c, 0)))
    print("  unrequested classes executed: %d" % len(unrequested))
    for n in notes:
        print("  note: %s" % n)

    if problems:
        print()
        for p in problems:
            print("FAIL: %s" % p)
        return 1

    print("  OK — exactly the requested classes ran, no failures")
    return 0


if __name__ == "__main__":
    sys.exit(main())
