---
name: audit-tree-parity
description: Verify the interface/nonfips and interface/fips native trees honour the twin discipline — byte-identical files everywhere except the sanctioned divergence list (rand.c, rand.h, jostle_lib_ctx.c, bc_err_codes.h, the fips-only/nonfips-only file sets) — and report unsanctioned drift with sync commands. Use this skill whenever the user wants the two trees checked or synchronized — including phrases like "check tree parity", "did the fips tree get the fix", "are the twins in sync", "audit fips/nonfips drift", "sync the trees", "cross-tree check", and similar. Run after ANY edit to interface/ (both-tree fixes are applied deliberately, never automatically) and before declaring a native change done.
---

# Audit fips/nonfips tree parity

The C under `interface/` is two independent copies by design: a fix in `interface/nonfips/util/rsa.c` does NOT propagate to `interface/fips/util/rsa.c`. Divergence is allowed — but almost all of it is *unintentional*, and an unsanctioned difference between twins is the classic cross-tree defect (a bug fixed in one provider and still live in the other). This skill knows exactly which differences are deliberate and flags everything else.

## When to use this skill

1. After any edit under `interface/` — confirm the twin got the same change (or that the divergence was intended and gets added to the sanction list).
2. Before declaring a native change done, alongside the OPS-coverage audits.
3. After multi-agent or multi-session work on the C trees, where a `cp` step is easy to drop.
4. When reviewing someone else's branch: "did the fips tree get the fix?"

## How to run

```bash
python3 .claude/skills/audit-tree-parity/scripts/check-tree-parity.py           # full report
python3 .claude/skills/audit-tree-parity/scripts/check-tree-parity.py --quiet   # violations only
```

Exit 0 = clean, 1 = at least one violation. The script never writes; on drift it prints the diff head plus the `cp` command for **both** directions — choosing the direction is the reviewer's job, because "which tree has the correct version" is exactly the question a sync tool must not answer mechanically.

## The sanctioned divergences (2026-07-12)

1. **Content divergence** (same path, different bytes allowed): `util/rand.c` / `util/rand.h` (the fips tree adds `rand_init_fips`), `util/rand/jostle_lib_ctx.c` (nonfips carries the jrand bridge + `RAND_set_DRBG_type` install; the fips copy had the bridge excised so it cannot be wired in by accident), and `util/bc_err_codes.h` (fips appends the -400 `JO_FIPS_*` block; the shared range MUST still match — the script can't see partial-file drift there, so eyeball new shared codes land in both).
2. **Nonfips-only files**: the algorithm families the FIPS provider doesn't ship (edec, ks, mldsa, mlkem, slhdsa/slh_dsa in util/jni/ffi) plus `jni/open_ssl_jni.c` and `jni/native_info_jni.c` (base init/diagnostic glue; the fips tree has its own `openssl_fips_jni.c`).
3. **Fips-only files**: `util/rand/jostle_fips_ctx.*` and every `*_fips_jni.c` / `*_fips_*` rename-re-include wrapper.

## Interpreting findings

1. **DRIFT in a twin** — the finding this skill exists for. Decide which tree holds the intended content and `cp` it over; if the divergence was actually deliberate, add the path to `DIVERGENT_CONTENT` in the script *with a comment saying why*, in the same change.
2. **FILE-SET violation** — a file added to one tree only. Either add its twin (most native work) or, if it's genuinely single-tree (a new nonfips-only algorithm, a new fips-only wrapper), extend the sanction lists — again with the rationale in the comment.
3. **NOTE: sanctioned-divergent but currently identical** — harmless, but it means the sanction may be stale; consider tightening the list so drift there becomes visible again.

The sanction lists in the script are the machine-readable form of the "Native source layout" rules in CLAUDE.md — when the layout rules change, change the script in the same commit.
