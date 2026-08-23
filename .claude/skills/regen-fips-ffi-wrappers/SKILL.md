---
name: regen-fips-ffi-wrappers
description: Regenerate or verify the interface/fips/ffi/<x>_fips_ffi.c rename wrappers that give the FIPS interface library JoFIPS_-prefixed exports. Use whenever an FFI entry point is added, renamed or removed in either native tree, whenever FIPS_FFI_GLUE_SOURCES is edited, and as a check before declaring native work done — including phrases like "I added an FFI entry point", "regenerate the FIPS wrappers", "are the FIPS FFI symbols still disjoint", "why does the FIPS library not export X". Exists because a hand-edited or forgotten wrapper produces a FIPS library that silently lacks an entry point, or one whose twin is compiled twice.
---

# Regenerate the FIPS FFI rename wrappers

The FIPS interface library must export **no entry-point name the base library
also exports**. It achieves that with 21 generated wrappers under
`interface/fips/ffi/`: each `#define`s every `Jo`-named export of its
byte-identical twin to a `JoFIPS_`-prefixed name, then `#include`s the twin —
the same trick `fips/jni/<x>_fips_jni.c` uses for JNI.

**Never hand-edit a `<x>_fips_ffi.c`.** They are generated, and a hand-edit is
invisible until the specific entry point it broke is first called.

```bash
# Regenerate (writes only files whose content would change):
python3 .claude/skills/regen-fips-ffi-wrappers/scripts/regen-wrappers.py

# Verify without writing — use before declaring native work done:
python3 .claude/skills/regen-fips-ffi-wrappers/scripts/regen-wrappers.py --check
```

Run from the repo root. Exit 0 consistent, 1 problems found, 3 wrong directory.

## When to run it

1. **An FFI entry point was added, renamed or removed** in either tree. The
   wrapper for that file needs a new/changed/dropped `#define`.
2. **A new `ffi/*.c` glue file was added.** It needs a whole new wrapper, and
   that wrapper needs a `FIPS_FFI_GLUE_SOURCES` entry.
3. **`FIPS_FFI_GLUE_SOURCES` was edited** — the checker catches a twin left
   listed alongside its wrapper, which duplicates every symbol in that file.
4. **Before declaring native work done**, alongside `audit-tree-parity`.

## What `--check` catches

| Detection | Why it matters |
|---|---|
| wrapper missing or stale | the FIPS library silently lacks that entry point; the Java lookup throws only when that path first runs |
| orphaned wrapper | its twin is gone; the build fails or compiles dead code |
| wrapper not in `FIPS_FFI_GLUE_SOURCES` | the whole file is absent from the FIPS library |
| twin listed *as well as* its wrapper | the twin is compiled twice — duplicate symbol at link |
| a glue function called across glue files | per-file renaming would leave that call unresolved in the FIPS library (see below) |

All five were falsified by breaking each one deliberately and confirming the
checker fires.

## The precondition worth understanding

Per-file `#define` renaming is only correct because **no glue function calls
another glue function across files**. If `md_ffi.c` ever called
`JoMAC_allocate`, that call sits in `md_ffi.c`'s translation unit, which carries
`md_fips_ffi.c`'s `#define` block and *not* `mac_fips_ffi.c`'s — so it would
reference the unrenamed `JoMAC_allocate`, which the FIPS library does not
export, and fail to link. The checker scans for this (comments stripped, so a
mention in prose is not a false positive). If it ever fires, the fix is to add
the same `#define` to the calling file's wrapper, not to suppress the check.

## What it deliberately does not touch

1. **`openssl_fips_ffi.c`** — FIPS-only, already `JoFIPS_`-named, not a twin. It
   also owns `JoFIPS_get_openssl_errors`. There is **no `openssl_ffi.c` in the
   FIPS tree** and no wrapper for one: until 2026-08-23 the twin was re-included
   purely to reach `JoOpenSSL_getErrors`, which also exported
   `JoOpenSSL_setModule` — a function that builds a lib ctx with
   `jostle_ctx_init_new` (no fipsinstall config, no `fips=yes` properties) and
   installs it as the FIPS global. Nothing bound it, but its only possible
   effect was to make FIPS fetches resolve to mainline, and `fips/jni/` never
   carried the equivalent. Pinned by
   `FIPSLibraryLookupParityTest.fipsLibraryDoesNotCarryTheBaseInitGlue`. Do not
   re-add the twin to save writing a small function.
2. **`rand_upcall_ffi.c`** — defines no `Jo` export (internal, called from C).
   Reported as "not wrapped" rather than treated as an error.
3. **`util/` symbols.** Only `ffi/` glue is wrapped. A util function the Java
   layer resolves directly (`set_ops_test`, `OPS_GetRandomBytes`) cannot use the
   re-include trick — util compiles once into the library, so re-including it
   duplicates every symbol. Add a `Jo`-named forwarder in the glue instead;
   `ffi/ops_ffi.c` is the reference, twinned across both trees like any other
   glue file.
4. **The base tree.** Base exports keep their plain `Jo*` names.

## Related guards

The generator keeps the wrappers correct. Two JUnit tests keep the *property*
correct, and both run on ordinary non-FIPS CI legs:

1. `FIPSLibraryLookupParityTest.everyResolvedFfiSymbolIsJoPrefixed` — every FFI
   symbol the Java layer resolves starts with `Jo`.
2. `FIPSLibraryLookupParityTest.builtLibrariesHaveDisjointEntryPoints` — probes
   the built artefacts: the FIPS library exports `JoFIPS_X` and not `X`, the base
   library the reverse.
3. `FIPSLibraryLookupParityTest.fipsLibraryDoesNotCarryTheBaseInitGlue` — the
   FIPS library owns `JoFIPS_get_openssl_errors` and exports neither spelling of
   the base `JoOpenSSL_*` init glue.
4. `FIPSLibraryLookupParityTest.libCtxAccessorsAreNamedApartAcrossTheTwoLibraries`
   — the lib ctx accessors are `get/set_global_jostle_fips_*` in the FIPS library
   and unprefixed in the base one, so neither name exists in both.

Background: `reviews/fips-ffi-distinct-symbols-plan.md`, and the
symbol-collision section of `.claude/guides/native-code.md`.
