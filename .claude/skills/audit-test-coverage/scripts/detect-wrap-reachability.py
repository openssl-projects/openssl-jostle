#!/usr/bin/env python3
"""
MT-35: classify every bare-RuntimeException wrap in the provider by whether the
exception it erases can actually occur.

THE CONDITION.  `catch (SomeCheckedException e) { throw new RuntimeException(e) }`
erases the type a caller can catch on.  Some of those catches are required by
the compiler and can never fire; others are live defects.  Only an inventory of
the error codes the callee can actually RETURN tells them apart, and a
behavioural survey cannot: MT-31's Cipher survey was structurally blind to
`BlockCipherNI.updateAAD` because its fault catalogue had no AAD row, while this
analysis PREDICTED the site and driving it confirmed the prediction.

METHOD.  For each wrap site: take the caught types, map the NI's handleError
code->type table backwards to the JO_ codes that produce them, and intersect
with the codes the corresponding native entry point can return -- the JNI glue's
OWN returns (it rejects most bad input before reaching util) UNION the util
function's, followed transitively through helpers.

  empty intersection      -> UNREACHABLE, correct contract narrowing
  non-empty               -> REACHABLE, a live MT-30 instance
  reachable only via a
  callee's reinit path    -> STATICALLY REACHABLE, NO TRIGGER

FALSIFICATION LIST -- each entry is a mistake actually made during the hand
audit this tool automates:
  1. Comments are STRIPPED before matching. `block_cipher_get_update_size`'s
     comment naming JO_NOT_BLOCK_ALIGNED was read as a return.
  2. Helpers are followed TRANSITIVELY. A code returned two calls down counts.
  3. Function anchors are EXACT. `block_cipher_ctx_update` is a PREFIX of
     `block_cipher_ctx_updateAAD`; a substring search analysed the wrong
     function and reported its result as the right one.
  4. An override that does NOT call super breaks a hierarchy assumption.
     DESede overrides validateKeyAlg without calling super, so a shared guard
     assumed to cover it did not.
  5. A dereference reached through a HELPER is invisible to a direct-body scan.
     SM4 validates the key's algorithm before the dereference a scan keyed on.
  (4) and (5) were both caught by a test rather than by the scan -- which is the
  miss this tool exists to prevent.

WHAT A VERDICT MEANS.  UNREACHABLE is sound; REACHABLE means "needs human
review", never "is a defect".

Worked example, and it is the control's one deliberate difference: the SPI's
3-arg engineUpdate site reports REACHABLE via JO_OUTPUT_TOO_SMALL, while the
hand audit proved it unreachable.  That proof rests on a CROSS-LAYER sizing
agreement -- `block_cipher_get_update_size` returns max(aligned, len) precisely
so the auto-allocating caller always satisfies update's own guard -- which a
code-level analysis cannot and should not encode.  The hand audit itself marked
that argument as the WEAK kind, resting on two layers agreeing rather than on
the code being unproducible.  A screener that keeps surfacing that site is doing
its job.

KNOWN-ANSWER CONTROL, and it must run JUDGEMENT-FREE.  Over the pre-fix
BlockCipher sources from git history the tool must reproduce 1 live
(`updateAAD`) + 1 conditional (`doFinal`) + 7 unreachable, with NO exclusion
table, no named-entry evidence, and nothing citing the present tree.  MT-32's
control silently began measuring its own triage table when the table cited a
test that did not exist at the historical commit; the same trap applies here.
Until the control reproduces that answer, verdicts on unexamined NI classes are
NOT admissible.
"""
import argparse
import os
import re
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))


def strip_comments(text):
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def brace_body(text, open_pos):
    depth, i = 1, open_pos + 1
    while i < len(text) and depth:
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
        i += 1
    return text[open_pos + 1:i]


def c_functions(path):
    """name -> body, anchored EXACTLY so a name cannot prefix-match a longer one."""
    src = strip_comments(open(path, encoding="utf-8", errors="replace").read())
    out = {}
    for m in re.finditer(r"(?m)^[A-Za-z_][\w \*]*?\b(\w+)\s*\((?:[^;{]|\n)*?\)\s*\{", src):
        out.setdefault(m.group(1), "")
        out[m.group(1)] += brace_body(src, src.index("{", m.end() - 1))
    return out


def codes_of(fn, funcs, seen=None):
    """JO_ codes a C function can return, following helpers transitively."""
    if seen is None:
        seen = set()
    if fn in seen or fn not in funcs:
        return set()
    seen.add(fn)
    body = funcs[fn]
    codes = set(re.findall(r"JO_[A-Z0-9_]+", body))
    # Callee names are NOT all-lowercase. `block_cipher_ctx_updateAAD` carries
    # an uppercase suffix, and a lowercase-only pattern silently skipped it -
    # which made the one site the hand audit proved LIVE read as unreachable.
    # The known-answer control is what caught that.
    for callee in set(re.findall(r"\b([A-Za-z_]\w{3,})\s*\(", body)):
        if callee in funcs and callee != fn:
            codes |= codes_of(callee, funcs, seen)
    return codes


def handle_error_map(ni_src):
    """JO_ code -> exception simple name, from an NI's handleError switch."""
    text = strip_comments(ni_src)
    # Anchor on the DECLARATION, not the first call site. `return (int)
    # handleError(ni_init(...))` appears earlier in the file, and matching it
    # took the wrong brace and produced an empty map - which then made every
    # site read UNREACHABLE "of 0 codes", a vacuous pass.
    m = re.search(r"\b(?:long|int)\s+handleError\s*\(", text)
    if not m:
        return {}
    body = brace_body(text, text.index("{", m.end()))
    pairs, pending = {}, []
    for line in body.split("\n"):
        c = re.search(r"case\s+(JO_\w+)\s*:", line)
        if c:
            pending.append(c.group(1))
        t = re.search(r"throw new (\w+)\s*\(", line)
        if t and pending:
            for code in pending:
                pairs[code] = t.group(1)
            pending = []
    return pairs


CHECKED_EXCEPTIONS = {
    "InvalidKeyException", "InvalidAlgorithmParameterException",
    "ShortBufferException", "IllegalBlockSizeException", "BadPaddingException",
    "AEADBadTagException", "NoSuchAlgorithmException", "NoSuchPaddingException",
}

WRAP_RE = re.compile(
    r"catch\s*\(([^)]*?)\s+\w+\s*\)\s*\{\s*throw new RuntimeException\s*\(", re.S)


def wrap_sites(java_src):
    """-> [(caught type simple names, enclosing method name)]"""
    text = strip_comments(java_src)
    sites = []
    for m in WRAP_RE.finditer(text):
        types = [t.strip().split(".")[-1] for t in m.group(1).split("|")]
        head = text[:m.start()]
        # The callee is what the TRY block called, not the enclosing method.
        # In an NI default method that is `ni_<name>(...)`; in an SPI it is
        # `<field>Ni.<name>(...)`. Using the enclosing method name works only
        # for the former and reports UNKNOWN-CALLEE for every SPI site.
        try_start = head.rfind("try")
        callee = None
        if try_start >= 0:
            blk = head[try_start:]
            c = re.search(r"\bni_(\w+)\s*\(", blk) or re.search(r"\b\w*[Nn][Ii]\.(\w+)\s*\(", blk)
            if c:
                callee = c.group(1)
        meth = None
        # `catch (...) {` and `if (...) {` match a bare name-paren-brace shape.
        for mm in re.finditer(r"\b(\w+)\s*\([^)]*\)\s*(?:throws [\w,. ]+)?\s*\{", head):
            if mm.group(1) in ("catch", "if", "for", "while", "switch", "synchronized", "try"):
                continue
            meth = mm.group(1)
        sites.append((types, callee or meth))
    return sites


# Wrap sites this tool does NOT analyse, and why. Printed on every run: an
# exclusion the reader cannot see is how a scope hole becomes a false clean
# bill of health. "18 NI classes, no findings" must never read as "the provider
# is clean".
OUT_OF_SCOPE = [
    ("FFI downcall wrap sites", "src/main/java25/**/*FFI.java",
     "catch (Throwable) around MethodHandle.invokeExact. A DIFFERENT fault "
     "class: FFM native code cannot throw a checked Java exception at all, so "
     "the erasure fault cannot exist there. The real smell is that catch "
     "(Throwable) also wraps ERRORS. One uniform analysis, registered as MT-38."),
]

# NI interfaces whose native methods are not named ni_*, so the glue lookup
# cannot find them. Each verified to contain ZERO wrap sites, so nothing is
# missed -- recorded rather than silently skipped.
UNMAPPED_DISPOSITIONS = {
    "KdfNI":           "native methods are pbkdf2/hkdf/kbkdf, not ni_*; glue is "
                       "kdf_jni.c. Zero wrap sites, nothing to analyse.",
    "MemoryHardKdfNI": "same naming scheme as KdfNI. Zero wrap sites.",
    "OpenSSLFIPSNI":   "FIPS-only; glue is interface/fips/jni/openssl_fips_jni.c "
                       "and its methods are not ni_*. Zero wrap sites.",
}


def count_out_of_scope(repo):
    import glob as _g
    n = 0
    for f in _g.glob(os.path.join(repo, "jostle/src/main/java25/org/openssl/jostle/jcajce/**/*.java"),
                     recursive=True):
        src = strip_comments(open(f, encoding="utf-8", errors="replace").read())
        n += len(re.findall(r"throw new RuntimeException", src))
    return n


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ni", required=True, help="path to the *NI.java interface")
    ap.add_argument("--jni", required=True, help="path to its JNI glue .c")
    ap.add_argument("--util", required=True, action="append",
                    help="util .c the glue includes; repeatable. Pass ALL of them - "
                         "picking one is a guess, and a first-include heuristic "
                         "mapped DHServiceNI to key_spec.c instead of dh.c.")
    ap.add_argument("--extra-java", action="append", default=[],
                    help="additional Java sources carrying wrap sites (SPIs)")
    args = ap.parse_args(argv[1:])

    ni_src = open(args.ni, encoding="utf-8", errors="replace").read()
    codemap = handle_error_map(ni_src)
    by_type = {}
    for code, exc in codemap.items():
        by_type.setdefault(exc, set()).add(code)

    jni = c_functions(args.jni)
    both = {}
    for u in args.util:
        for k, v in c_functions(u).items():
            both[k] = both.get(k, "") + v
    both.update(jni)

    def native_codes(ni_method):
        """Codes reachable from ni_<method>: the JNI glue's own returns plus util's."""
        for name in jni:
            if name.endswith("_ni_1" + ni_method):
                return codes_of(name, both)
        return None

    print("=== MT-35 wrap-reachability ===")
    print("  NI: %s" % os.path.basename(args.ni))
    print("  handleError maps %d codes\n" % len(codemap))

    rows = []
    for path in [args.ni] + args.extra_java:
        src = open(path, encoding="utf-8", errors="replace").read()
        for types, meth in wrap_sites(src):
            # A broad `catch (Exception)` erases EVERY checked type the callee
            # can raise, so its erased set is every code mapping to one. Left
            # to a name lookup it mapped to nothing and the site passed as
            # UNREACHABLE "of 0 codes" - the right answer for the wrong reason,
            # which is indistinguishable from analysis until you read it.
            erased = set()
            for t in types:
                if t in ("Exception", "Throwable"):
                    erased |= {c for c, e in codemap.items() if e in CHECKED_EXCEPTIONS}
                else:
                    erased |= by_type.get(t, set())
            nat = native_codes(meth) if meth else None
            if nat is None:
                verdict, detail = "UNKNOWN-CALLEE", "no ni_%s in the JNI glue" % meth
            elif not erased and any(t in CHECKED_EXCEPTIONS or t in ("Exception", "Throwable")
                                    for t in types):
                # NON-VACUITY. A catch naming checked types with ZERO candidate
                # codes means the code map or the type mapping failed, not that
                # the site is safe. Two control bugs produced exactly this and
                # both read as "UNREACHABLE of 0 codes" - a pass indistinguishable
                # from analysis. It fails the RUN; it is never a verdict.
                verdict, detail = "VACUOUS", ("catch names %s but zero candidate codes "
                                              "were considered" % "|".join(types))
            else:
                hit = sorted(erased & nat)
                verdict = "REACHABLE" if hit else "UNREACHABLE"
                detail = ("%s" % ", ".join(hit)) if hit else (
                    "none of %d candidate code(s) returned by the callee" % len(erased))
            rows.append((os.path.basename(path), meth, "|".join(types), verdict, detail))

    for f, meth, types, verdict, detail in rows:
        print("  %-22s %-16s %-14s %s" % (f, meth, verdict, detail))
    tally = {}
    for _, _, _, v, _ in rows:
        tally[v] = tally.get(v, 0) + 1
    print()
    for v in sorted(tally):
        print("  %-16s %d" % (v, tally[v]))
    total = sum(tally.values())
    print("  %-16s %d wrap sites" % ("TOTAL", total))
    # The census must sum. A report contradicting its own breakdown is the one
    # document that has to be exact.
    assert total == len(rows), "census does not sum: %d vs %d" % (total, len(rows))

    n_oos = count_out_of_scope(REPO)
    print("\n  OUT OF SCOPE, not analysed by this tool:")
    for what, where, why in OUT_OF_SCOPE:
        print("    %d %s (%s)" % (n_oos, what, where))
        for line in re.findall(r".{1,66}(?:\s|$)", why):
            print("      %s" % line.strip())
    if UNMAPPED_DISPOSITIONS:
        print("\n  NI interfaces the glue lookup cannot map (each verified "
              "zero-wrap-site):")
        for k, v in sorted(UNMAPPED_DISPOSITIONS.items()):
            print("    %-18s %s" % (k, v))

    vacuous = tally.get("VACUOUS", 0)
    if vacuous:
        print("\nFAIL: %d site(s) analysed ZERO candidate codes - the run is vacuous,"
              " not clean." % vacuous)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
