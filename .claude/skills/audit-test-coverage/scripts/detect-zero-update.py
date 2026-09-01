#!/usr/bin/env python3
"""
MT-32: find Cipher transformations whose tests never drive a data-path update().

THE CONDITION.  A JCA transformation with update()/doFinal() promises that any
split of the same input yields the same output.  A transformation exercised only
by one-shot doFinal calls has that whole promise untested, however many vectors
it has -- and the per-name completeness guards cannot see it, because every name
IS covered.  Three instances were found by hand in one arc (AES key wrap,
ChaCha20-Poly1305, AES WRAP_INV); a fourth should not be.

WHAT THIS TOOL CAN AND CANNOT SEE.  Stated up front because a detector whose
limits are undocumented gets trusted past them:

  1. Coverage is attributed at FILE granularity.  A file that drives five
     transformations and updates one attributes coverage to all five.  That is
     an over-attribution, and it is the granularity that would have caught all
     three known instances (each was a whole file with zero update calls).
  2. The literal-zero check cannot see a VARIABLE holding zero, nor an
     `update(new byte[0])` shape.  The live trap instance
     (AESAgreementTest.exercise_complexUpdateDoFinal's `update(input, off, 0)`)
     is a literal, so the encoding is right for it.
  3. Receiver typing is by local declaration (`Cipher x = ...`).  A Cipher
     reached through a field or a method return is not recognised as one.
  4. A method declaration must begin a line to be recognised as one. True of
     every source in this tree; a one-line `class T { void a(){...} }` is not
     seen, which matters only for synthetic snippets.
  5. The exclusion source is the MT-3 PIN/CLOSE table in the planning notes,
     which is NOT tracked in git.  Absent, the tool FAILS rather than silently
     running with no exclusions -- an unavailable input must not degrade into a
     quiet answer.

FOUR CLASSIFICATIONS, never two.  COVERED / UNCOVERED / COVERED-BY-DRIVER /
UNRESOLVED.  An unanswerable cell must never read as covered, and every
UNRESOLVED site must appear in UNRESOLVED_CLASSIFICATIONS below with a reason --
an unclassified one FAILS the run.  A percentage floor was considered and
rejected: it hides identity ("61 unresolved" names none of them) and, set at
today's mass, silently absorbs growth up to it.
"""
import argparse
import os
import re
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
PLAN = os.path.join(REPO, "reviews", "misc-tasks-plan.md")
SERVICES = os.path.join(REPO, "SERVICES.md")
TEST_ROOTS = [
    os.path.join(REPO, "jostle", "src", "test", "java", "org", "openssl", "jostle", "test"),
    os.path.join(REPO, "jostle", "src", "test", "java25", "org", "openssl", "jostle", "test"),
]

# Sites where a transformation cannot be resolved statically. Each entry is a
# reviewed CLAIM, not a suppression: site -> (reason, covering evidence).
# An unresolved site absent from here fails the run.
UNRESOLVED_CLASSIFICATIONS = {
    # -- transformation TABLES iterated at runtime; the tool cannot enumerate
    #    the elements, so these sites make no coverage claim either way.
    "name":              "loop variable over a per-file name table (wrap OIDs, surface sweeps)",
    "oid":               "loop variable over an OID table",
    "oids[i]":           "element of a per-file OID table",
    "KEM_OIDS[i]":       "element of the ML-KEM KTS OID table",
    "c[0]":              "element of a per-case parameter table",
    "e[1]":              "element of a per-case expectation table",
    "m.transformation":  "field of ChunkingContractTest's Mode table -- this is the "
                         "file that DOES the chunking, so its invisibility is why "
                         "several modes below need an UNCOVERED classification",
    "transformation":    "loop variable over a transformation table",
    "transform":         "loop variable over a transformation table",
    "alg":               "loop variable over an algorithm table / provider sweep",
    "cipherName":        "loop variable over the ChaCha20 spelling variants",
    "ariaCbcOid":        "OID held in a local, resolved from a table at runtime",
    "camCbcOid":         "OID held in a local, resolved from a table at runtime",

    # -- method parameters of drivers: one indirection past the approved rule.
    "xform":             "driver-method parameter; where the driver itself chunks it "
                         "is credited by the helper rule, otherwise the caller is a "
                         "non-chunking driver and makes no claim",
    "xf":                "driver-method parameter",

    # -- constants declared in a SUPERCLASS, so not visible in this file.
    "XFORM":             "constant declared in the superclass, not the file scanned",

    # -- negative tests: these transformations must be REFUSED, so no coverage
    #    claim is intended or wanted.
    "bad":               "inline table of transformations asserted to be REFUSED "
                         "(AESCTSTest: CTS with a padding scheme); a negative test",
}

# Explained UNCOVERED transformations: reason + the evidence that the gap is not
# a real one. An UNCOVERED entry absent from here is a genuine finding.
UNCOVERED_CLASSIFICATIONS = {
    # One indirection past the approved helper rule: the Cipher comes from a
    # same-file FACTORY method rather than from getInstance directly
    # (`Cipher c = jsl(ENCRYPT_MODE, key, iv)`). Per the one-level ruling this
    # is the pressure valve, not a third resolution rule. Each DOES chunk.
    "AES/CFB1/NOPADDING":      "AESCFB1Test chunks via a jsl(...) factory; see its "
                               "random-split loop and byte-wise loop",
    "DESEDE/CBC/NOPADDING":    "DESedeAgreementTest chunks (byte-wise 3-arg update "
                               "and the 5-arg offset-write path)",
    "DESEDE/CBC/PKCS7PADDING": "as DESEDE/CBC/NOPADDING",
    "DESEDE/ECB/NOPADDING":    "as DESEDE/CBC/NOPADDING",
    "1.2.840.113549.3.7":      "the DESede-CBC OID, same suite as above",

    # One-shot by contract - update() is not part of what they promise.
    "AES/CCM":                 "CCM is one-shot by contract (AESCCMCipherSpi); the "
                               "PIN/CLOSE table records the same",
    "AES/CCM/PKCS5PADDING":    "as AES/CCM",
    "ML-KEM":                  "a KTS cipher driven through wrap/unwrap only",

    # Deliberate negative-test strings that reach the universe because their
    # BASE algorithm is registered.
    "AES/NOTAREALMODE/NOPADDING": "a deliberate unknown-mode string asserted to be "
                                  "refused, not a transformation we serve",

    # Covered by ChunkingContractTest, whose Mode table is reached through the
    # unresolvable `m.transformation` (see UNRESOLVED_CLASSIFICATIONS). Verified
    # against its modes() list rather than assumed.
    "AESWRAP":                 "ChunkingContractTest modes() line 142",
    "AES/KW/NOPADDING":        "alias spelling of AESWRAP; same coverage",
    "2.16.840.1.101.3.4.1.5":  "AES-128 key-wrap OID; alias of AESWRAP",
    "AES/KWP/NOPADDING":       "alias spelling of AESWRAPPAD; ChunkingContractTest line 143",
    "CHACHA20-POLY1305":       "ChunkingContractTest modes() line 149",
    "AES/CFB/NOPADDING":       "ChunkingContractTest modes() line 152",

    # Sites that make no chunking claim: the transformation is named to build a
    # key or to exercise a PARAMETERS codec, not to drive data.
    "AES":                     "AESKeyGeneratorTest names it to generate keys",
    "AES/CBC/ISO10126PADDING": "AESParametersTest exercises the parameters codec",
    "2.16.840.1.101.3.4.1.46": "AESParametersTest exercises the parameters codec",
    "ARIA192":                 "a key-size spelling used for keygen, not a data path",

    # RSA is one-shot in practice: a single modulus-sized block, and the SPIs
    # buffer to it. update() carries no split contract worth pinning.
    "RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING": "RSA is one-shot; no split contract",
    "RSA/ECB/OAEPWITHSHA-512ANDMGF1PADDING": "RSA is one-shot; no split contract",
    "RSA/ECB/OAEPWITH":        "a truncated concatenation fragment of the OAEP names",
    "RSA/NONE/PKCS1PADDING":   "RSA is one-shot; no split contract",
}

# Helpers that drive a whole family enumerated from the provider, so the
# transformation names appear in no test source at all. Value is the evidence
# that the helper makes a qualifying update() call per transformation.
#
# EMPTY, and that is the measured answer rather than an unfilled slot. Both
# surface drivers were checked and NEITHER chunks:
#   CipherSurfaceDriver  - doFinal + wrap/unwrap only, zero update() calls
#   DESedeSurfaceDriver  - doFinal only
# They are invoked from five agreement tests plus a FIPS twin and sweep every
# registered name in their family. So the names they reach are not "unknown to
# the tool" - they are DRIVEN ONE-SHOT ONLY, which is this detector's own
# condition at surface scale. Registered as MT-37; see the NOT DRIVEN note.
DRIVER_HELPERS = {}

NON_CHUNKING_DRIVERS = ("CipherSurfaceDriver.driveWholeSurface",
                        "DESedeSurfaceDriver")


def close_verdict_modes(plan_path):
    """Modes the PIN/CLOSE table marks CLOSE: no caller can drive them."""
    if not os.path.exists(plan_path):
        sys.stderr.write(
            "FAIL: exclusion source not found: %s\n"
            "The MT-3 PIN/CLOSE table is the single source of CLOSE verdicts.\n"
            "Refusing to run with no exclusions rather than reporting unreachable\n"
            "modes as uncovered.\n" % plan_path)
        sys.exit(2)
    modes = set()
    for line in open(plan_path, encoding="utf-8"):
        if "**CLOSE**" in line and line.lstrip().startswith("|"):
            cells = [c.strip() for c in line.split("|")]
            if len(cells) > 1 and cells[1]:
                modes.add(cells[1].upper())
    return modes


def registered_cipher_names(services_path):
    """Cipher names from the generated SERVICES.md (both provider sections)."""
    if not os.path.exists(services_path):
        return set()
    names, in_cipher = set(), False
    for line in open(services_path, encoding="utf-8"):
        if line.startswith("## "):
            in_cipher = line.startswith("## Cipher (")
            continue
        if in_cipher:
            m = re.match(r"\s*\d+\.\s+`([^`]+)`", line)
            if m:
                names.add(m.group(1).upper())
    return names


def java_files():
    for root in TEST_ROOTS:
        for dirpath, _, filenames in os.walk(root):
            for fn in filenames:
                if fn.endswith(".java"):
                    yield os.path.join(dirpath, fn)


def strip_comments(text):
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


# Any String-to-literal binding in the file, not only `static final`. The live
# shape is a LOCAL: `String xform = "AES/GCM/NoPadding";` handed to a helper that
# calls getInstance(xform, ...). Resolving only constants reported GCM, OCB and
# the wraps as uncovered when they are heavily exercised - a false positive that
# would have discredited the whole report.
#
# A name may bind to SEVERAL literals in one file (AESAgreementTest assigns
# `xform` five times). All of them count: attribution is file-granular anyway,
# so the file genuinely drives all five.
CONST_RE = re.compile(r"\bString\s+(\w+)\s*=\s*\"([^\"]+)\"")
GETINSTANCE_RE = re.compile(r"\bCipher\s*\.\s*getInstance\s*\(\s*([^,()]+?)\s*[,)]")
CIPHER_VAR_RE = re.compile(r"\bCipher\s+(\w+)\s*[=;]")
CLASS_RE = re.compile(r"\bclass\s+(\w+)\s+extends\s+(\w+)")


ASSIGN_RE = re.compile(
    r"\bCipher\s+(\w+)\s*=\s*Cipher\s*\.\s*getInstance\s*\(\s*([^,()]+?)\s*[,)]")


def _resolve(arg, consts):
    arg = arg.strip()
    if arg.startswith('"') and arg.endswith('"'):
        return {arg[1:-1].upper()}
    if arg in consts:
        return {v.upper() for v in consts[arg]}
    return set()


def _qualifying_update(text, var):
    """A data-path update() on `var` with a non-literal-zero length."""
    for m in re.finditer(r"\b%s\s*\.\s*update\s*\(" % re.escape(var), text):
        tail = text[m.end():m.end() + 400]
        depth, args, cur = 1, [], ""
        for ch in tail:
            if ch in "([{":
                depth += 1
            elif ch in ")]}":
                depth -= 1
                if depth == 0:
                    args.append(cur)
                    break
            if depth == 1 and ch == ",":
                args.append(cur)
                cur = ""
            else:
                cur += ch
        if len(args) >= 3 and args[-1].strip() == "0":
            continue          # exercises nothing
        return True
    return False



METHOD_RE = re.compile(
    r"(?:^|\n)\s*(?:public|private|protected|static|final|abstract|synchronized|\s)+"
    r"[\w<>\[\],. ]+?\s+(\w+)\s*\(([^)]*)\)\s*(?:throws [\w,. ]+)?\s*\{")


def _body_after(text, brace_pos):
    depth, i = 1, brace_pos + 1
    while i < len(text) and depth:
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
        i += 1
    return text[brace_pos + 1:i]


def _split_top_level(argstr):
    out, depth, cur = [], 0, ""
    for ch in argstr:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                break
            depth -= 1
        if depth == 0 and ch == ",":
            out.append(cur); cur = ""
        else:
            cur += ch
    out.append(cur)
    return [a.strip() for a in out]


def update_driving_helpers(text):
    """(method name -> parameter index) for helpers that CHUNK what they are given.

    Qualifies ONLY when the SAME method both binds `Cipher v =
    Cipher.getInstance(p, ...)` with `p` its own parameter AND drives a
    qualifying update on `v`. The sibling shape - caller builds the Cipher, a
    helper updates it - is deliberately NOT covered; it surfaces as UNCOVERED
    and gets a named-table entry, which is the pressure valve rather than
    deeper resolution.

    One level only. A second indirection lands in UNCOVERED by design.
    """
    helpers = {}
    for m in METHOD_RE.finditer(text):
        name, params = m.group(1), m.group(2)
        pnames = []
        for prm in _split_top_level(params):
            toks = prm.replace("...", " ").split()
            if toks:
                pnames.append(toks[-1].strip("[]"))
        if not pnames:
            continue
        body = _body_after(text, text.index("{", m.end() - 1))
        for a in ASSIGN_RE.finditer(body):
            var, arg = a.group(1), a.group(2).strip()
            if arg in pnames and _qualifying_update(body, var):
                helpers[name] = pnames.index(arg)
                break
    return helpers


def helper_credited(text, consts, helpers):
    """Transformations passed as the driving argument at a helper's call sites."""
    credited = set()
    for name, idx in helpers.items():
        for m in re.finditer(r"\b%s\s*\(" % re.escape(name), text):
            args = _split_top_level(text[m.end():m.end() + 600])
            if len(args) > idx:
                credited |= _resolve(args[idx], consts)
    return credited


def scan_file(path):
    """-> (drives, updated, unresolved, file_has_update, class, parent)

    `drives`  every transformation the file names resolvably.
    `updated` those whose OWN Cipher variable takes a qualifying update().

    Binding per VARIABLE, not per file. File granularity credited
    ChaCha20-Poly1305 as covered because ChaCha20AgreementTest names it while
    updating a plain ChaCha20 cipher - it missed a known instance by
    over-attribution, measured against the pre-MT-3 tree.
    """
    raw = open(path, encoding="utf-8", errors="replace").read()
    text = strip_comments(raw)

    consts = {}
    for m in CONST_RE.finditer(text):
        consts.setdefault(m.group(1), set()).add(m.group(2))

    drives, unresolved = set(), set()
    for m in GETINSTANCE_RE.finditer(text):
        got = _resolve(m.group(1), consts)
        if got:
            drives |= got
        else:
            unresolved.add(m.group(1).strip())

    updated = set()
    helpers = update_driving_helpers(text)
    updated |= helper_credited(text, consts, helpers)

    # Bind within the ENCLOSING METHOD, not the file. A file-wide search for
    # `<var>.update(` credits an assignment in one method from a same-named
    # variable in another - the constructed "caller builds, helper updates"
    # case was credited that way, which condition 2 excludes. Two different
    # `Cipher c` in two methods are two different ciphers.
    for m in METHOD_RE.finditer(text):
        body = _body_after(text, text.index("{", m.end() - 1))
        for a in ASSIGN_RE.finditer(body):
            got = _resolve(a.group(2), consts)
            if got and _qualifying_update(body, a.group(1)):
                updated |= got

    # Whether the file updates ANY cipher - inherited by subclasses, which
    # commonly add transformation names to a parent that does the driving.
    file_has_update = any(
        _qualifying_update(text, v) for v in set(CIPHER_VAR_RE.findall(text)))

    m = CLASS_RE.search(text)
    cls, parent = (m.group(1), m.group(2)) if m else (None, None)
    return drives, updated, unresolved, file_has_update, cls, parent


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--plan", default=PLAN)
    ap.add_argument("--services", default=SERVICES)
    ap.add_argument("--test-root", action="append", dest="roots")
    ap.add_argument("--no-classifications", action="store_true",
                    help="Report raw detection, ignoring the EXPLAINED/UNRESOLVED "
                         "tables. REQUIRED for the historical known-answer control: "
                         "the classifications describe TODAY's tree and cite "
                         "evidence (ChunkingContractTest) that did not exist at the "
                         "historical commit, so applying them there suppresses the "
                         "very instances the control must see. The control must "
                         "measure the DETECTOR, never the triage.")
    args = ap.parse_args(argv[1:])

    global TEST_ROOTS
    if args.roots:
        TEST_ROOTS = [os.path.abspath(r) for r in args.roots]

    excluded_modes = close_verdict_modes(args.plan)
    registered = registered_cipher_names(args.services)

    drives = {}          # transformation -> set of files
    covered_transforms = set()
    class_of, file_of_class, parent_of = {}, {}, {}
    updating_files = set()
    unresolved_sites = {}

    for path in java_files():
        rel = os.path.relpath(path, REPO)
        resolved, updated, unresolved, has_update, cls, parent = scan_file(path)
        for t in updated:
            covered_transforms.add(t)
        if cls:
            class_of[rel] = cls
            file_of_class[cls] = rel
            if parent:
                parent_of[cls] = parent
        if has_update:
            updating_files.add(rel)
        for t in resolved:
            drives.setdefault(t, set()).add(rel)
        for u in unresolved:
            unresolved_sites.setdefault(u, set()).add(rel)

    # A subclass INHERITS its parent's update-driving methods. The FIPS twins
    # are the live case: FIPSAESAgreementTest extends AESAgreementTest and makes
    # no update() call of its own, so without this every transformation named
    # only in a twin reported as uncovered. Walk the chain, bounded.
    for rel, cls in list(class_of.items()):
        seen, cur = set(), cls
        while cur and cur not in seen:
            seen.add(cur)
            prel = file_of_class.get(cur)
            if prel and prel in updating_files:
                updating_files.add(rel)
                break
            cur = parent_of.get(cur)

    # The universe is PROVIDER-DERIVED. Test-extracted names only ever match
    # INTO it; one that matches nothing registered goes to a side list rather
    # than entering the universe or vanishing. A deliberate negative-test string
    # lands there harmlessly and a real typo becomes VISIBLE instead of being
    # silently dropped.
    # A fragment like "RSA/ECB/OAEPWITH" passes this, because any
    # BASE/mode/padding expansion of a registered cipher must - MT-36's genuine
    # finding is exactly such an expansion, and filtering them into the side
    # list would lose it. The failure direction is safe: a fragment can never be
    # falsely COVERED, since its getInstance throws and no variable-bound update
    # can credit it. It can only land in UNCOVERED, where the named-table
    # discipline forces triage. Noise in the safe direction, by design.
    def matches_registry(t):
        if not t or any(seg == "" for seg in t.split("/")):
            return False          # e.g. "AES/", a concatenation fragment
        return t in registered or t.split("/")[0] in registered

    side_list = sorted(t for t in drives if not matches_registry(t))
    universe = {t for t in drives if matches_registry(t)} | registered
    universe = {t for t in universe
                if not any("/%s/" % m in "/%s/" % t for m in excluded_modes)}

    covered, uncovered, undriven = [], [], []
    for t in sorted(universe):
        files = drives.get(t, set())
        if not files:
            undriven.append(t)
        elif t in covered_transforms:
            # Variable-bound ONLY. A file-level fallback ("some file naming this
            # also updates something") is what credited ChaCha20-Poly1305 while
            # its own suite made zero data-path update calls.
            covered.append(t)
        else:
            uncovered.append((t, sorted(files)))

    print("=== MT-32 zero-update detector ===")
    print("  excluded (PIN/CLOSE): %s" % (", ".join(sorted(excluded_modes)) or "none"))
    print("  universe: %d transformations\n" % len(universe))

    print("COVERED       %d" % len(covered))
    print("UNCOVERED     %d" % len(uncovered))
    print("NOT DRIVEN    %d  (registered, named by no test that this tool can resolve)"
          % len(undriven))
    print("              of these, the family sweeps reach most: %s -"
          % ", ".join(NON_CHUNKING_DRIVERS))
    print("              MEASURED to make NO update() call, so those names are")
    print("              driven ONE-SHOT ONLY, not merely unresolved. See MT-37.")
    print("UNRESOLVED    %d distinct getInstance argument expressions" % len(unresolved_sites))
    print("SIDE LIST     %d named in tests, not registered\n" % len(side_list))

    if args.no_classifications:
        genuine, explained = uncovered, []
    else:
        genuine = [(t, f) for t, f in uncovered if t not in UNCOVERED_CLASSIFICATIONS]
        explained = [(t, f) for t, f in uncovered if t in UNCOVERED_CLASSIFICATIONS]

    if explained:
        print("--- UNCOVERED but EXPLAINED (each entry names its evidence) ---")
        for t, _ in explained:
            print("  %-34s %s" % (t, UNCOVERED_CLASSIFICATIONS[t]))
        print()

    if genuine:
        print("--- UNCOVERED, UNEXPLAINED: candidate findings ---")
        for t, files in genuine:
            print("  %-34s %s" % (t, ", ".join(os.path.basename(f) for f in files)))
        print()

    if side_list:
        print("--- named in tests, NOT registered (not part of the universe) ---")
        for t in side_list:
            print("  %s" % t)
        print()

    if undriven:
        print("--- NOT DRIVEN by any resolvable getInstance ---")
        for t in undriven:
            print("  %s" % t)
        print()

    unclassified = {} if args.no_classifications else {
        u: f for u, f in unresolved_sites.items()
        if u not in UNRESOLVED_CLASSIFICATIONS and u not in DRIVER_HELPERS}
    if unclassified:
        print("--- UNRESOLVED and UNCLASSIFIED (this fails the run) ---")
        for u, files in sorted(unclassified.items()):
            print("  %-34s %s" % (u, ", ".join(sorted(os.path.basename(f) for f in files))))
        print("\nEach needs an entry in UNRESOLVED_CLASSIFICATIONS with a reason and")
        print("covering evidence, or in DRIVER_HELPERS if it is a surface driver.")
        return 1

    return 1 if genuine else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
