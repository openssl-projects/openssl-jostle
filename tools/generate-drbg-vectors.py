#!/usr/bin/env python3
"""Generate the CAVP DRBG test-vector resource from the standards-library archive.

The archive holds 15,840 COUNT blocks across three sets. One block is selected
per (set, file, mechanism, PersonalizationStringLen, AdditionalInputLen) for the
mechanisms the provider registers: 13 headers x 4 configurations x 3 sets = 156.

The selection rule is total and deterministic -- the FIRST section in file order
for each key, COUNT = 0 -- and the emitted resource carries every selection key,
so the test pins the SET of keys rather than a count.

Run from the repo root, naming the archive:

    python3 tools/generate-drbg-vectors.py --archive <path>/CAVP-drbgtestvectors.zip

or set JOSTLE_STANDARDS_DIR to the standards library and omit the flag. Writes
jostle/src/test/resources/drbg/cavp-drbg-vectors.txt and MANIFEST.sha256.
"""

import argparse
import hashlib
import io
import os
import sys
import zipfile

ARCHIVE_NAME = "CAVP-drbgtestvectors.zip"
ARCHIVE_SHA256 = "5f7e5658ebd5b4e6785a7b12fa32333511d2acc2f2d9c5ae1ffa16b699377769"
INDEX_ROW = "recorded in the standards library INDEX, row for " + ARCHIVE_NAME

SETS = ["drbgvectors_no_reseed", "drbgvectors_pr_false", "drbgvectors_pr_true"]

# The section headers that map to a registered SecureRandom name. Every
# registered CTR name carries useDerivationFunction = true (RandAlgorithm), so
# the no-df sections are deliberately absent, as are 3KeyTDEA and the truncated
# SHA-512 variants, which the provider does not register at all.
MAPPED = {
    "CTR_DRBG": ["AES-128 use df", "AES-192 use df", "AES-256 use df"],
    "Hash_DRBG": ["SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512"],
    "HMAC_DRBG": ["SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512"],
}

COLUMNS = [
    "set", "file", "mechanism", "psLen", "aiLen", "eiLen", "nonceLen", "rbLen", "count",
    "EntropyInput", "Nonce", "PersonalizationString",
    "EntropyInputReseed", "AdditionalInputReseed",
    "AdditionalInput1", "AdditionalInput2",
    "EntropyInputPR1", "EntropyInputPR2",
    "ReturnedBits",
]


def parse_rsp(text):
    """Yield (mechanism, attrs, block) for every COUNT block, in file order."""
    mech = None
    attrs = {}
    block = None
    for raw in text.split("\n"):
        line = raw.rstrip("\r").strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            if block is not None:
                yield mech, dict(attrs), block
                block = None
            inner = line[1:-1]
            if "=" in inner:
                k, v = inner.split("=", 1)
                attrs[k.strip()] = v.strip()
            else:
                mech = inner.strip()
                attrs = {}
            continue
        if line.startswith("COUNT"):
            if block is not None:
                yield mech, dict(attrs), block
            block = {"COUNT": line.split("=", 1)[1].strip()}
            continue
        if block is not None and "=" in line:
            k, v = line.split("=", 1)
            block.setdefault(k.strip(), []).append(v.strip())
    if block is not None:
        yield mech, dict(attrs), block


def one(block, key, index=0):
    values = block.get(key, [])
    return values[index] if index < len(values) else ""


def select(archive):
    """Return the selected rows, in a stable order, plus the keys that were expected."""
    with zipfile.ZipFile(archive) as outer:
        inner_names = {os.path.basename(n): n for n in outer.namelist() if n.endswith(".zip")}
        rows = []
        expected = []
        for set_name in SETS:
            member = inner_names.get(set_name + ".zip")
            if member is None:
                raise SystemExit("missing %s.zip inside %s" % (set_name, archive))
            with zipfile.ZipFile(io.BytesIO(outer.read(member))) as inner:
                for file_name in ["CTR_DRBG", "Hash_DRBG", "HMAC_DRBG"]:
                    entry = next(n for n in inner.namelist() if n.endswith(file_name + ".rsp"))
                    text = inner.read(entry).decode("ascii")
                    seen = set()
                    for mech, attrs, block in parse_rsp(text):
                        if mech not in MAPPED[file_name]:
                            continue
                        key = (set_name, file_name, mech,
                               int(attrs["PersonalizationStringLen"]),
                               int(attrs["AdditionalInputLen"]))
                        if key in seen:
                            continue                    # a later repeat of the same config
                        seen.add(key)
                        rows.append((key, attrs, block))
                    for mech in MAPPED[file_name]:
                        for ps in (0, 1):
                            for ai in (0, 1):
                                expected.append((set_name, file_name, mech, ps, ai))
    return rows, expected


def render(rows):
    out = []
    out.append("# CAVP DRBG test vectors (SP 800-90A), selected subset.")
    out.append("# GENERATED by tools/generate-drbg-vectors.py -- do not edit by hand.")
    out.append("#")
    out.append("# Source: CAVP-drbgtestvectors.zip")
    out.append("#   sha256 %s" % ARCHIVE_SHA256)
    out.append("#   %s" % INDEX_ROW)
    out.append("#   Public domain: a work of the US federal government (17 U.S.C. 105).")
    out.append("#")
    out.append("# Selection rule: for each (set, file, mechanism, psLen, aiLen) key, the FIRST")
    out.append("# section in file order, COUNT = 0. Each configuration appears four times in")
    out.append("# the source with byte-identical headers and distinct data; the first is taken.")
    out.append("#")
    out.append("# The archive holds 15,840 blocks; %d are carried here -- 13 headers that map to")
    out.append("# a registered SecureRandom name, x 4 (ps, ai) configurations, x 3 sets.")
    out.append("# The no-df, 3KeyTDEA, SHA-512/224 and SHA-512/256 sections are deliberately")
    out.append("# absent: no registered name resolves to them.")
    out.append("#")
    out.append("# ReturnedBits is the output of the SECOND generate call, per the archive Readme.")
    out.append("#")
    out.append("# " + "|".join(COLUMNS))
    out[12] = out[12] % len(rows)
    for key, attrs, block in rows:
        set_name, file_name, mech, ps_len, ai_len = key
        fields = [
            set_name, file_name, mech, str(ps_len), str(ai_len),
            attrs["EntropyInputLen"], attrs["NonceLen"], attrs["ReturnedBitsLen"],
            block["COUNT"],
            one(block, "EntropyInput"), one(block, "Nonce"), one(block, "PersonalizationString"),
            one(block, "EntropyInputReseed"), one(block, "AdditionalInputReseed"),
            one(block, "AdditionalInput", 0), one(block, "AdditionalInput", 1),
            one(block, "EntropyInputPR", 0), one(block, "EntropyInputPR", 1),
            one(block, "ReturnedBits"),
        ]
        if any("|" in f for f in fields):
            raise SystemExit("a field contains the delimiter: %r" % (key,))
        out.append("|".join(fields))
    return "\n".join(out) + "\n"


def default_archive():
    """The archive is not committed, so its location is the caller's to supply."""
    root = os.environ.get("JOSTLE_STANDARDS_DIR")
    return os.path.join(root, ARCHIVE_NAME) if root else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--archive", default=default_archive())
    ap.add_argument("--out-dir", default="jostle/src/test/resources/drbg")
    args = ap.parse_args()

    if not args.archive:
        raise SystemExit("pass --archive <path>/%s, or set JOSTLE_STANDARDS_DIR to the"
                         " standards library holding it. It is recorded there with"
                         " sha256 %s; see that library's INDEX." % (ARCHIVE_NAME, ARCHIVE_SHA256))

    digest = hashlib.sha256(open(args.archive, "rb").read()).hexdigest()
    if digest != ARCHIVE_SHA256:
        raise SystemExit("archive sha256 %s does not match the INDEX row %s"
                         % (digest, ARCHIVE_SHA256))

    rows, expected = select(args.archive)

    # Vacuity and completeness: every expected key must have been selected exactly
    # once, and nothing else may appear. A parser that reads nothing reports a tidy
    # empty result otherwise.
    got = [r[0] for r in rows]
    got_norm = {(s, f, m, 1 if ps else 0, 1 if ai else 0) for (s, f, m, ps, ai) in got}
    missing = sorted(set(expected) - got_norm)
    extra = sorted(got_norm - set(expected))
    if missing or extra:
        raise SystemExit("selection mismatch: missing=%s extra=%s" % (missing, extra))
    if len(rows) != len(expected):
        raise SystemExit("selected %d rows for %d keys" % (len(rows), len(expected)))
    if len(rows) != 156:
        raise SystemExit("expected 156 rows, selected %d" % len(rows))

    os.makedirs(args.out_dir, exist_ok=True)
    body = render(rows)
    vectors = os.path.join(args.out_dir, "cavp-drbg-vectors.txt")
    with open(vectors, "w", encoding="ascii", newline="\n") as fh:
        fh.write(body)

    vec_sha = hashlib.sha256(body.encode("ascii")).hexdigest()
    with open(os.path.join(args.out_dir, "MANIFEST.sha256"), "w",
              encoding="ascii", newline="\n") as fh:
        fh.write("# CAVP-drbgtestvectors.zip sha256 %s\n" % ARCHIVE_SHA256)
        fh.write("# %d blocks selected by tools/generate-drbg-vectors.py\n" % len(rows))
        fh.write("%s  cavp-drbg-vectors.txt\n" % vec_sha)

    print("wrote %s: %d blocks, sha256 %s" % (vectors, len(rows), vec_sha))


if __name__ == "__main__":
    main()
