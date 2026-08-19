---
name: audit-fips-approval-status
description: Determine and document the FIPS-approval status of what JSLFIPS serves, by reading the OpenSSL FIPS module's security policy (CMVP cert #4985) — approved algorithms, Table 7/8 non-approved algorithms, §4.4 Table 13 non-approved services, and their usage scopes. JSLFIPS does NOT filter on approval, so this is for producing accurate documentation and answering "is this use approved?", never for deciding what to register. Use whenever the user asks about approval status, including phrases like "is X approved under FIPS", "check JSLFIPS against the security policy", "document the approval status", "which of our services are non-approved", "what does the policy say about X", and similar. Also use when a code comment asserts something is or is not approved — those claims have been wrong in both directions, four times.
---

# Determine FIPS-approval status for what JSLFIPS serves

**Read this first: JSLFIPS does not filter on approval.** Its surface is what the
OpenSSL FIPS module serves — the module's implementations carry a `fips=yes` /
`fips=no` property and the lib ctx's `fips=yes` default query excludes the
latter, so Triple-DES, ChaCha20 and OCB are unfetchable without any Java-side
list. Approval is a *compliance determination* that belongs to the operator, and
this provider deliberately does not make it.

So this skill is **not** for deciding what to register. Adding or removing a
registration on approval grounds is exactly what we stopped doing, and it is how
we removed working algorithms from callers. Use it for:

1. Answering "is this particular use approved?" when someone asks.
2. Producing or checking documentation that states approval status.
3. Checking a code comment that asserts something is or is not approved.

That last one matters. Four confident comments in this area were wrong, in both
directions:

1. `NoneWithECDSA` excluded on a comment claiming it was non-approved. The
   SigGen Component is approved — the exclusion cost TLS ECDSA authentication.
2. Then its *verify* half served on the same reasoning. The SigVer Component is
   non-approved (Table 8, §4.4 Table 13).
3. `ECDHWITHSHA1KDF` served with a comment asserting "SHA-1 as a KDF PRF is
   approved". Table 8 scopes X963KDF-with-SHA-1 as non-approved.
4. "Table 13 is empty" — an extraction artefact; see the trap below.

**Do not trust a comment in this area; check the policy and quote it.**

## Why this cannot be done by reading algorithm names

The policy's non-approved entries are **usage-scoped, not algorithm-scoped**.
Reading only the name gets the wrong answer roughly as often as the right one:

| Entry | Approved? |
|---|---|
| `KDA HKDF SP800-56Cr2` | approved |
| Table 8 `HKDF` | non-approved **only** "with key length less than 112 bits" |
| Table 8 `HMAC` | non-approved **only** "with key length less than 112 bits for MAC generation" |
| Table 8 `X963KDF` | non-approved **only** with PRF SHA-1, SHA2-512/224, SHA2-512/256, SHA3-*, SHAKE*, KECCAK-KMAC* |
| Table 8 `OneStep KDF` | non-approved **only** with PRF SHAKE128, SHAKE256 |
| Table 8 `Hash and HMAC DRBG` | non-approved **only** with PRFs SHA2-224, SHA2-384, SHA2-512/224, SHA2-512/256 |
| Table 8 `ECDSA SigVer Component` | non-approved at **every** listed curve (the full B/K/P set) — no narrowing clause |
| Table 8 `Triple-DES`, `Ed25519`, `Ed448`, `X25519`, `X448`, `FIPS 186-2 RSA` | non-approved wholesale |

So each finding needs the scope quoted, and the verdict depends on whether the
scope is reachable through what we register:

- **Wholesale non-approved** → must not be registered by default.
- **Scoped by PRF / curve / key length**, and our registration pins the
  non-approved value (e.g. a SHA-1-PRF variant registered under its own name)
  → must not be registered by default.
- **Scoped by a runtime parameter** a caller chooses (HMAC key length, HKDF key
  length) → registration is correct; the constraint belongs at init as a range
  check, or is accepted as the caller's responsibility. Say which.

## Getting the policy text

The security policy is the authority; the CMVP certificate page carries only
module metadata and the CAVP validation (A3548) listing is not fetchable.

```bash
# 140sp4985.pdf, ~89 pages. Fetch once, extract to text, keep it in the scratchpad.
python3 -m pip install --quiet --target ./pdflib pypdf
python3 - <<'EOF'
import sys; sys.path.insert(0, './pdflib')
from pypdf import PdfReader
r = PdfReader("140sp4985.pdf")
open("sp4985.txt", "w").write("\n".join((p.extract_text() or "") for p in r.pages))
EOF
```

**Extraction trap that has already caused one wrong conclusion.** The extraction
is column-major and places each table's **caption AFTER its body**. Searching for
`Table 13: Non-Approved Services` and reading forward shows a blank line, which
reads as an empty table — it is not. The body sits in the ~60 lines BEFORE the
caption. Always read backwards from a caption, and cross-check a table's contents
against `§4.4` / the section heading rather than the caption line.

Sections that matter:

- Approved algorithms table (~line 500-800): per-algorithm properties, including
  the `Component - No, Yes` columns that decide externally-hashed variants.
- Security Function Implementations (Table 9): per-service constraints such as
  `Private Key format: CRT, Public Exponent Mode: Fixed : k = 2048`.
- Table 7 — Non-Approved, **Allowed** algorithms (usable in approved mode).
- Table 8 — Non-Approved, **Not Allowed** algorithms, with usage scopes.
- Table 12 — Approved Services, whose wording carries deliberate asymmetries
  ("SigGen (includes SigGen Component)" says SigGen only, and means it).
- §4.4 / Table 13 — Non-Approved Services.
- The service-indicator list: which EVP getters identify each service.

## Running the audit

1. **Enumerate what we actually register**, both surfaces:

```bash
# default (approved) surface
java --module-path jostle/build/libs/openssl-jostle-0.1-SNAPSHOT.jar \
  --module org.openssl.jostle.prov/org.openssl.jostle.util.DumpInfo \
  --services --fips-config "fips_module='$TEST_FIPS_LIB'"
```

   The golden list in `FIPSServedSurfaceSnapshotTest.GOLDEN` is the same set and
   is easier to diff; `UNAPPROVED_EXTRA` is the opt-in set.

2. **For each registration, find its policy basis** and record one of:
   `APPROVED` (cite the algorithm/service row), `NON-APPROVED` (cite Table 8 or
   Table 13 with the scope quoted), or `SCOPED` (approved, but a non-approved
   usage is reachable — name the parameter and whether we bound it).

3. **Check both directions of every split service.** Sign and verify are
   separate services for the Components; encrypt and decrypt can be too. A
   service being approved does not make its inverse approved.

4. **Check the properties, not just the name.** `k = 2048` on the RSA Signature
   Primitive is a real constraint that our keygen range (2048-16384) exceeds, and
   the module does not enforce it — verified: 3072 signs happily.

5. **Report per registration**, with the quote. A finding without a quote from
   the policy is not a finding — that is how the three historical errors happened.

## What to do with a finding

**Do not change what is registered.** The finding is information, not a defect.
Instead:

- **Record the status where the reader will be**: at the registration site, with
  the policy quote and its scope. `ProvFIPSEC`'s note on the ECDSA Components and
  the X9.63 SHA-1 PRF is the worked example — it states the status precisely and
  then says the determination is the operator's.
- **Correct any comment that got it wrong**, in both directions. A stale claim is
  what causes the next error.
- **Say which constraints are usage-scoped**, since those are the ones no surface
  can express and the ones an operator most needs to know about: HMAC and HKDF key
  length, X9.63 KDF PRF choice, the RSA primitive's `k = 2048`.
- **If asked to restrict a deployment**, point at the JVM's
  `jdk.security.providers.filter` rather than editing registrations.

## Do not claim the audit proves compliance

This audit compares registrations against the policy text. It cannot establish
that a *use* is approved, for two reasons worth stating in any report:

1. **The module does not enforce its own envelope.** It performs non-approved
   operations without complaint, so nothing fails when you stray.
2. **3.1.2 exposes no runtime approved-mode indicator.** There are no
   `fips-indicator` params in that release (mainline gained
   `OSSL_ALG_PARAM_FIPS_APPROVED_INDICATOR` later); the policy's mechanism is
   caller-side per IG 2.4.C — the application queries EVP getters and compares
   against Table 12 itself. So "we are in approved mode" is not observable at
   runtime, only reasoned about.

Where the policy is genuinely ambiguous — as with whether the RSA Signature
Primitive covers module-applied PKCS#1 v1.5 padding — say so and escalate to the
module owner rather than picking the convenient reading. Two of the three
historical errors came from resolving an ambiguity unilaterally.
