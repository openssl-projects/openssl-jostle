# PKITS test certificates and CRLs

NIST Public Key Interoperability Test Suite (PKITS), Certification Path
Validation test data. **Public domain** — a work of the US federal government,
not subject to copyright (17 U.S.C. §105).

- Source: https://csrc.nist.gov/projects/pki-testing (`PKITS_data.zip`)
- `PKITS_data.zip` sha256 `592f66030d2eff80fced7ad022e197d96b7ee4ccce7da9df9c9b2007b1665665`,
  recorded in the standards library INDEX.
- Specification: `PKITS.pdf`, sha256 `506913f4…`, same index.

## What is here

The **whole** corpus the zip carries under `certs/` and `crls/`: 405
certificates (378 KiB) and 173 CRLs (82 KiB), extracted verbatim. Nothing is
selected, renamed or re-encoded. The zip's other directories — `certpairs/`,
`pkcs12/`, `smime/`, the LDIF — are not path-validation inputs and are not
here.

`MANIFEST.sha256` carries the sha256 of every extracted file plus the zip's
own, so a file that is altered, truncated or replaced is a loud mismatch
rather than a silent change of what is under test.

## Why the whole corpus rather than the subset

Until 2026-09-11 this directory held only the 94 certificates the phase 1
cases named, produced by a subsetting step. That step is deleted, and the
argument against it is a measured one: a trailing-newline bug in its parser
resolved 4.1.1's end entity to `GoodCACert.crt`, and a subset is an instrument
that can pick the WRONG file with nothing to say so. With every file present,
a name the case table cannot resolve is a missing-file failure that names
itself. 461 KiB does not pay for keeping an instrument that fails silently.

The residual risk the corpus does not close is a name resolving to the wrong
EXISTING file, so the case table keeps its presence guard and adds a
member-count check per case.

## `cases.txt`

`case|expect|ee|chain|crls`, generated from PKITS.pdf's own "Expected Result"
and "Certification Path" text rather than typed, so the expected column is the
specification's.

- `chain` is the certification path in path order, anchor first, end entity
  excluded (it is the `ee` column).
- `crls` is the CRLs the specification lists for that case, in its order.
  Every case names CRLs, including the ones that do no revocation processing —
  a validator that disables revocation simply never reads them.

161 rows: sections 4.1, 4.2, 4.3, 4.5, 4.6 and 4.7 (55), 4.4 Basic Certificate
Revocation (21), 4.14 Distribution Points (35), 4.15 Delta-CRLs (10), 4.13 Name
Constraints (38) and 4.16 Private Certificate Extensions (2). PKITS
transposes its own words in 4.4.20 and 4.4.21 — "The path **not should**
validate successfully" — which the generator matches explicitly so the typo
stays visible rather than being absorbed by a looser test.

## `cases_policy.txt`

`variant|expect|ee|chain|crls|initial policies|explicit|inhibit-map|inhibit-any`,
one row per sub-test of sections 4.8 to 4.12 (86 rows): Certificate Policies (20
cases), Require Explicit Policy (8), Policy Mappings (14), Inhibit Policy Mapping
(11) and Inhibit Any Policy (10). Generated from PKITS.pdf like `cases.txt`, never
from another implementation's tests.

- `variant` is the case number, then `#` and the sub-test number where the case
  lists numbered sub-tests ("1. default settings, but with ..."); a case without
  them is one row at default settings.
- `initial policies` is the initial-policy-set as OIDs, NIST-test-policy-n being
  2.16.840.1.101.3.2.1.48.n, or `any` for the default any-policy. The three flags
  are initial-explicit-policy, initial-policy-mapping-inhibit and
  initial-inhibit-any-policy.
- `expect` comes from the sub-test's own "The path should (not) validate" or, for a
  default-settings case, from its Expected Result read for an application that
  processes policyConstraints at the default inputs. Where that text is
  conditional the generator takes the clause for those defaults: "If the
  application can process the policyConstraints extension, then the path should
  (not) validate / be rejected", "If the initial-explicit-policy indicator is set
  and the initial-policy-set does not include ...", "If the initial-policy-set does
  not include ... (and the application can process ...)" and "If the
  initial-policy-set is any-policy or otherwise includes ...". 4.9.3's "not should"
  is matched as written.

Generation: `pdftotext -layout PKITS.pdf`, split at the case headings, read each
case's numbered sub-tests, Expected Result and Certification Path bullets, and
resolve each object name to a file by removing its spaces and hyphens. Every name
resolves and every chain starts at the trust anchor and ends at the end entity.

## Why these are committed rather than read from a local copy

CI checks out only this repository. A gate that skipped when the data was
absent would skip the whole certificate-path suite in CI permanently while
reporting green. The standards-library rule ("never commit these files")
governs the specification DOCUMENTS; NIST test vectors are the data under test.
