# PKITS test certificates (phase 1 subset)

NIST Public Key Interoperability Test Suite (PKITS), Certification Path
Validation test data. **Public domain** — a work of the US federal government,
not subject to copyright (17 U.S.C. §105).

- Source: https://csrc.nist.gov/projects/pki-testing (`PKITS_data.zip`)
- `PKITS_data.zip` sha256 `592f66030d2eff80fced7ad022e197d96b7ee4ccce7da9df9c9b2007b1665665`,
  recorded in the standards library INDEX.
- Specification: `PKITS.pdf`, sha256 `506913f4…`, same index.

## What is here, and what is not

`certs/` holds the **94** certificates the phase 1 cases need, of the 405 in the
full distribution — the trust anchor plus every certificate named in the
certification path of the 50 cases in `cases.txt`. Nothing else is copied.

**No CRLs.** Phase 1 does no revocation processing, so a CRL here would be
unused and would read as coverage that does not exist. They arrive with phase 2.

`cases.txt` is `case|expect|ee|chain`, generated from PKITS.pdf's own
"Expected Result" and "Certification Path" text rather than typed, so the
expected column is the specification's.

## Why these are committed rather than read from a local copy

CI checks out only this repository. A gate that skipped when the data was
absent would skip the whole certificate-path suite in CI permanently while
reporting green. The standards-library rule ("never commit these files") governs
the specification DOCUMENTS; NIST test vectors are the data under test.
