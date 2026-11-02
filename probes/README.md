# OpenSSL probes

Standalone C programs that measure an OpenSSL behaviour a comment in this repository depends on. A comment that
cites a probe names it as `probes/<name>.c`.

- `dhx_probe.c`: whether `EVP_PKEY_derive_set_peer` pairs a DH-keymgmt private key with a DHX-keymgmt peer on the
  same p and g, in both directions, beside same-keymgmt controls. Keys are imported, not generated.
- `rsakem_probe.c`: RSA-KEM through `EVP_PKEY_encapsulate` on a 2048-bit key: whether the provider needs the KEM
  operation named, and whether the RSASVE secret is r zero-padded to the modulus length.

Each probe runs on mainline OpenSSL or on a FIPS module, with the FIPS lib ctx set up the way
`interface/fips/util/rand/jostle_fips_ctx.c` sets it up:

    <probe> mainline
    <probe> fips <module_dir> <fipsmodule.cnf>

`run.sh` builds every probe against one OpenSSL install and runs it on mainline and on each module given:

    probes/run.sh <openssl_prefix> <bin_dir> <out_dir> [<label> <module_dir> <fipsmodule.cnf>]...

Output is return codes, lengths and OpenSSL reason strings only, so two installs compare with `cmp`. Results are
kept outside the repository.
