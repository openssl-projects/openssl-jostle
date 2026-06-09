# Family-specific patterns

This file collects the canonical reference implementations per algorithm family. Before writing any layer of a new transformation, read the corresponding family reference end-to-end. It will show you the exact shape, the per-family idioms, and any gotchas particular to that family.

## Table of contents

1. [Block cipher (symmetric encrypt/decrypt/AEAD/wrap)](#block-cipher)
2. [Signature](#signature)
3. [Key agreement (ECDH / XDH)](#key-agreement)
4. [KEM (post-quantum encapsulation)](#kem)
5. [KDF / SecretKeyFactory](#kdf--secretkeyfactory)
6. [MAC](#mac)
7. [MessageDigest](#messagedigest)
8. [KeyPairGenerator + KeyFactory for new key types](#keypairgenerator--keyfactory)

---

## Block cipher

**SPI base class**: `javax.crypto.CipherSpi`. Jostle's project base is `org.openssl.jostle.jcajce.provider.blockcipher.BlockCipherSpi`. New block ciphers should extend it (or a per-algorithm subclass like `AESBlockCipherSpi`).

**Canonical references**:
1. **AES** — `interface/util/block_cipher_ctx.c` (the shared C-side context), `interface/jni/block_cipher_ni_jni.c`, `provider/blockcipher/AESBlockCipherSpi.java`, `provider/ProvAES.java`.
2. **AESWrap** (the wrap-mode wiring added recently) — same files, but shows how to wire a single-update mode that doesn't use `EVP_EncryptFinal`.

**Family-specific notes**:

1. **Native context** — block ciphers share a single `block_cipher_ctx` struct that's keyed by `cipher_id` (AES128/192/256, ARIA*, CAMELLIA*, SM4) and `mode_id` (ECB/CBC/CFB/CTR/OFB/GCM/CCM/XTS/WRAP/WRAP_PAD/OCB). Adding a new cipher means extending the enums (`OSSLCipher`, `OSSLMode`) and adding a switch case in `block_cipher_ctx_init` for the `EVP_CIPHER_fetch` call.
2. **Wrap modes** — set `EVP_CIPHER_CTX_FLAG_WRAP_ALLOW` before `EVP_EncryptInit_ex`. Wrap modes are single-update: all output comes from `EVP_EncryptUpdate`, `EVP_EncryptFinal` returns 0 bytes. `final_size` must account for the +8-byte ICV on encrypt and the matching shrink on decrypt. Skip the AES-block-alignment check for these modes (KW needs multiple-of-8, KWP accepts any length — let OpenSSL enforce).
3. **AEAD modes** (GCM/CCM/OCB) — tag is appended to ciphertext on encrypt, must be split off and fed to `EVP_DecryptUpdate` then checked at `EVP_DecryptFinal` on decrypt. CLAUDE.md "AEAD — damage the ciphertext, the tag, or the AAD independently".
4. **Java SPI** — `engineWrap` / `engineUnwrap` defer to `engineDoFinal`; unwrap failures collapse to `InvalidKeyException` (Bleichenbacher channel). `engineInit` must translate `Cipher.WRAP_MODE` / `UNWRAP_MODE` → `ENCRYPT_MODE` / `DECRYPT_MODE` before passing to the native init.
5. **JCE getInstance forms** — `Cipher.getInstance("X/Y/Z")` runs four lookup forms. If you register a transformation alias on the bare algorithm, form-1 wins and `engineSetMode` / `engineSetPadding` are NOT called. Test with explicit padding to confirm. CLAUDE.md "JCE transformation lookup: form-1 alias vs form-4 fallback".

**Tests**: `crypto/AESAgreementTest.java`, `crypto/AESWrapTest.java`. For limit tests: `crypto/BlockCipherLimitTest.java`. For ops: `crypto/BlockCipherOpsTest.java`.

---

## Signature

**SPI base class**: `java.security.SignatureSpi`. Each algorithm typically has its own subclass.

**Canonical references**:
1. **RSA (PKCS#1 v1.5 + PSS)** — `interface/util/rsa.c`, `interface/util/rsa_pkcs1.c`, `provider/rsa/RSASignatureSpiBase.java`, `provider/rsa/RSAPSSSignatureSpi.java`, `provider/ProvRSA.java`.
2. **ECDSA** — `interface/util/ec.c` (shared with ECDH), `provider/ec/ECDSASignatureSpi.java`, registration in `provider/ProvEC.java`.
3. **Ed25519 / Ed448** — `interface/util/edec.c`, `provider/eddsa/EdSignatureSpi.java`, `provider/ProvED.java`.
4. **ML-DSA / SLH-DSA** — `interface/util/mldsa.c` / `slhdsa.c`, `provider/mldsa/*.java`, `provider/slhdsa/*.java`.

**Family-specific notes**:

1. **State machine** — `created → initSign/initVerify → update* → sign/verify → ready-for-reInit`. Implement `requireInitialised()` and call it at every entry point (CLAUDE.md "SPI state-machine guards").
2. **Determinism** — PKCS#1 v1.5 signing is deterministic (same input → same output); PSS, OAEP, and ECDSA are randomised (same input → different outputs each call). Test both — `testEcdsa_SameMessageTwice_signaturesDiffer` vs `testPkcs1_SameMessageTwice_signaturesIdentical`.
3. **Implicit rejection** — RSA PKCS#1 v1.5 decrypt depends on OpenSSL's `OSSL_ASYM_CIPHER_PARAM_IMPLICIT_REJECTION = 1`. Explicitly set it AND write a hard-guard test that breaks if it gets removed. CLAUDE.md "Hard-code security-critical OpenSSL parameters".
4. **Verify-side errors** — verify's "signature didn't match" path is a NORMAL return, not an error queue entry. Use `ERR_set_mark` / `ERR_pop_to_mark` to scrub benign noise. CLAUDE.md "OpenSSL ERR-queue conventions".
5. **POP** — when the signature is used as Proof of Possession in CMP / CMS, the same engine drives both signing and verification with the same SPI. Test the role-flip pattern (`initSign` → `sign` → `initVerify` → `verify` on one instance).

**Tests**: `rsa/RSATest.java`, `rsa/RSAOAEPCipherTest.java`, `ec/ECDSATest.java`, `eddsa/EdDSATest.java`, `mldsa/MLDSATest.java`. Plus the `*LimitTest`, `*OpsTest` suites per family.

---

## Key agreement

**SPI base class**: `javax.crypto.KeyAgreementSpi`.

**Canonical references**:
1. **ECDH** — `interface/util/ec.c` (the `ec_kex_*` functions are type-agnostic at the EVP_PKEY level), `provider/ec/ECDHKeyAgreementSpi.java`.
2. **XDH (X25519/X448)** — `interface/util/xec.c` (keygen only; agreement reuses `ec_kex_*`), `provider/xec/XDHKeyAgreementSpi.java`.
3. **ECDH-with-KDF** — `provider/ec/ECDHwithKDFKeyAgreementSpi.java`. Pattern for composing two primitives.

**Family-specific notes**:

1. **State machine** — `created → init(priv) → doPhase(pub, true) → generateSecret`. ECDH is single-phase; `lastPhase` MUST be true.
2. **Re-init after derive** — `EVP_PKEY_derive` invalidates the ctx. The SPI's `engineGenerateSecret` must internally re-init for any subsequent call. The reset/reuse test (two derivations on one instance) verifies this.
3. **EC point blinding** — `EVP_PKEY_derive_set_peer` runs an internal `EVP_PKEY_public_check` that consumes RAND on binary-field curves. Plumb `RandSource` through `set_peer` AND `derive`.
4. **Type-agnostic kex** — the C-side `ec_kex_init / set_peer / derive` works for any EVP_PKEY type that supports derive (EC, X25519, X448). The XDH SPI reuses these and ec.c's `check_is_ec_or_xec` widens the type predicate.
5. **Composed KDF** — when adding an `XwithKDF` variant, extend the existing KeyAgreementSpi or build a thin wrapper. The composition pattern: derive raw Z, then run a KDF (X9.63 or HKDF or ConcatKDF) over Z + sharedInfo + digest. Carry the optional shared-info via a `KDFParameterSpec` AlgorithmParameterSpec (or bcpkix-compatible reflection).
6. **`engineGenerateSecret(String)`** — wraps the derived bytes in a `SecretKeySpec` with the requested algorithm. Reject blank algorithm names with `NoSuchAlgorithmException` (SecretKeySpec accepts whitespace-only names silently otherwise).

**Tests**: `ec/ECDHTest.java`, `xec/XDHTest.java`, `ec/ECDHwithKDFTest.java`.

---

## KEM

**SPI base class**: `javax.crypto.KEMSpi` (Java 21+). On Java 8 baseline, the equivalent uses `SecretKeyFactorySpi` with custom key specs.

**Canonical references**:
1. **ML-KEM** — `interface/util/mlkem.c`, `provider/mlkem/MLKEMSecretKeyFactory.java`, `provider/ProvMLKEM.java`.

**Family-specific notes**:

1. **KEMRecipientInfo** — when used in CMS / CMP (RFC 9629), the encapsulation output flows through HKDF to derive a wrapping key. So a new KEM typically also wants HKDF available.
2. **Encapsulation / decapsulation** — distinct from key transport. Encapsulation produces a (ciphertext, shared-secret) pair given a public key; decapsulation recovers the shared-secret given a private key + ciphertext.
3. **Spec carrier** — `KEMGenerateSpec` and `KEMExtractSpec` in `jcajce/spec/` carry the encapsulation/decapsulation inputs.

**Tests**: `mlkem/MLKEMTest.java`, `mlkem/MLKEMOpsTest.java`.

---

## KDF / SecretKeyFactory

**SPI base class**: `javax.crypto.SecretKeyFactorySpi`. (Java 22+ has a separate `KDF` SPI — Jostle currently uses the SecretKeyFactory shim for broad compatibility.)

**Canonical references**:
1. **PBKDF2** — `interface/util/kdf.c::pbkdf2`, `provider/kdf/PBKDF2SecretKeyFactory.java`, `provider/ProvPBKDF.java`.
2. **HKDF** — `interface/util/kdf.c::hkdf`, `provider/kdf/HKDFSecretKeyFactory.java`, `jcajce/spec/HKDFKeySpec.java`.
3. **X9.63 KDF** — `interface/util/kdf.c::x963kdf`, `provider/kdf/X963KDFSecretKeyFactory.java`, `jcajce/spec/X963KDFKeySpec.java`.
4. **Scrypt** — `interface/util/kdf.c::scrypt`, `provider/kdf/ScryptSecretKeyFactory.java`.

**Family-specific notes**:

1. **Native side** — fetch `EVP_KDF_fetch(libctx, "<NAME>", NULL)` once, build `OSSL_PARAM[]` with the algorithm's inputs (`OSSL_KDF_PARAM_DIGEST`, `OSSL_KDF_PARAM_KEY`, `OSSL_KDF_PARAM_SALT`, `OSSL_KDF_PARAM_INFO`, ...), call `EVP_KDF_derive`. Always free both `EVP_KDF` and `EVP_KDF_CTX` at `exit:`.
2. **Optional parameters** — for params OpenSSL treats as optional (salt, info for HKDF; shared-info for X9.63), the bridge layer must pass a non-NULL stub even for empty inputs. Use the file-static `kdf_empty_stub` (see `kdf.c`).
3. **Pinned-PRF vs bare** — for KDFs that take a digest as input, register both forms: `<KDF>withSHA256` etc. (digest pinned at construction, the SPI rejects spec-digest mismatch) AND a bare `<KDF>` (digest taken from spec at derive time). The pinned form is the common case; the bare form covers SP 800-56A callers that resolve the digest dynamically.
4. **OID aliases** — PBKDF2 has `id-PBKDF2 = 1.2.840.113549.1.5.12` plus per-PRF HMAC OIDs (`1.2.840.113549.2.{7..13}`). Add aliases for each registered transformation so bcpkix can route by OID.
5. **Custom KeySpec** — every KDF gets its own KeySpec in `jcajce/spec/` carrying the algorithm's inputs (`HKDFKeySpec`, `X963KDFKeySpec`, etc.). Constructor rejects null / empty / non-positive inputs with `IllegalArgumentException`.

**Tests**: `kdf/PBKdf2Test.java` (BC agreement), `kdf/HKDFTest.java` (RFC KAT), `kdf/X963KDFTest.java` (BC agreement), `kdf/PBKdf2OIDTest.java` (OID resolution).

---

## MAC

**SPI base class**: `javax.crypto.MacSpi`.

**Canonical references**:
1. **HMAC family** — `interface/util/mac.c`, `provider/mac/MacSpiBase.java`, `provider/ProvMac.java`.

**Family-specific notes**:

1. **MAC vs Signature** — MACs are symmetric (one key, used for both authenticate and verify); Signatures are asymmetric. JCE has separate SPI hierarchies.
2. **Auto-reset** — MAC's `doFinal()` auto-resets to ready-for-update state. Different from Cipher / Signature.
3. **Tag-length set via param** — for CMAC / Poly1305 variants, the tag length is set via `OSSL_MAC_PARAM_SIZE`. HMAC tag length comes from the digest.

**Tests**: `mac/MacTest.java`, `mac/MacOpsTest.java`.

---

## MessageDigest

**SPI base class**: `java.security.MessageDigestSpi`.

**Canonical references**:
1. **SHA family** — `interface/util/md.c`, `provider/md/MDServiceSpi.java`, `provider/ProvMD.java`. **CLAUDE.md cites this as THE canonical reference for new transformations.**

**Family-specific notes**:

1. **Clone support** — `MessageDigestSpi.engineGetDigestLength` and clone require the SPI to maintain enough state to fork. `md.c` shows the `EVP_MD_CTX_dup` pattern.
2. **XOFs (SHAKE128/256)** — variable output length; the SPI accepts a length parameter via the digest's update path or via `OSSL_DIGEST_PARAM_XOFLEN`.

**Tests**: `md/MDTest.java`, `md/MDOpsTest.java`.

---

## KeyPairGenerator + KeyFactory

When you're adding a new **key type** (not just a transformation over an existing key type), you also need:

1. **KeyPairGenerator** extending `java.security.KeyPairGenerator` — produces a `KeyPair` of your JOXxxPublicKey / JOXxxPrivateKey.
2. **KeyFactorySpi** — decodes X.509 SubjectPublicKeyInfo / PKCS#8 PrivateKeyInfo into the same key classes.
3. **Key classes** — `JOXxxPublicKey` / `JOXxxPrivateKey` extending `AsymmetricKeyImpl`, implementing the canonical `java.security.interfaces.XxxPublicKey` / `XxxPrivateKey` plus a Jostle marker interface (e.g. `org.openssl.jostle.jcajce.interfaces.ECKey`) plus `OSSLKey`.
4. **`OSSLKeyType`** entry with name + every OID alias. The decode-by-OID path through `PKEYKeySpec(long ref)` uses these.

**Canonical references**:
1. **EC** — `provider/ec/ECKeyPairGenerator.java`, `ECKeyFactorySpi.java`, `JOECPublicKey.java`, `JOECPrivateKey.java`.
2. **XEC (X25519/X448)** — `provider/xec/XECKeyPairGenerator.java`, `XECKeyFactorySpi.java`, `JOXECPublicKey.java`, `JOXECPrivateKey.java`. Simpler than EC since the curve is the EVP_PKEY type itself.
3. **RSA** — `provider/rsa/RSAKeyPairGenerator.java`, `RSAKeyFactorySpi.java` — shows the `RSAPublicKeySpec` / `RSAPrivateCrtKeySpec` component-form paths.

**Family-specific notes**:

1. **`initialize(int)` vs `initialize(AlgorithmParameterSpec)`** — JCE has two init forms. Pick exceptions per the contract: `InvalidParameterException` (a RuntimeException) for the int form, `InvalidAlgorithmParameterException` (checked) for the spec form. CLAUDE.md "Validate resource-consumption parameters at the JCE boundary".
2. **Reflection for newer specs** — `NamedParameterSpec` (Java 11) and `EdECPublicKeySpec` (Java 15) aren't compileable on the Java 8 baseline. Accept them reflectively (check `Class.forName(...)` + `Method.invoke(...)`), and provide a `java11/` or `java15/` override that uses them directly if the algorithm needs them strictly.
3. **`PKEYKeySpec(long ref)` decode** — looks up the OpenSSL EVP_PKEY type name via `EVP_PKEY_get0_type_name`, maps to OSSLKeyType.forAlias(name). Your new OSSLKeyType entry MUST include the type name OpenSSL returns (canonical uppercase, e.g. "X25519", "ED25519").
4. **Encoded round-trip** — `getEncoded()` on public key returns X.509 SubjectPublicKeyInfo; on private key returns PKCS#8 PrivateKeyInfo. The KeyFactory's `engineGeneratePublic` / `engineGeneratePrivate` must accept these byte sequences and produce a key that re-encodes to the same bytes.

**Tests**: `ec/ECTest.java` covers `KeyPairGenerator` and `KeyFactory` round-trip including X.509/PKCS#8 → key → encoded comparison. `xec/XDHTest.java` covers the X25519/X448 equivalent.
