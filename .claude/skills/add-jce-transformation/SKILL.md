---
name: add-jce-transformation
description: How to add a new JCE / JCA algorithm or transformation to the OpenSSL Jostle provider (Cipher, Signature, KeyAgreement, SecretKeyFactory, KeyPairGenerator, KeyFactory, Mac, MessageDigest, KEM, KDF). Make sure to use this skill whenever the user asks to add, register, wire up, expose, or hook a new cryptographic algorithm into Jostle's JCE surface — including phrases like "add support for X", "expose Y as a Cipher transformation", "register Z in the provider", "wire up an X9.63 KDF", "implement HKDF", "add Chacha20 support", "add an ML-KEM variant", and similar. Also applies when the user wants to add a new OID alias on an existing transformation, add a new SPI hierarchy, or build out the native bridge for a JCE primitive.
---

# Adding a JCE transformation to Jostle

Jostle is a JCA/JCE provider that delegates to OpenSSL via a three-layer native interface (Java SPI → JNI/FFI bridge → C util → OpenSSL EVP_*). Adding a new transformation means landing files in coordinated places across all three layers plus tests and provider registration. The work is not hard once you know the layers — but missing any layer (especially the multi-release Java overrides or the OPS instrumentation) creates subtle bugs that don't surface until later.

This skill walks through the canonical workflow. It does NOT duplicate the rules in `CLAUDE.md` — those are the source of truth for HOW to write each layer. This skill is about WHAT to touch and in WHAT ORDER.

## When to use this skill

The user is asking to add a JCE-surface algorithm — anything that ends up callable via `Cipher.getInstance(...)`, `Signature.getInstance(...)`, `KeyAgreement.getInstance(...)`, `SecretKeyFactory.getInstance(...)`, `KeyPairGenerator.getInstance(...)`, `KeyFactory.getInstance(...)`, `Mac.getInstance(...)`, `MessageDigest.getInstance(...)`, `KDF.getInstance(...)`, or `KEM.getInstance(...)`. The trigger is broad: anything from "add HKDF" to "expose the X9.63 KDF as a SecretKeyFactory" to "register a new ECDH-with-KDF variant" qualifies.

If the user is only adding an OID alias to an existing transformation (no new SPI, no new native code), this skill still applies — but you'll skip steps 1–6 and only do step 7 (provider registration) + step 8 (tests). Jump straight to the section "Lightweight: OID alias on an existing transformation".

## The 8-layer workflow

Adding a new transformation touches at most 8 layers. Not every algorithm needs all 8 — pure-Java compositions (e.g. ECDHwithKDF that wraps two existing primitives) can skip the native layers. But the canonical full path is:

1. **Native util** — `interface/util/<algo>.c` + `<algo>.h`. The only place that calls `EVP_*`.
2. **JNI bridge** — `interface/jni/<algo>_ni_jni.c`. Validates user-supplied inputs, calls util.
3. **FFI bridge** — `interface/ffi/<algo>_ni_ffi.c`. Same validation, same error codes, different surface (raw pointers + sizes).
4. **NI interface + impls** — Java side: `XServiceNI` interface, `XServiceJNI` (native methods), `XServiceFFI` (Java 25+ FFI implementations).
5. **Spec class(es)** — `org.openssl.jostle.jcajce.spec.<Name>KeySpec` for any algorithm-specific input bundle. Implements `KeySpec`.
6. **SPI class** — Extends the right JCE SPI (`CipherSpi`, `SignatureSpi`, `KeyAgreementSpi`, `SecretKeyFactorySpi`, `KeyPairGenerator`, `KeyFactorySpi`, `MacSpi`, `MessageDigestSpi`, ...).
7. **Provider registration** — `Prov<NAME>.configure(JostleProvider)`, then wire into `JostleProvider.setup()` so it actually loads.
8. **Tests** — Unit test + BC agreement test (where applicable) + `*LimitTest` for NI-level input validation + `*OpsTest` for fault-injection at every new OPS site.

Plus cross-cutting:
1. **Error codes** — `interface/util/bc_err_codes.h` macro AND matching `ErrorCode.java` enum entry AND matching case in the NI's `handleErrorCodes` default method. All four edits go together.
2. **Key types** — `interface/util/key_spec.h` `KS_*` macro AND matching `OSSLKeyType` enum entry with name + OID aliases.
3. **CMakeLists.txt** — Add new `.c`/`.h` to every target list (multiple entries in `interface/CMakeLists.txt`; use `replace_all` on `util/<existing>.[ch]` pattern).
4. **Multi-release overrides** — If the new SPI uses post-Java-8 APIs internally (e.g. `Reference.reachabilityFence`), provide `java9/` or `java11/`/`java25/` override copies with identical public ABI.
5. **OPS instrumentation** — Wrap every fallible OpenSSL call in `OPS_OPENSSL_ERROR_N` + matching `OPS_OFFSET_OPENSSL_ERROR_N(<offset>)` so fault-injection tests can exercise the failure path.

## Step-by-step procedure

### 0. Pick a canonical reference

Before writing a line of code, identify the closest-existing transformation in the codebase and read its three layers end-to-end. The canonical references per family are in `references/family-patterns.md`. Reading the existing canonical implementation is the single highest-leverage thing you can do — it shows you the project's style, the error-handling discipline, the bracing convention, the OPS pattern, and the test scaffolding all at once.

CLAUDE.md names `MDServiceSPI` / `MDServiceNI` / `md.c` as the "canonical reference for newer transformations". For most additions, look there first.

### 1. Native util (`interface/util/<algo>.c` + `.h`)

Read `references/family-patterns.md` for the per-family signature shape. Universal rules:

1. **Bridge trusts you** — every pointer / length parameter is already validated by the JNI/FFI bridge. Use `jo_assert` on every input as an invariant (`jo_assert(ctx != NULL);` etc.).
2. **`get_global_jostle_ossl_lib_ctx()`** — never pass `NULL` to `EVP_*_fetch` / `EVP_*_new_from_name`. The lib ctx hosts the Java RAND bridge.
3. **Error returns** — return `JO_SUCCESS` on the happy path, `JO_OPENSSL_ERROR` (or a typed code from `bc_err_codes.h`) on failure. Functions that produce a pointer take `int32_t *err` as the last parameter.
4. **`ERR_clear_error()`** at the top of every operation, before any OpenSSL call whose error you'd surface.
5. **`1 != X` pattern** — `if (1 != EVP_X_op(...))` not `if (!EVP_X_op(...))` (some OpenSSL functions return -1 for "unsupported"). CLAUDE.md "Logic errors and inverted conditions".
6. **`goto exit` cleanup** — declare every resource (`EVP_PKEY_CTX *ctx = NULL;` etc.) at the top before any branch that could `goto exit`. The cleanup at `exit:` must use NULL-tolerant freers (`EVP_PKEY_CTX_free`, `BN_clear_free`, etc.) so the early-failure path doesn't deref uninitialised pointers.
7. **OPS instrumentation** — wrap each fallible OpenSSL call in the `OPS_OPENSSL_ERROR_N <cond>` pattern with a matching `OPS_OFFSET_OPENSSL_ERROR_N(<offset>)` on the return. Pick a unique offset block for the file (see existing files: rsa.c uses 1000s, rsa_oaep.c uses 2000s, ec.c uses 3000s, kdf.c uses one block per KDF — pick something unused). CLAUDE.md "OPS_* macro hygiene".
8. **Secret material** — `BN_clear_free` / `OPENSSL_clear_free` for keys/scalars, never `BN_free`/`OPENSSL_free`. Never `memset` for secrets — the compiler may elide it.

Add the new `.c`/`.h` files to **every** target list in `interface/CMakeLists.txt` (there are typically 6 sections — `replace_all` on the pattern `util/<sibling>.h\n            util/<sibling>.c` is the fastest way).

### 2. JNI bridge (`interface/jni/<algo>_ni_jni.c`)

Bridge layer. The ONLY place that null-checks and range-checks user inputs as error returns (not asserts). The util layer trusts these checks have happened.

For each parameter the Java caller supplies:

1. **Byte arrays** — `load_bytearray_ctx(&ctx, env, jarray)` + null-check on the `.array` field + appropriate `JO_*_FAILED_ACCESS` / `JO_*_NULL` error code. **Release every ctx on every exit path.**
2. **Strings** — `(*env)->GetStringUTFChars(env, jstr, NULL)` + `JO_UNABLE_TO_ACCESS_NAME` on failure. **Release via `ReleaseStringUTFChars` on every exit.**
3. **Lengths** — `if (len < 0) return JO_*_IS_NEGATIVE;` and `if (len > INT32_MAX) return JO_*_TOO_LONG_INT32;` BEFORE any cast to `size_t`.
4. **Offset+length pairs** — `check_bytearray_in_range(&ctx, off, len)` returns false on `off + len > size` (handles overflow safely).
5. **`OPS_FAILED_ACCESS_N`** — for fault-injecting JNI-side access failures. One per byte-array access typically.

### 3. FFI bridge (`interface/ffi/<algo>_ni_ffi.c`)

Symmetric to the JNI bridge but takes raw pointers + sizes. Must return **identical error codes for identical inputs** — the cross-bridge regression suite depends on this. Key differences from JNI:

1. **Symbol prefix** — exported function names use `Jo<MOD>_*` (e.g. `JoEC_generateKeyPair`, `JoRSA_sign`). Verify no collision with libcrypto via `nm libinterface_ffi.dylib | grep " T " | grep -E "<your-prefix>"`. CLAUDE.md "Symbol-name collisions with libcrypto exports".
2. **No `load_bytearray_ctx`** — FFI receives raw pointers, just null-check directly.
3. **`check_in_range(size, off, len)`** instead of the bytearray-ctx variant.
4. **No `OPS_FAILED_ACCESS_N`** — those flags are JNI-only.

### 4. NI interface + JNI + FFI impls

Three files in `jostle/src/main/java/.../jcajce/provider/<pkg>/`:

1. **`<X>ServiceNI.java`** — interface extending `DefaultServiceNI`. Declares each native method abstract. Default methods centralize error-code → typed-exception mapping via `handleErrorCodes(int code)` overriding `baseErrorHandler` and adding the per-family error codes.
2. **`<X>ServiceJNI.java`** — class implementing the interface with `native` method declarations. JNI links to these by name (`Java_<class>_<method>`).
3. **`<X>ServiceFFI.java`** in `jostle/src/main/java25/.../` — FFI implementation using `Linker.nativeLinker()`, `Linker.Option.critical(true)`, and `MethodHandle.invokeExact`. Lookup via `lookup.find("Jo<MOD>_*")`. CLAUDE.md "SecureRandom flow" — never invoke FFI down-call inside a critical region if it can up-call into Java entropy.

The `NISelector` picks JNI or FFI at load time. New `<X>ServiceNI` doesn't need to register itself — `NISelector` exposes it as a static field; add a getter there.

### 5. Spec class (`jcajce/spec/<Name>KeySpec.java`)

If the algorithm takes structured parameters (IKM + salt + info for HKDF, scalar + curve for EC, etc.), define a spec class. Conventions:

1. Implements `java.security.spec.KeySpec`.
2. Constructor rejects null / empty / out-of-range inputs with `IllegalArgumentException` + a specific message.
3. Defensive cloning on byte-array fields — store via `Arrays.clone(...)` (project helper, null-safe), getters return `Arrays.clone(...)` again.
4. Digest names resolved via `DigestUtil.getCanonicalDigestName(...)` so callers can pass "SHA-256" / "SHA256" / OID equivalently.

### 6. SPI class

Extends the JCE SPI abstract class. The choices:

1. **`CipherSpi`** for symmetric ciphers (block + stream + wrap + AEAD) — typically extends an existing project `BlockCipherSpi` base if it's a block cipher.
2. **`SignatureSpi`** for signatures.
3. **`KeyAgreementSpi`** for ECDH / XDH / DHE family.
4. **`SecretKeyFactorySpi`** for password- and KDF-based factories.
5. **`KeyPairGeneratorSpi`** (you extend `KeyPairGenerator` directly).
6. **`KeyFactorySpi`** for X.509 / PKCS#8 / spec-based key materialisation.
7. **`MacSpi`** for HMAC etc.
8. **`MessageDigestSpi`** for hashes.

JCE state-machine rules apply — every SPI is a state machine. Read CLAUDE.md sections "Test that the SPI is correctly usable after reset" and "Throw the right JCE exception type" before writing. Multi-release notes:

1. If the SPI uses `synchronized(this)` for native-reference keep-alive, also create a `java9/` override that uses `Reference.reachabilityFence(this)` in `try { ... } finally { ... }`.
2. If the SPI uses Java 11+ APIs (`NamedParameterSpec`, `XECPublicKey`, etc.), gate via reflection or provide a `java11/` override. CLAUDE.md "Multi-release source-set API stability — public surface MUST be identical".

### 7. Provider registration

Create `Prov<NAME>.java` in `org.openssl.jostle.jcajce.provider`. Inside `configure(JostleProvider provider)`, call `provider.addAlgorithmImplementation("<Type>", "<Name>", PREFIX + "<Suffix>", attr, (arg) -> new <Spi>())` for each transformation, plus `provider.addAlias("<Type>", "<Name>", "<OID>")` for every OID alias.

Then wire into `JostleProvider.setup()` (constructor / static block) with `new Prov<NAME>().configure(this);`. Forgetting this single line is the most common "I built everything and nothing works" mistake.

Notes:

1. Algorithm-name lookups are **case-insensitive** in the JCE provider registration — `addAlgorithmImplementation("Cipher", "AESWrap", ...)` plus `addAlgorithmImplementation("Cipher", "AESWRAP", ...)` will collide at registration time. Pick one canonical casing. JCE rules on `Cipher.getInstance("X/Y/Z")` lookup forms (1–4) matter: registering an alias on a bare-algorithm transformation can bypass `engineSetPadding` entirely. CLAUDE.md "JCE transformation lookup: form-1 alias vs form-4 fallback".
2. Set `SupportedKeyClasses` and `SupportedKeyFormats` attributes if the JCE caller routes by these.

### 8. Tests

Per CLAUDE.md "Tests must exercise the negative path", "Run agreement tests against BouncyCastle, with random inputs", "Boundary-test key, IV, and nonce lengths", and "Test that the SPI is correctly usable after reset":

1. **Positive roundtrip** — generate / sign / wrap / derive, then verify / unwrap / agree against the original.
2. **BC agreement** — every algorithm Jostle exposes needs at least one agreement test against BouncyCastle, in both directions (Jostle-produces / BC-consumes and vice versa), with random inputs across multiple trials.
3. **Negative path** — at least one test that breaks a precondition (tampered ciphertext / wrong key / mismatched algorithm / malformed input) and asserts the right typed exception with a specific message assertion (`assertEquals` for fixed messages, `startsWith` / `contains` for variable ones).
4. **`*LimitTest`** — NI-level tests calling `ni_*` directly to exercise the bridge's input validation. Boundary probes at exactly `boundary + 1` (CLAUDE.md "Probe range-check boundaries at exactly boundary + 1").
5. **`*OpsTest`** — one test per OPS-instrumented site in the native code. Requires `JOSTLE_OPS_TEST=1` at native build time.
6. **SPI reset/reuse** — two operations on one instance, negative-then-positive sequence, role-flip for Signature, etc.
7. **Offset-write contract** — for any `engineGenerateSecret(byte[], int)` / `Cipher.doFinal(out, off)` style API. CLAUDE.md "Verify offset-write contracts via functional round-trip, not sentinel bytes".

Use the project helpers (`org.openssl.jostle.util.Arrays.areEqual`, `Arrays.clone`) not the JDK `java.util.Arrays.equals` / `.clone()`.

## Lightweight: OID alias on an existing transformation

Just `provider.addAlias("<Type>", "<existing name>", "<OID>")` in the `Prov<NAME>.configure` for that family. Then a test that confirms `<Type>.getInstance("<OID>", JostleProvider.PROVIDER_NAME)` resolves and produces output byte-identical to the name-lookup factory (run multiple random trials).

## Verification checklist

After writing all the code, walk through `references/verification-checklist.md` before submitting. It catches the layer that's easiest to forget — typically OPS instrumentation, multi-release override sync, CMakeLists registration, or the `JostleProvider.setup()` wiring.

## Final order of operations

1. Pick canonical reference (`references/family-patterns.md`).
2. Add error codes + OSSLKeyType entries up front so the rest of the code can reference them.
3. Write native util (`.c`/`.h`) and add to `CMakeLists.txt`.
4. Write JNI bridge.
5. Write FFI bridge.
6. Write NI interface + JNI impl + FFI impl Java side.
7. Write spec class(es) if needed.
8. Write SPI class (+ multi-release overrides).
9. Write `Prov<NAME>.configure` and wire into `JostleProvider.setup()`.
10. Build native (`./gradlew :jostle:compileJava` then `./interface/build.sh` — header generation must run before the native build).
11. Write tests at every level.
12. Run unit + limit + ops tests on both JNI and FFI bridges (`unitTest25JNI`, `unitTest25FFI`, `integrationTest25JNI`, `integrationTest25FFI`).
13. Walk through `references/verification-checklist.md`.
