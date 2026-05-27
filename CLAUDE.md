# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

OpenSSL Jostle is a JCA/JCE provider that delegates cryptographic implementations to OpenSSL via a native interface layer. Two languages, three layers:

```
Java SPI  →  JNI / FFI bridge (per-transformation)  →  C abstraction (interface/util/)  →  OpenSSL EVP_*
```

Building requires Java 25; the resulting jar runs on Java 8 → Java 25 via a multi-release jar.

## Build

Two stages: native interface, then jar. **Both `OPENSSL_PREFIX` and `JAVA_HOME` (Java 25) must be set.**

```bash
# Stage 0 (one-off): build OpenSSL 3.5 with --prefix pointing somewhere accessible,
# then export OPENSSL_PREFIX=<that prefix>.

# Stage 1: generate JNI headers from current Java sources.
./gradlew clean compileJava

# Stage 2: compile native interface (writes to jostle/src/main/resources/native/<os>/<arch>).
./interface/build.sh           # or build.bat on Windows
# Optional: build with operations-test instrumentation enabled.
JOSTLE_OPS_TEST=1 ./interface/build.sh

# Stage 3: jar (runs unit tests by default — add -x test to skip).
./gradlew clean build
```

`build_osx.sh` and `build_linux.sh` automate all three stages and do two passes (with and without `JOSTLE_OPS_TEST`). They expect `OPENSSL_PREFIX` to point at `../openssls/<os>/<arch>` relative to the repo.

## Test

Four test categories distinguished by class-name suffix:
1. `*Test` (no suffix below) — **Unit**: parallel-safe; compares behavior to BouncyCastle, asserts portability.
2. `*LimitTest` — sequential; calls `*NI` directly to exercise input-validation edges.
3. `*OpsTest` — sequential; requires `JOSTLE_OPS_TEST=1` at build time. Uses macros in `interface/util/ops.h` to fault-inject around OpenSSL/JVM calls that are otherwise impossible to exercise.
4. `*IntegrationTest` — sequential; miscellaneous tests that need ordered execution.

The base `:jostle:test` task **excludes** Limit/Ops/Integration. To run those you need the Java-25-specific tasks (which require `BC_JDK25`):

```bash
# Set BC_JDK25 to a Java 25 install; tests that need it will be skipped otherwise.
export BC_JDK25=/path/to/jdk-25

# Unit tests, JNI and FFI on Java 25 explicitly:
./gradlew :jostle:unitTest25FFI :jostle:unitTest25JNI

# Limit + Ops + Integration tests on Java 25:
./gradlew :jostle:integrationTest25FFI :jostle:integrationTest25JNI

# Run a single test class or method:
./gradlew :jostle:test --tests "org.openssl.jostle.test.crypto.AESAgreementTest"
./gradlew :jostle:test --tests "org.openssl.jostle.test.crypto.AESAgreementTest.testJce_aesCfb_aliasesToCfb128"
```

Older JDKs (`BC_JDK8`, `BC_JDK17`, `BC_JDK21`) trigger additional `testNN` tasks if their env vars are set.

To switch the native build between OPS-instrumented and not, you must rebuild the C interface — the gradle layer doesn't recompile native code on its own.

## Multi-release source layout (critical)

`jostle/src/main/java<N>/` directories produce per-Java-version overrides in the multi-release jar:
1. `java/` — Java 8 baseline; uses `synchronized(this)` to keep native references alive.
2. `java9/` — same classes re-implemented using `Reference.reachabilityFence(this)` in `try { ... } finally { ... }`. Loaded on JDK 9+.
3. `java11/`, `java15/`, `java17/`, `java21/`, `java25/` — replace classes that depend on APIs added/removed at those levels.
4. `java25/` — also contains the FFI implementations of the `*NI` interfaces (`MDServiceFFI`, `BlockCipherFFI`, etc.) and the FFI-aware `NISelector`.

When you change a class that has overrides in `javaN/`, you **must apply equivalent changes** to every override copy. There is no automation guarding against drift; the `DefaultRandSourceParityTest` in `src/test/java/.../rand/` is one example of a source-level parity guard.

**Test source sets follow the same split.** `src/test/java/` compiles at `release=8` — tests that use Java 9+ APIs (`DrbgParameters`, `Reference.reachabilityFence`, sealed classes, the FFI APIs) MUST live in `src/test/java25/`. The `unitTest25*` / `integrationTest25*` Gradle tasks run BOTH source sets together against a Java 25 JVM, so a test in `src/test/java25/` runs alongside everything in `src/test/java/`. Use this split to add strength-validation, DRBG, or FFI-only tests; put baseline coverage that works on every JDK in `src/test/java/`.

**Test classpath uses `jar.archiveFile`, not live class outputs.** The `test25` source set compiles against the assembled multi-release jar. If you modify a class/interface that tests reference, `compileTest25Java` will see the OLD signature until the jar is rebuilt — `./gradlew :jostle:jar`. Most often surfaces when you add a new method to a project-internal interface (`RandSource`, `MDServiceNI`, etc.) and test compilation fails with "method does not override or implement a method from a supertype" because the jar still contains the pre-edit version.

## How a transformation is wired

A given crypto operation (e.g. ML-DSA signatures) involves files in roughly this layout:

1. **Public interface** — `org.openssl.jostle.jcajce.interfaces.SLHDSAPrivateKey` (extends `java.security.PrivateKey`).
2. **Package-private impl** — `org.openssl.jostle.jcajce.provider.slhdsa.JOSLHDSAPrivateKey`.
3. **SPI class** — `SLHDSASignatureSpi` in the same provider sub-package; calls `xxxServiceNI`.
4. **NI interface** — `SLHDSAServiceNI` declares the native operations; default methods centralize error-code-to-exception mapping (see `MDServiceNI` for the canonical pattern).
5. **JNI implementation** — `SLHDSAServiceJNI` (Java) → `interface/jni/slhdsa_ni_jni.c` (C glue, validates input, calls `interface/util/slhdsa.c`).
6. **FFI implementation** — `SLHDSAServiceFFI` in `src/main/java25/`; targets `interface/ffi/slhdsa_ni_ffi.c` (same validation, same error codes).
7. **C abstraction** — `interface/util/slhdsa.c/.h` is the only place that calls `EVP_*` directly.
8. **Provider registration** — `org.openssl.jostle.jcajce.provider.ProvSLHDSA.configure(JostleProvider)`, invoked from `JostleProvider.setup()`.

`NISelector` decides at load time whether to return JNI or FFI impls. The decision is forced by setting `org.openssl.jostle.loader.interface=jni|ffi|auto|none`.

## Native code conventions (`interface/`)

1. **Bridge layer (`interface/jni/`, `interface/ffi/`)** is the only layer that validates user-supplied inputs and surfaces failures as typed return codes. The bridge MUST do all of the following before calling util:
   1. **Null-check every user-supplied pointer** — strings (curve names, digest names), byte arrays, and native handles cast from `jlong` (JNI) or `size_t`/raw pointer (FFI). Each gets a typed return code (`JO_NAME_IS_NULL`, `JO_INPUT_IS_NULL`, `JO_KEY_SPEC_IS_NULL`, `JO_SIGNER_CTX_IS_NULL`, etc.). **Never `jo_assert` on a value derived from a Java/FFI caller.**
   2. **Range-check every user-supplied length** — sign (`< 0` → `JO_*_IS_NEGATIVE`), zero where zero is meaningless (`== 0` → `JO_*_IS_NEGATIVE`), and upper bound where the value will be cast to `int` downstream (`> INT32_MAX` → `JO_INPUT_TOO_LONG_INT32` / `JO_OUTPUT_TOO_LONG_INT32`).
   3. **Range-check offset+length pairs** against the buffer they index — FFI uses `check_in_range(size, off, len)`; JNI uses `check_bytearray_in_range(ctx, off, len)`. These compute the addition safely even when both operands approach `SIZE_MAX/2`.
   4. **Translate JNI/FFI access failures** — `load_bytearray_ctx` / `load_critical_ctx` / `GetStringUTFChars` returning failure → `JO_FAILED_ACCESS_*` / `JO_UNABLE_TO_ACCESS_NAME`.

   JNI **must** request critical pointers via JVM and surface failures explicitly; FFI **must** receive the full byte-array size as a parameter so it can do its own range checks. **Both layers must return identical error codes for identical inputs** — if FFI rejects a value, JNI rejects it too with the same code, and vice versa.

2. **Abstraction layer (`interface/util/`)** is the only place that calls OpenSSL. It maintains state in structs across the JCA new → init → update → final → reset lifecycle. Util **trusts** the bridge to have validated user-supplied inputs and asserts those preconditions as invariants (see point 5). That includes `rnd_src` — both JNI and FFI bridges null-check the RandSource on every entry point that takes one, so util just `jo_assert`s it. Util's only legitimate `if (X) return JO_*` patterns are:
   1. **State checks** on bridge-validated outer pointers — e.g. `spec->key == NULL` (the `spec` was validated by the bridge, but its inner `key` field may legitimately be unset on a freshly-allocated spec), `ctx->digest_ctx == NULL` (`JO_NOT_INITIALIZED`), `ctx->opp != EC_OP_SIGN` (`JO_UNEXPECTED_STATE`).
   2. **OpenSSL-output bounds** after a probe call — e.g. `if (sig_len > (size_t) INT32_MAX) return JO_OUTPUT_TOO_LONG_INT32;` after `EVP_DigestSignFinal(NULL, &sig_len)` or `EVP_PKEY_derive(NULL, &need)`. These are values OpenSSL returned to us; we validate them before casting back to `int32_t` for the Java return path.

   Anything else that looks like user-input validation in util is a bug — move it to the bridge. Older modules (e.g. `rsa.c`) may still have the legacy "util as safety net" form for `rnd_src`; that's pre-existing tech debt, not the rule for new code.

3. Functions returning a pointer take `int32_t *err` as the last parameter; everything else returns a status code (`bc_err_codes.h`). Negative codes are errors, non-negative are byte counts / success.
4. Use `get_global_jostle_ossl_lib_ctx()` when calling `EVP_*_fetch` / `EVP_*_new_from_name`. Never call OpenSSL with a `NULL` lib ctx — operations need the lib ctx that hosts the Java RAND bridge.
5. `jo_assert` is for catastrophic conditions only (allocation failure, internal invariant). **Never use it for user-supplied input** — user errors must surface as error codes the bridge layer translates to JCE exceptions. Concretely, in the util layer:
   1. **Every parameter the bridge has validated is asserted as an invariant**, not error-returned. That includes pointers (`spec`, `key`, `digest_name`, byte-array pointers, `ctx`) AND value bounds the bridge enforces (`scalar_len > 0 && scalar_len <= INT32_MAX`, `in_len <= INT32_MAX`, `sig_len <= INT32_MAX`). If a util-layer assert fires, it means the bridge skipped a check — programmer error, not user error.
   2. **The exceptions** that stay as `if (X) return JO_*` in util are listed in point 2 (rnd_src, state checks, OpenSSL-output bounds). Anything outside that list belongs in the bridge.
6. **Use `INT32_MAX` (not `INT_MAX`)** when the bound's intent is "fits in int32_t" — it pairs with the `JO_*_INT32` error code names, the `int32_t` parameter types crossing the bridge, and the `(int32_t)` casts on the way back to Java. `int` happens to be 32-bit on every platform we build for, but `INT32_MAX` makes the intent unambiguous. Reserve `INT_MAX` for bounds that genuinely depend on the platform `int` width (rare).
7. Operations-test macros (`OPS_FAILED_ACCESS_1`, `OPS_OPENSSL_ERROR_3`, `OPS_FAILED_INIT_2`, etc.) defined in `interface/util/ops.h` are placed inside conditionals so tests can fault-inject failure paths. They expand to `is_ops_set(N) ||` in OPS builds and to nothing otherwise; the `OPS_OFFSET_*` macros let tests differentiate between multiple call sites that produce the same error code.

## SecureRandom flow

Every native call that consumes entropy must accept a `RandSource` parameter. On the native side, the bridge layer null-checks and calls `rand_set_java_srand_call(rnd_src)` (sets a thread-local). The Java RAND bridge inside the OpenSSL provider then up-calls into Java for entropy.

`rnd_src` is **not** valid across calls — it's only live for the duration of the function it was passed into. Cache the Java reference on the SPI side, not in C state.

Direct buffer access (JNI critical regions) cannot make up-calls — fetch random data before entering critical sections, or after leaving them.

**Strength-appropriate default RNG for post-quantum algorithms.** ML-KEM-768/1024, ML-DSA-65/87, and SLH-DSA-*-192/256 require RNG strength above the JDK default 128-bit DRBG — the C-side RAND gate rejects insufficient entropy with `JO_RAND_INSUFFICIENT_STRENGTH` (GH issue #34). The canonical pattern, with the existing four PQ SPIs (`MLKEMKeyPairGenerator`, `MLKEMKeyGenerator`, `MLDSAKeyPairGeneratorImpl`, `SLHDSAKeyPairGenerator`) as reference:

1. Parameter spec exposes `getRequiredStrengthBits()` returning 128/192/256.
2. `CryptoServicesRegistrar.getSecureRandom(int strengthBits)` returns a strength-targeted DRBG via `SecureRandomProvider.get(int)`. The Java 9+ override of `ThreadLocalSecureRandomProvider` constructs `SecureRandom.getInstance("DRBG", DrbgParameters.instantiation(...))`; Java 8 inherits the default that delegates back to `get()`. The multi-release split lives in `ThreadLocalSecureRandomProvider`, NOT in `CryptoServicesRegistrar` (which is a single source file).
3. SPIs hold a `RandSource randSource` field initialised in the constructor to a strength-appropriate default (so typed instances work without explicit `initialize()`). `initialize` / `engineInit` calls `DefaultRandSource.replaceWith(randSource, userRand, strengthBits)` which reuses the existing wrapper when current strength is sufficient AND the caller didn't supply a different SecureRandom — avoids per-call `wrap()` allocation. `generateKeyPair` / `engineGenerateKey` uses `randSource` directly with no further resolution.
4. Strength-validation gate at `initialize` / `engineInit`: if the caller-supplied SecureRandom reports a non-zero strength via `DefaultRandSource.strengthOf(rand)` below the requirement, throw `InvalidAlgorithmParameterException` immediately. A reported strength of 0 means "unknown" (Java 8, or non-DRBG SecureRandom) — accept it and let the C-side RAND gate be the safety net.
5. Don't add a separate `SecureRandom userRandom` field alongside `randSource` — `replaceWith` takes the user's SecureRandom as a parameter, so it doesn't need to be cached on the SPI. The user-supplied SecureRandom enters `replaceWith` directly from the `initialize` parameter.

## Style and submission

1. Checkstyle config: `config/checkstyle/checkstyle.xml`. PRs must pass.
2. Match existing code style — Java looks Java, C looks C. Look at `MDServiceSPI`/`MDServiceNI`/`md.c` as the canonical reference for newer transformations; some older code follows an earlier pattern where error handling lived in the SPI rather than in `*NI` default methods.
3. SPI sub-packages under `org.openssl.jostle.jcajce.provider` are usually named after the transformation (`mldsa`, `kdf`); `Prov<NAME>` classes register them with the provider.
4. AUTHORS.md, LICENSE, CONTRIBUTING.md exist — read CONTRIBUTING.md before significant changes; it is the source of truth for code organization, testing expectations, and the JNI-FFI split.
5. Use `org.openssl.jostle.util.Arrays.clone(byte[])` rather than direct `byteArray.clone()` for byte-array copies. The project helper is null-safe (returns null on null input rather than NPE-ing); a direct `.clone()` is a hidden NPE if the array reference happens to be null. Same applies to the other primitive-array clones the helper provides (`boolean[]`, `int[]`, `long[]`, `BigInteger[]`, etc.).
6. Use `org.openssl.jostle.util.Arrays.areEqual(...)` for array equality in tests and production code rather than `java.util.Arrays.equals(...)`. Same null-safety rationale as the `clone` rule above — the project helper returns `true` when both refs are null and `false` when only one is, where the JDK overloads can NPE on certain null patterns. Applies across every primitive overload (`byte[]`, `int[]`, `long[]`, etc.) and `Object[]`.
7. **All `if` / `else` / `else if` bodies use braces — no exceptions, even for single-statement bodies.** `if (foo) return bar;` and `if (foo) continue;` are forbidden; write `if (foo) { return bar; }` (formatted on three lines per the project's K&R-with-brace-on-newline style). The rule prevents the classic dangling-else / accidental-second-statement bug when someone adds a second line to what looks like a single-statement body, and matches the convention used in every existing braced block in the codebase. Applies to Java sources AND tests. C code in `interface/` follows the same rule.

## Useful debug entrypoints

`org.openssl.jostle.util.DumpInfo` (run via the standard `java --module-path .../openssl-jostle-1.0-SNAPSHOT.jar --module org.openssl.jostle.prov/org.openssl.jostle.util.DumpInfo`) prints the loaded provider, OS/arch, JVM version, the resolved interface (JNI/FFI), and which native libs were extracted. Use it to confirm a build picked up the right native libraries.

### Tests must exercise the negative path

A roundtrip-only test (sign → verify, encrypt → decrypt, hash → compare, encode → decode) passes equally well against a broken implementation — a `verify()` stubbed to return `true`, a tag check that's been short-circuited, an encrypt that copies its input, a digest that returns a fixed-length zero buffer, or a parser that silently accepts any bytes will all sail through a happy-path test. Placeholder values left in during development (`return new byte[outLen];`, `System.arraycopy(in, 0, out, 0, len);`, hardcoded literals returned for the one input the author tested with) are exactly the kind of thing a positive-only test misses. For every positive test, add at least one negative case that breaks the precondition the implementation relies on:

- **Signatures / MACs** — after signing, flip a byte in the message and assert verification returns `false` (or throws). For algorithms with key consistency checks (RSA, EC, key-validating PQC schemes), also test that a corrupted public/private key is rejected at parse time or causes verification to fail.
- **AEAD** — damage the ciphertext, the tag, or the AAD independently and assert the decryptor throws `InvalidCipherTextException`. Don't rely on a single "bit-flip somewhere" test; bit-flipping AAD vs. ciphertext vs. tag exercises different code paths.
- **Block ciphers** — confirm `encrypt(p, k) != p` (the transform actually transforms), `decrypt(encrypt(p, k), k) == p`, and `decrypt(c, wrongKey) != p`. An identity stub or one that returns a constant buffer will round-trip cleanly through a test that only checks decrypt-after-encrypt with a single key.
- **Digests / XOFs** — confirm a single-bit change in the input changes the output, and that two different short inputs don't produce the same digest. A stub that returns zeros, or one that hashes only the first few bytes, will pass any test that compares only one input against one expected value.
- **KAT vectors** — pair every "input → expected output" with at least one "modified input → output differs", so an implementation that ignores some input bits can't pass. Use multiple vectors of different lengths where the spec offers them.

This matters more in this codebase than most: many algorithms have a Java path and a native path, and a pure-positive test will accept either path producing wrong-but-self-consistent output. Negative tests are often what surface a divergence between the two.

### Vary the chunking, and randomise the inputs

Streaming algorithms (block ciphers, AEAD, digests, MACs, signatures) all have a buffering layer that absorbs partial blocks. A test that only calls `processBytes(wholeMessage, 0, len)` won't exercise the partial-block path; a test that only feeds bytes one at a time won't exercise the bulk path. Implementations have shipped where one path was right and the other returned garbage — and the native paths in this codebase deliberately buffer differently from the pure-Java paths (see "Behavioural difference vs. upstream BC" above), so the same input chunked differently is exactly the case where Java and native diverge.

For every implementation with incremental input methods, run the same logical input through several chunkings and assert byte-identical output (and identical tag/MAC):

- **one shot** — single `doFinal(in, 0, len, out, 0)` (or one-shot `digest(in)` for hashes).
- **byte-by-byte** — `update(b)` repeatedly, then `doFinal`.
- **adversarial offsets** — chunks of `BLOCK_SIZE - 1`, `BLOCK_SIZE`, and `BLOCK_SIZE + 1` so partial-block boundaries land in different places, plus a chunk that spans the last block (catches finalisation bugs).
- **random splits** — partition the message at random offsets so chunk boundaries don't always coincide with algorithmic alignments.

The same matrix applies to digest `update` vs. one-shot, and to incremental signature/MAC `update` vs. building the message buffer up-front. For AEAD, AAD chunking is independent of plaintext chunking — vary them separately.

When the test isn't anchored to a published KAT (i.e. a roundtrip comparing `decrypt(encrypt(x)) == x` rather than against a fixed expected output), use fully random values for **everything** — key, IV / nonce, AAD, plaintext content, and plaintext length. Hardcoded inputs let bugs hide in alignment-, length-, or value-specific code paths: an off-by-one in CTR counter handling that only fires past a certain block count, a GCM length encoding bug that only triggers when AAD length mod 16 is zero, a digest finalisation bug that only fires when the input length is a multiple of the block size. Seed `SecureRandom` from a value the test logs on failure so a flaky run is reproducible.

### Run agreement tests against BouncyCastle, with random inputs

Jostle's native path can produce wrong-but-self-consistent output that a roundtrip-only test never surfaces — a `verify()` stub that always returns `true`, an encrypt that copies its input, a digest that returns zeros, a tag check that's been short-circuited. The strongest defence against this is cross-validation against an independent reference implementation: BouncyCastle. **For every transformation Jostle exposes, there must be at least one agreement test that pipes ciphertext / signatures / MACs / KEM-encapsulated material between BouncyCastle and Jostle and asserts byte-equality (or the equivalent semantic check).** Files following the `*AgreementTest` convention are where these tests live (see `AESAgreementTest`, `CAMELLIAAgreementTest`, `SM4AgreementTest`, the `*BCParity*` methods in `RSATest` / `RSAOAEPCipherTest` / `RSAPKCS1CipherTest` for canonical examples).

For each algorithm an agreement test covers, do all of the following:

- **Sign / encrypt / wrap with Jostle, verify / decrypt / unwrap with BouncyCastle** — exercises Jostle's encrypt-side and BC's decrypt-side. A bug in Jostle's encrypt that produces malformed-but-consistent output shows up here because BC's parser doesn't tolerate it.
- **Sign / encrypt / wrap with BouncyCastle, verify / decrypt / unwrap with Jostle** — exercises BC's encrypt and Jostle's decrypt independently. A different code path; an error here might not surface in the reverse direction.
- **Both directions in the same test class** — having only one direction means a divergence pinpoints less precisely which side is broken.
- **Random keys** — generate via the JCE `KeyGenerator` / `KeyPairGenerator` for each test invocation; do NOT pin a hardcoded test key. A fixed key can hide alignment- or value-specific bugs in key-schedule or key-derivation code.
- **Random IVs / nonces / salts** — generate fresh random bytes per trial; a fixed IV hides bugs in IV-handling code that only surface for specific bit patterns.
- **Random message content AND length** — vary plaintext / signed bytes both across trials and across test invocations; an off-by-one in finalisation only fires when the input length is a multiple of the block size, etc.
- **Run the matrix multiple times per test** — typically 10–25 trials per JUnit test; a single random run probes only one point in the input space. Seed `SecureRandom` from a value the test logs on failure so a flaky run can be reproduced.

Independently of the encrypt/decrypt agreement, **every key type Jostle exposes must round-trip through BouncyCastle's encoding** — meaning a key generated by Jostle, serialised as X.509 / PKCS#8 (`getEncoded()`), must decode cleanly through BC's `KeyFactory.getInstance(alg, "BC")` and operate as expected, and vice versa. Test both directions: encode-with-Jostle → decode-with-BC and encode-with-BC → decode-with-Jostle. This catches three common bug classes that purely-internal tests miss:

- **Wrong OID emitted by encoding** — Jostle's `getEncoded()` produces bytes that BC parses as a different algorithm, or as the same algorithm with the wrong parameter set. Sign/verify on the resulting key still works because BC sees the right key data, but a downstream consumer keying off the OID would miscategorise.
- **Subtle parameter mis-encoding** — e.g. an RSA-PSS key emitted with `parameters NULL` instead of an explicit `RSASSA-PSS-params SEQUENCE`, or an EC key with a curve OID rather than an explicit named-curve `ECParameters`. The round-trip succeeds because BC tolerates both forms; a stricter parser (or a different version of BC, or a third-party JCE provider) does not.
- **Asymmetric encode/decode acceptance** — Jostle accepts BC's encoding but BC rejects Jostle's (or vice versa). Only a both-directions test surfaces this.

For asymmetric keypairs, run the round-trip on **both** the public and private halves. For algorithms with multiple key-spec formats (e.g. RSA's `X509EncodedKeySpec` / `RSAPublicKeySpec` / `RSAPrivateCrtKeySpec`), test every format Jostle's `KeyFactory` advertises via the `SupportedKeyFormats` attribute. Use the same random-input rules as the agreement tests above — generate fresh keys per trial, never a fixture key whose encoding might happen to be valid by coincidence.

### Boundary-test key, IV, and nonce lengths

Fixed-length validation is often condensed into a compact single-expression check — bit operations combining `& ~`, an `|` of differences, or arithmetic that folds three valid AES key lengths into one branch. These are easy to get subtly wrong (a check that accepts 17 alongside 16, or rejects 32 because of a mask typo) and the bug is invisible to any test that only ever exercises a valid length. Whenever you add a test for an input that has a length constraint, also test the values immediately on each side of the spec'd length and assert the implementation rejects with the expected exception:

- **Single fixed length** (e.g. GCM-SIV / GCM nonce = 12) — test 11, 12, 13. Also 0 and `null`.
- **Discrete valid set** (e.g. AES key ∈ {16, 24, 32}, or {16, 32} where 24 is rejected) — test every valid length, plus the boundaries: 15, 17, 23, 25, 31, 33. Also 0, 1, and a value well above the maximum (e.g. 64) so a check that only enforces an upper bound can't slip through.
- **Permitted range** (e.g. an HMAC key with a min and max) — test `min - 1`, `min`, `max`, `max + 1`.

Apply the matrix to keys, IVs, nonces, and salts **independently** — a missing IV-length check is easy to hide if a key-length check happens to fire first. And confirm the exception type matches the contract (`IllegalArgumentException` from `init`, `InvalidKeyException` from JCE entry points); a `bc_assert` abort on the C side looks identical to a clean failure from a poorly-written test, so verify the rejection reaches Java as a typed exception rather than a process abort.

### Verify offset-write contracts via functional round-trip, not sentinel bytes

Every NI (and SPI) entry point that writes into a caller-supplied buffer at a non-zero `outOff` is making two contracts: (1) it must NOT write to bytes preceding `outOff`, and (2) the bytes from `outOff..outOff+writtenLen` must be the actual ciphertext / signature / digest the operation claims to have produced. Single-byte sentinel proxies for either contract are flaky because the operation's output is essentially uniformly random — `assertNotEquals((byte) 0xAA, big[outOff])` has a built-in 1-in-256 false-positive rate. Across a multi-config CI matrix that's a real flake.

Use the four-step structure for every offset-write test:

1. **Fill the whole buffer with random bytes** (via `new SecureRandom().nextBytes(big)`), not a fixed sentinel. Random fill matches what a real caller's buffer state would look like and exercises the bridge under realistic conditions.
2. **Save aside a copy of the prefix region** (`System.arraycopy(big, 0, expectedPrefix, 0, prefix)`) BEFORE calling into the operation.
3. **Compare the prefix region byte-for-byte against the saved copy** after the call (`assertArrayEquals(expectedPrefix, actualPrefix)`). This is the bridge contract — bytes preceding `outOff` must be untouched. No sentinel involved.
4. **Validate the output region functionally** by extracting `big[outOff..outOff+writtenLen]` and round-tripping it through the inverse operation: a ciphertext extracted from the buffer must decrypt to the original plaintext; a signature must verify against the original message; a digest must match a reference. Then **extract a window starting at `outOff-1`** and assert it does NOT round-trip — proves the operation wrote at exactly `outOff` and not one byte earlier.

The negative shifted-window check is the part that catches an off-by-one in the bridge. Without it, a bridge that wrote at `outOff-1` instead of `outOff` would still produce a buffer where the first `writtenLen` bytes happen to look like valid output (because they ARE valid output, just shifted). The shifted-window check forces the test to actually verify the boundary.

Test this matrix at both layers — NI-level (via the raw `cipherNI.doFinal` / `serviceNI.sign` calls in `*LimitTest` classes) and JCE-level (via `Cipher.doFinal(in, off, len, out, outOff)` and `Signature.sign(out, off, len)` in regular unit tests). The two layers can diverge on subtle ways the SPI handles `outOff` (e.g. if the SPI re-implements the offset arithmetic instead of passing through to the NI), so cover both. `RSALimitTest.RSAServiceNI_sign_writesAtOffsetWithoutClobberingPrefix` and `RSATest.testPkcs1_signWritesAtOffsetWithoutClobberingPrefix_jce` are the canonical pair.

### Feed negative values into every integer parameter

Java `int` is signed; nearly every API in this codebase that takes a length, offset, count, or size declares it as `int`. Range checks that look fine in passing — `if (len > buffer.length) throw ...` — silently accept negative values, and the negative then propagates into a `size_t` cast on the JNI side, an allocation expression like `new byte[len + 16]` (`len = -1` becomes a 15-byte buffer, no exception), or pointer arithmetic that reads before the start of the input. For every test you write that calls a method with an `int` parameter — `inOff`, `len`, `outOff`, `iterations`, `macSize`, `keySize`, `ivLen` — also test:

- **`-1`** — catches checks written `len > 0` instead of `len >= 0`, and conditionals comparing in the wrong direction.
- **`Integer.MIN_VALUE`** — special-cases anywhere the implementation does `Math.abs(len)` or `-len`, both of which are still negative for `MIN_VALUE` and overflow silently.
- **Combinations** — negative offset with valid length, valid offset with negative length, both negative. A bug that's masked when one parameter is sane is still there when the other is the one being checked first.

For methods that cross the JNI boundary this matters more — a negative `jint` cast straight to `size_t` becomes ~2³² (or ~2⁶⁴ on 64-bit hosts), which then drives either a runaway allocation or a `memcpy` that reads memory the caller never owned. Verify the rejection happens at the Java boundary or as an explicit C-side check **before** the cast, and surfaces as a typed exception rather than a segfault.

### Probe range-check boundaries at exactly `boundary + 1`, not arbitrary far-from-boundary values

`*LimitTest` exercises offset / length / size range-check rejections at the NI surface — these are the tests whose entire purpose is to confirm the bridge's `if` condition fires at the right value. A test that passes `new byte[64], 200` for "offset past end" rejects the call, but it doesn't probe the boundary: a check written `> buffer.length + 100` (a real off-by-100 mistake) would still let `200` through but reject the same call with `offset = 65`. Pick the smallest value that should fail, not an arbitrary large number.

For every range-check rejection test, use exactly the boundary value:

1. **Offset past end** — for a buffer of length `N`, the smallest rejected offset is `N + 1` (the SPI typically accepts `offset == N` as "write at end with zero capacity"). Pass `new byte[N], N + 1`. Pair with a positive-side companion test that passes `offset == N` with `len == 0` and asserts no exception (or the appropriate zero-length success path) — this proves the boundary is exactly where it should be, not one in either direction.
2. **Length past end** — for a buffer of length `N` with valid `offset == 0`, the smallest rejected length is `N + 1`. Pass `new byte[N], 0, N + 1`.
3. **Offset+length past end** — pass values that exceed `N` by exactly one. Two separate tests: `(N - k, k + 1)` exercises the offset side (offset valid, length one past), and `(N - k + 1, k)` exercises the offset side itself slipping past. The canonical pair is `RSALimitTest.RSAServiceNI_update_outOfRange_offsetEdge` (`new byte[10], 1, 10` — `1 + 10 = 11 > 10`) and `RSAServiceNI_update_outOfRange_lenEdge` (`new byte[10], 0, 11` — `0 + 11 = 11 > 10`).
4. **Negative side already covered** by the previous section — `-1` and `MIN_VALUE`. Don't substitute one for the other; both directions of the boundary need a probe.

The principle is the same one that governs the "Boundary-test key, IV, and nonce lengths" section above (test `min - 1`, `min`, `max`, `max + 1`) — applied to the dynamic offset/length range checks at the NI surface. Far-from-boundary arbitrary values like `200`, `1000`, or `Integer.MAX_VALUE` are fine as additional tests for runaway-allocation paths, but they don't replace the `boundary + 1` probe.

### Test that the SPI is correctly usable after reset

JCE SPIs are state machines whose terminal operations — `sign`, `verify`, `doFinal`, `wrap`, `unwrap` — return the instance to a "ready for re-use without re-init" state. The reset path is its own code path: input buffers get cleared, the native `EVP_*_CTX` is reused (or rebuilt via an internal `reInit`), and any per-call randomness (OAEP seed, PSS salt, PKCS#1 PS bytes) must be regenerated rather than cached. A test that exercises one operation and stops misses every bug that lives in this transition — stale `digest_ctx` echoing the previous result, a buffer not cleared, a `lastKey` field not replaced when role-flips, randomness frozen because the underlying ctx wasn't properly re-randomised. For every Cipher and Signature transformation Jostle exposes, write reset/reuse tests covering the following patterns:

1. **Two distinct inputs through one instance.** Bind one `Signature` (or `Cipher`) instance, drive it twice with different messages, assert both outputs are correct. This is the baseline reset test and catches a buffer that wasn't cleared between calls.
2. **Same input twice — randomised algorithms must produce different outputs.** PSS, OAEP, and PKCS#1 v1.5 encryption all use fresh per-call randomness. Two `enc.doFinal(msg)` calls on the same plaintext must produce different ciphertexts; two `signer.sign()` calls on the same digest input must produce different signatures. Identical outputs prove the SPI is caching or freezing the random source — a real correctness bug, not a style issue.
3. **Same input twice — deterministic algorithms must produce identical outputs.** PKCS#1 v1.5 signing is deterministic; two `signer.sign()` calls on the same message must be byte-equal. A divergence proves the SPI's internal state changed between calls in a way that affects output.
4. **Negative-then-positive sequence.** Drive the SPI to a failure (tampered signature, bad ciphertext, structurally invalid input) and assert the typed exception fires. Then drive a successful operation on the same instance and assert it succeeds. This is the strongest reset test — it proves the failure path didn't poison the SPI's state. Native code that releases an `EVP_PKEY_CTX` only on success but not on failure, or that forgets to scrub a partial-result buffer, surfaces here.
5. **Positive-then-negative sequence.** Drive a successful operation, then a failing one on the same instance, and assert the failure surfaces correctly. A `verify()` SPI that caches a "true" result and echoes it on the next call (or short-circuits the next verify because the ctx still has the prior signature loaded) only fails this pattern.
6. **Role-flip on a Signature.** Call `initSign`, `update`, `sign` on one instance; then `initVerify` on the same instance and verify the result; then `initSign` again. The bidirectional flip exercises `lastKey` replacement and the SPI's reInit-after-terminal path. A role-leak (the second `initVerify` reusing the first `initSign`'s key state) only fires when the round-trip is on a single instance.

These tests are cheap — typically 15–30 lines each — and they're the only practical way to catch the class of bugs where the per-call path is correct but the inter-call transition isn't. The CLAUDE.md "exercise the negative path" rule applies recursively to reset: a positive-only reuse test ("two encrypts in a row") proves the SPI doesn't crash on reuse, but it doesn't prove the second encrypt actually re-randomised — the negative-then-positive and positive-then-negative patterns are what surface that.

### Pin the exception message in OPS / Limit-test catch blocks

The error-code → exception mapping in `DefaultServiceNI.baseErrorHandler` (and the per-NI `handleError` overrides like `BlockCipherNI.handleError`) is the only place that guarantees a specific `JO_*` code maps to a specific typed exception with a specific message. A test that only catches by type — `catch (OpenSSLException ex) { // expected }` — passes even when someone moves the case to a different arm whose typed exception happens to be the same but whose message format differs, or when the underlying error code silently changes to one that produces a different message via the same wrapper. Both are the exact bug classes the OPS / Limit infrastructure is designed to detect; an empty catch body fails to detect them.

Rule: every catch block in an `*OpsTest` or `*LimitTest` MUST assert the exception's message text. Three sub-patterns by injected-failure type:

1. **OPS-injected `JO_OPENSSL_ERROR`** — exact-match `assertEquals("OpenSSL Error: null", ex.getMessage())`. The OPS macro short-circuits before any real OpenSSL call, so the thread-local error queue stays empty and `String.format("OpenSSL Error: %s", OpenSSL.getOpenSSLErrors())` formats the literal `"null"` into the message.
2. **Real OpenSSL failures (Limit tests where actual EVP calls fail)** — prefix-match `assertTrue(ex.getMessage().startsWith("OpenSSL Error:"))`. The queue content varies with the call site and OpenSSL version, so an exact-match would be brittle; the prefix proves the wrapper fired without pinning the volatile detail.
3. **Other typed exceptions from the handler arms** — exact-match the fixed message from the corresponding `baseErrorHandler` arm, e.g. `assertEquals("a returned pointer changed unexpectedly", e.getMessage())` for `UnexpectedPointerChangeException` (`JO_UNEXPECTED_POINTER_CHANGE`), `assertEquals("output too long int32", e.getMessage())` for `OverflowException` (`JO_OUTPUT_SIZE_INT_OVERFLOW`).

Avoid `// expected` empty catch bodies. `BlockCipherOpsTest`, `ASN1UtilOpsTest`, `RSAOpsTest` are the canonical references; all `*OpsTest` files now follow the convention. Non-OPS tests that catch JDK-provider-thrown exceptions (`DigestException`, `NoSuchAlgorithmException`, `CloneNotSupportedException`, etc.) are exempt — those messages come from the JDK and vary across releases.

### Link every OPS test to its C-source fault-injection site

Every test in a `*OpsTest.java` file MUST carry a `// Exercises <repo-relative-c-path>:<line>` comment immediately above the `operationsTestNI.setFlag(...)` call that drives it. The comment names the exact C if-line containing the `OPS_*` macro that the test trips — i.e. the call site whose return value the flag short-circuits, NOT the error-return line. Without the link, reading the test alone doesn't tell you which C site it exercises: you'd have to compute `offset = -code - 2`, grep the C tree for the matching `OPS_OFFSET_*(offset)`, and walk backwards to the `if (OPS_* ...)` line every time.

The format is intentionally minimal — single line, same indent as the `setFlag` call, no prose, no function name:

```java
            // Exercises interface/util/rsa.c:589
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            int code = rsaServiceNI.ni_initSign(...);
```

Rationale for the minimalism: a bare `path:line` is the smallest target that can go stale (only the integer line number), so a C-side refactor that shifts lines is trivially fixed by re-running the annotate-ops-tests skill or by editing the integer. Any additional context — slot-reuse rationale, padding-choice rationale, "this fires inside helper X called by Y" — belongs in the test's surrounding Javadoc, NOT in the inline comment. The skill's "update in place" logic would overwrite manual prose added to the comment on the next re-run.

Three rules apply:

1. **Every new OPS test gets the comment at creation time.** This is not optional and not "we'll add it later" — the linkage is the only thing that makes the test traceable. Apply to `OPS_OPENSSL_ERROR_*`, `OPS_FAILED_ACCESS_*`, `OPS_INT32_OVERFLOW_*`, `OPS_LEN_CHANGE_*`, `OPS_POINTER_CHANGE`, every OPS family.
2. **The path is repo-root-relative.** `interface/util/rsa.c:589` for OpenSSL-error sites in the abstraction layer, `interface/jni/ec_ni_jni.c:42` for JNI access faults in the bridge layer. Same prefix whether the site lives under `util/` or `jni/`.
3. **The line number is the if-line, not the return line.** `if (OPS_OPENSSL_ERROR_1 md_ctx == NULL) {` is the line readers care about — it names the EVP function being faulted. The `return JO_OPENSSL_ERROR OPS_OFFSET_*(...)` on the next line is the consequence, not the test target.

For `OPS_OPENSSL_ERROR_*` tests, the `.claude/skills/annotate-ops-tests/` skill auto-generates and refreshes the comment from the test's `setFlag` + `assertEquals(-code, ...)` pair — useful after C edits shift line numbers. For `OPS_FAILED_ACCESS_*` and other non-offset OPS families the skill can't auto-link (no `OPS_OFFSET_*` macro to key the index off), so the comment must be added manually when the test is written.

### Hard-code security-critical OpenSSL parameters; pair with a runtime hard guard

When OpenSSL exposes a parameter that controls a security property the implementation depends on — even when its default already matches what we need — set it explicitly in our code via `EVP_PKEY_CTX_set_params` (or the equivalent setter). Defaults can change between OpenSSL releases, custom providers can override them, and someone editing the C code can flip a value "for diagnostics" without realising it weakens the implementation. The explicit set makes the intent unambiguous to anyone reading the source and survives all three of those drift modes.

The canonical example is RSA PKCS#1 v1.5 implicit rejection. `OSSL_ASYM_CIPHER_PARAM_IMPLICIT_REJECTION` is documented in `provider-asym_cipher(7)` as "Set by default in OpenSSL providers" — and the Bleichenbacher mitigation in `rsa_pkcs1.c` depends on the synthetic-plaintext-on-padding-failure behaviour that the parameter enables. We set `implicit_rejection = 1` explicitly in `rsa_pkcs1_init` immediately after `EVP_PKEY_CTX_set_rsa_padding`, with a block comment naming the security property and forbidding any change to the value. Apply the same pattern to any future security-critical parameter (e.g. PSS salt-length sentinels, mode-specific KDF iteration minimums) that has a sensitive default.

Pair the explicit set with a **runtime hard-guard test** — a regular unit test that exercises the API at the JCE surface and asserts the security property still holds. The test must be designed to fail loudly if the property is removed; a passing-positive-only test (e.g. round-trip succeeds) doesn't catch a regression where the property was removed but the happy path still works. The canonical hard-guard test is `RSAPKCS1CipherTest.testPKCS1_ImplicitRejection_HardGuard`: it constructs a deliberately-tampered ciphertext, calls decrypt, and asserts no `BadPaddingException` is thrown — a behaviour that can ONLY be true when implicit rejection is on. Verify the guard works by temporarily disabling the property (set the parameter to 0), confirming the test fails, then reverting.

Test design caveat for implicit-rejection guards: implicit rejection only fires for PKCS#1 v1.5 *padding* failures, not *structural* failures. A ciphertext whose integer value exceeds the modulus `n` is rejected by `RSA_public_decrypt` *before* the padding check runs — the test sees `BadPaddingException` even on a healthy implementation. For a 2048-bit RSA modulus, byte 0 of the 256-byte ciphertext is the most-significant byte; XOR-tampering it has roughly 50% probability of pushing the integer value past `n`. Tests that rely on the "no exception" property MUST restrict random tampering to bytes 1..length-1 — those positions cannot push the value past the modulus (the largest possible change is bounded well below the modulus's top-byte gap). The PKCS#1 hard guard's `posLowerBound = 1` constraint exists for exactly this reason; a future test that drops it will flake at a 1-in-256-ish per-trial rate.

OAEP doesn't have implicit rejection because OAEP is IND-CCA2 secure by construction and doesn't need it. Any OAEP decrypt failure (padding-check or structural) maps to a single error code (`JO_INVALID_CIPHER_TEXT`) at the C boundary, which the bridge translates to `InvalidCipherTextException` (`extends OpenSSLException`) and the SPI further translates to JCE-canonical `BadPaddingException` at `engineDoFinal`. The pattern of "distinct C error code → typed runtime exception → JCE-canonical checked exception" is what lets NI-level callers (limit tests) catch the specific `InvalidCipherTextException` without losing the JCE contract. Use this pattern when you have a failure mode that callers will want to react to differently from generic OpenSSL errors.

### Update `module-info.java` when you add a package

Each module has a JPMS descriptor at `<module>/src/main/jdk1.9/module-info.java` (e.g. `core/src/main/jdk1.9/module-info.java`) listing every exported package. The Java 8 sources under `<module>/src/main/java` and the descriptor are bundled into the same multi-release jar; the descriptor is the source of truth for what's visible when downstream code runs on JDK 9+ with `--module-path`. A package that exists in the source tree but isn't listed in `module-info.java` is invisible to modular consumers — class-path consumers still see it, which is why the omission is easy to miss locally.

When you add a class, ask which case applies:

- **Existing package** (e.g. dropping `ECBModeCipher` into `org.bouncycastle.crypto.modes`, already on line 40 of `core/.../module-info.java`) — no descriptor change needed. `module-info.java` exports packages, not classes.
- **New package** (a directory that doesn't yet exist under any `org.bouncycastle.*` tree) — add `exports org.bouncycastle.your.new.package;` to the corresponding module's `module-info.java`. The modules are `core`, `prov`, `util`, `pkix`, `tls`, `mail` / `jmail`, `pg` — pick the one whose `src/main/java` your new package physically lives under.

Symmetrically, if you delete or merge away an entire package, remove its `exports` entry. The compile-time signal that catches a missed entry — `module org.bouncycastle.lts.core does not export org.bouncycastle.crypto.foo` — only fires for modular downstream consumers, so a class-path-only test run won't surface it.

### Review native code for the bug classes Java tests can't catch

Most security-critical bugs in this codebase live in C, not Java: the JNI bridges in `interface/jni/`, the FFI bridges in `interface/ffi/`, and the OpenSSL abstraction layer in `interface/util/`. A Java roundtrip test cannot catch a memory-safety incident in native code, and a function that silently produces wrong-but-self-consistent output sails through any positive-only test on either side of the boundary. Every native change should be reviewed for the following classes specifically.

**Logic errors and inverted conditions**

OpenSSL's API convention is "1 = success, 0 = failure" and the project standardised on `if (1 != EVP_X_op(...))` for clarity. A bare `if (EVP_X_op(...))` (without the `1 !=`) accepts both success AND the rare-but-legal case where the function returns a different positive value, and `if (!EVP_X_op(...))` reads as "if not success" but evaluates to `if zero` — fine for OpenSSL's binary returns but wrong for any function that can return -1 (some `EVP_PKEY_CTX_*` functions do, signalling "operation not supported"). Off-by-one bugs hide between `>=` vs `>` on length checks (rejecting a valid length, or accepting one byte too many), `< 0` vs `<= 0` returning the wrong sign on a length parameter, and goto-fallthrough where an error path falls into the success path because the cleanup block doesn't `return`. OpenSSL has hard order-of-call requirements: `EVP_PKEY_CTX_set_rsa_oaep_md` requires `set_rsa_padding(OAEP)` first; `EVP_DigestSignInit_ex` must precede any `EVP_DigestSignUpdate`. A misordering passes silently — both calls return 1 — but produces wrong output that only a cross-implementation parity test will surface.

**Missing return statements and pointer-vs-value confusion in returns**

A C function that falls off its end without returning is undefined behaviour but compiles cleanly, especially when an early `goto exit` is added later and the writer forgets that the path past `exit:` no longer reaches the `return ret_code;` because of an intervening control flow change. Audit every function that returns a value to confirm every path either returns or unconditionally branches to a label that returns. Watch also for **address-vs-value mix-ups** — returning `&local_var` (pointer to a stack object that's destroyed at `return`) when the function is supposed to return the value, or returning `&p` (address of the local pointer) when the contract is "return the heap pointer `p`". Pointer-to-pointer parameters compound this: `int32_t *err` is an out-parameter the caller writes through (`*err = JO_FAIL`); writing `err = JO_FAIL` instead loses the assignment to a local, leaves the caller's `err` slot untouched, and the function is now silently returning success-but-with-an-error-code-that-disappears.

**Dangling pointers and free-after-use**

The `set0_*` family of OpenSSL functions takes ownership on success but **NOT on failure** — `EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, label, len)` returning 0 leaves the caller still owning `label`, which is why `rsa_oaep.c` frees `label_copy` on the failure branch. After freeing a pointer, set it to NULL or zero out the field that holds it: the lifecycle structs in `interface/util/*.c` (e.g. `rsa_ctx`, `rsa_oaep_ctx`) are reused across init / update / final / reset, and a stale `digest_ctx` pointer in `rsa_ctx` after a previous `EVP_MD_CTX_free` is exactly the kind of double-free that surfaces as a SIGSEGV inside `libcrypto`. Watch also for pointers escaping their scope — a local buffer's address copied into a struct that outlives the function. Pointers to JNI byte-array contents (from `GetByteArrayElements` or critical regions) MUST be released before the function returns; the `bytearrays.h` / `byte_array_critical.h` ctx helpers exist so `release_*_ctx` always pairs with `load_*_ctx`.

**Things not freed during error handling**

The `goto exit` pattern requires every owned resource to be visible at the cleanup label and to have a NULL-tolerant freer. **Declare every resource pointer at the top of the function and initialise to NULL before any branch that could goto** — if validation fails on line 5 and gotos to exit on line 6, the cleanup at line 50 must not deref an uninitialised pointer (which is undefined behaviour with potentially security-relevant consequences). The standard freers (`EVP_PKEY_free`, `EVP_PKEY_CTX_free`, `EVP_MD_CTX_free`, `BN_free`, `BN_clear_free`, `OSSL_PARAM_BLD_free`, `OSSL_PARAM_free`, `OPENSSL_free`, `OPENSSL_clear_free`) all accept NULL, so calling them unconditionally at the cleanup label is safe. The non-obvious case: `OSSL_PARAM_BLD_to_param(bld)` returns a NEW `OSSL_PARAM*` independent of `bld` — both must be freed. Secret material (private exponents, prime factors, key bytes) goes through `BN_clear_free` / `OPENSSL_clear_free` to zero memory before release. JNI string handles from `GetStringUTFChars` need `ReleaseStringUTFChars` on every exit path — the `rsa_init_strings_load` / `rsa_init_strings_release` helper in `rsa_ni_jni.c` is the canonical pattern for paired allocate-and-release across multiple JNI strings.

**Integer overflow / underflow and signed→unsigned casts**

Java `int` is signed; nearly every length / offset / count crossing the JNI boundary is a `jint`. A negative `jint` cast straight to `size_t` becomes ~2³¹ (or ~2⁶³ on 64-bit hosts), and is then large-but-positive — which passes any `len > 0` check, drives runaway allocations, or produces a `memcpy` that reads memory the caller never owned. **Always validate range checks before the cast**: `if (in_off < 0 || in_len < 0) return JO_INPUT_*_NEGATIVE;` precedes any `(size_t)` cast or pointer arithmetic. The FFI `check_in_range(size, off, len)` and JNI `check_bytearray_in_range(ctx, off, len)` helpers compute the addition safely even when both operands are near `SIZE_MAX/2`. `BN_num_bytes()` returns `int` but represents an unsigned magnitude — a negative return signals an OpenSSL internal error and must be checked, not blindly cast to `size_t`. Allocations of the form `n * sizeof(T)` need an upper bound on `n` to avoid wraparound; same for `len + 16` style allocations where `len` could be near `INT32_MAX`. On the way back to Java, casting a `size_t` back to `jint` requires an explicit `> INT32_MAX` check — see `JO_OUTPUT_TOO_LONG_INT32` and `JO_INPUT_TOO_LONG_INT32` in `bc_err_codes.h`. Per the "Native code conventions" point 6: use `INT32_MAX`, not `INT_MAX`, anywhere the intent is "fits in int32_t".

**String functions without bounds**

`strcpy`, `strcat`, `sprintf`, and `gets` are banned outright. `strlen` on untrusted input is fine when the buffer is statically sized or NUL-termination is guaranteed by a producer (e.g. `GetStringUTFChars`'s return), but never on a raw network-, file-, or test-derived buffer that might lack a terminator. `strncpy` does NOT NUL-terminate when the source length ≥ destination size — explicitly write the trailing NUL or use `snprintf` instead. The `strncmp` size argument trips reviewers regularly: `strncmp(name, "FOO", sizeof("FOO"))` is **strict equality** because `sizeof("FOO")` includes the NUL terminator (4 chars total), so the comparison only succeeds when `name` is also exactly "FOO" (its 4th byte matches the literal's `\0`). `strncmp(name, "FOO", strlen("FOO"))` is a **prefix match** (3 chars, no NUL) and would accept "FOOBAR". The codebase uses the `sizeof` form deliberately for equality (e.g. `mac.c` checking `mac_name == "CMAC"`); a switch from `sizeof` to `strlen` silently changes the semantics.

**Side-channel and constant-time on secret data**

This is a crypto library; "wrong but consistent" answers turn into compromise vectors when an attacker can time the call. `memcmp(tag, expected, len)` short-circuits on the first mismatched byte and leaks the matched-prefix length to a network attacker — never use it for tag verification, MAC comparison, or password-hash check. Use `CRYPTO_memcmp` (OpenSSL's constant-time equivalent) instead. Similarly, avoid branching on a secret bit (`if (priv_key & 1)`), avoid indexing arrays with a secret value (cache-line timing leak), and avoid loops whose iteration count depends on a secret. The `rsa_pkcs1.c` Bleichenbacher mitigation — relying on OpenSSL's default implicit-rejection so decrypt failures emit a deterministic-length pseudo-random plaintext rather than an error — is one example of why this matters: a stricter `EVP_PKEY_decrypt` failure path that emitted distinct error codes for "wrong PKCS#1 marker" vs "wrong padding" would be a textbook padding oracle.

**JNI exception state and local-reference lifetime**

The `bytearrays.h` / `byte_array_critical.h` ctx helpers and `rsa_init_strings_load`/`_release` already handle `GetByteArrayElements`/`GetStringUTFChars` correctly, but JNI has two more failure modes that come up if a bridge ever needs to construct Java objects or run anything that can throw:

- **Pending exceptions silently propagate.** After any `(*env)->NewByteArray`, `(*env)->FindClass`, `(*env)->NewObject`, or upcall, an exception may be pending on `JNIEnv*`. Subsequent JNI calls during the same native invocation produce undefined behaviour — many will crash, some return invalid handles that segfault later. After a JNI call that can throw, `(*env)->ExceptionCheck(env)` and either `return` (letting the exception surface to Java) or `(*env)->ExceptionClear(env)` if the C side recovers.
- **Local refs accumulate inside loops.** `(*env)->NewByteArray`, `GetObjectArrayElement`, and constructor calls all return local refs that live until the JNI function returns. A loop that allocates ~1000+ local refs without `(*env)->DeleteLocalRef(env, ref)` exhausts the local-ref slot table — the JVM aborts. Long-running JNI loops should `DeleteLocalRef` per iteration or call `EnsureLocalCapacity` up-front.
- **`JNIEnv*` is per-thread and non-portable.** A pointer obtained on thread A is invalid on thread B. The current bridges don't pass `JNIEnv*` across threads, but a future native-callback path would need `(*jvm)->GetEnv(jvm, ...)` from each consumer thread.

**OpenSSL ERR-queue conventions**

OpenSSL maintains a thread-local error queue that operations push onto. Mismanagement leaks errors from one call into another's results.

- **`ERR_clear_error()` before any operation whose error you care about.** Otherwise a stale entry from a prior call surfaces as "the current error" in `OpenSSL.getOpenSSLErrors()`. Most `interface/util/*.c` functions clear the queue at the top of their main work block.
- **Mark/pop pairs balance.** `rsa.c::rsa_ctx_verify` uses `ERR_set_mark` + `ERR_pop_to_mark` (success or expected verify-fail) / `ERR_clear_last_mark` (genuine error) to scrub "signature didn't verify" noise without dropping real errors. Every `ERR_set_mark` must terminate via exactly one of those two functions on every code path including `goto exit`. A leaked mark is a permanent queue entry.
- **`pop_to_mark` honours nesting in order.** Nested marks pop their own scope; using `pop_to_mark` after the outer mark when the intent was the inner one silently keeps recent errors that should have been discarded.

**`OPS_*` macro hygiene (project-specific)**

The `OPS_FAILED_ACCESS_N`, `OPS_OPENSSL_ERROR_N`, `OPS_INT32_OVERFLOW_N`, `OPS_LEN_CHANGE_N`, etc. (defined in `interface/util/ops.h`) expand to either nothing (release build) or `is_ops_set(N) ||` (OPS build); the matching `OPS_OFFSET_*` macros expand to either nothing or `+ -<N>`. The idiosyncratic shape makes a few mistakes silent:

- **`OPS_*` must appear inside an `if` condition's expression, with whitespace between it and the next token.** `if (OPS_X expr)` is correct. `OPS_X if (expr)` and `OPS_X stmt;` either don't compile in OPS builds or silently no-op in release builds.
- **Pair the flag and the offset.** `if (OPS_OPENSSL_ERROR_2 cond) { ret = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_1(1000); }` mixes flag `_2` with offset `_1` — tests targeting the `_2` site receive a different code than they expect.
- **Numeric offsets are part of the test contract.** `RSAOpsTest`, `RSAOAEPCipherOpsTest`, etc. assert exact return codes (`-1003`, `-2102`, `-2105`). Renumbering an offset in C without the test update is silent — the test sees a different (legitimate-looking) negative number and fails opaquely.
- **Each new fault-injection point needs a unique offset within its file's range.** `rsa.c` uses the 1000-block; `rsa_oaep.c` the 2000-block; `rsa_pkcs1.c` the 2100-block. Reusing an offset within a file collides on which call site failed; reusing across files is fine.

**Symbol-name collisions with libcrypto exports**

FFI exports are resolved by the dynamic loader against the union of `libinterface_ffi.dylib` and any other library already loaded in-process — including `libcrypto.dylib`. A C function named `RSA_sign` shadows libcrypto's own export of that name; depending on RTLD order, a call into "our" `RSA_sign` resolves to libcrypto's, producing impossible-looking SIGSEGVs inside libcrypto from what should be Jostle code. This was caught the hard way during initial RSA work — the fix was the `JoRSA_*` / `JoRSAOAEP_*` / `JoRSAPKCS1_*` prefix.

Use a `Jo*_` prefix on every FFI export. Verify before commit with `nm jostle/src/main/resources/native/<os>/<arch>/libinterface_ffi.dylib | grep ' T '` (Linux/macOS) and grep for any name that also appears in `nm "$OPENSSL_PREFIX/lib/libcrypto.3.dylib" | grep ' T '`. JNI exports use the JVM-mandated `Java_<class>_<method>` naming, so collision is a non-issue there.

**Thread-local entropy state and re-entrance**

`rand_set_java_srand_call(rnd_src)` writes a thread-local that the next OpenSSL operation consuming entropy reads. Two implications:

- **Within one native call, two operations that both set the thread-local race.** A future native function that calls into OpenSSL twice with different `rnd_src` values has the second `rand_set_java_srand_call` overwrite the first; the first OpenSSL call sees the second source. Currently no Jostle function does this; a refactor that consolidates two operations into one entry point needs to keep the order in mind.
- **The thread-local persists across calls on the same thread.** A thread that finished an RSA operation still has its `rand_src` pointer set when a later operation runs on it. The pointer references a Java `RandSource` whose lifetime is the duration of the original native call — reading it after the original call returned is use-after-free. Currently safe because every entropy-consuming OpenSSL call is preceded by a fresh `rand_set_java_srand_call`. Adding a code path that calls into OpenSSL without that prefix re-uses stale (possibly freed) state.

**Zeroize secrets with `OPENSSL_cleanse`, not `memset`**

The compiler is allowed to elide `memset(buf, 0, len)` if `buf` is freed (or its scope ends) immediately afterward — dead-store elimination. `OPENSSL_cleanse` (and the `BN_clear_free` / `OPENSSL_clear_free` allocators that wrap it) are written to be opaque to that optimization. For secret material — private exponents, prime factors, AES keys, post-decrypt plaintext, anything derived from a key — never use `memset` to zero before free.

**`memcpy` vs `memmove` for overlapping ranges**

`memcpy(dst, src, n)` with overlapping `dst`/`src` ranges is undefined behaviour even if the size is small and any sane implementation would happen to work. Two cases come up in this codebase:

- **Shifting a buffer onto itself.** `memcpy(buf, buf + offset, n)` when `offset < n` is the canonical violation. The GCM tag-buffer slide in `block_cipher_ctx.c` already uses `memmove` for this; copy that pattern for any new buffering code.
- **Aliased input/output via JNI.** A caller that passes the same byte array as both input and output to a native function exposes it twice through `GetByteArrayElements`; `memcpy(out, in, n)` is undefined when the underlying ranges coincide. The `java_bytearray_ctx` / `critical_bytearray_ctx` helpers handle one direction at a time, so this is structural rather than an active risk — but worth flagging if a future bridge starts doing in-place transforms.

### Review Java SPI and provider plumbing for the bug classes positive-only tests can't catch

The JCE SPI surface is a contract-heavy state machine: subtle exception-type expectations, transition rules, parameter-handling defaults, and provider-fallback semantics that a positive-only roundtrip test never surfaces. Most of these bugs become visible only under specific use patterns — wrong exception type breaking provider fallback, mis-registered cipher transformations silently downgrading the digest, GC reclaiming a key handle mid-call, or a multi-release ABI drift only visible to downstream callers compiled against the older view. When reviewing Java in `jostle/src/main/java/`, `jostle/src/main/java<N>/`, and `jostle/src/test/java/`, look for these classes specifically.

**JCE transformation lookup: form-1 alias vs form-4 fallback**

`Cipher.getInstance("X/Y/Z")` runs through `javax.crypto.Cipher.Transform.getTransforms()`, which tries four lookup forms in order: (1) the exact transformation `"X/Y/Z"` — `engineSetMode`/`engineSetPadding` are NOT called; (2) `"X/Y"` with explicit padding to apply; (3) `"X//Z"` with explicit mode to apply; (4) bare `"X"` with both mode and padding to apply. The first matching service wins. Registering a transformation alias of the bare algorithm — `provider.addAlias("Cipher", "RSA", "RSA/ECB/OAEPWithSHA-512AndMGF1Padding")` — makes form 1 succeed, **bypassing the SPI's `engineSetPadding` entirely**. The SPI silently uses its default values regardless of what the alias claimed. Real bug we hit: every `OAEPWith<digest>AndMGF1Padding` alias collapsed to the SPI's `DEFAULT_DIGEST = "SHA-256"`, caught only when a multi-trial agreement test surfaced an input-length mismatch at the SHA-512 boundary.

Don't register transformation aliases on a primary cipher whose SPI uses `engineSetPadding` to configure itself. Either register each transformation as its own primary (separate SPI per name, the `RSA/ECB/PKCS1Padding` model), or register only the bare algorithm and let JCE fall through to form 4 where `setMode`/`setPadding` actually run.

**Throw the right JCE exception type — provider-chain fallback depends on it**

JCE has strict exception-type contracts that determine both caller-visible behaviour and **whether the JCE moves on to the next registered provider**:

- `init` throwing `InvalidKeyException` or `InvalidAlgorithmParameterException` → JCE retries with the next provider in `Provider[]` order. This is the primary fallback mechanism for "wrong key type for this provider".
- `init` throwing `ProviderException` (a `RuntimeException`) → propagates, no fallback. A native bridge crash that surfaces as `ProviderException` leaves the caller stuck with this provider.
- `engineDoFinal` throws `BadPaddingException` for decrypt-padding failures, `IllegalBlockSizeException` for size mismatches, `ShortBufferException` for the in-place variant when output is too small. A generic `RuntimeException` from `doFinal` breaks `assertThrows` patterns and shoves errors into application-level handlers that expect typed JCE exceptions.
- `engineUnwrap` should surface `InvalidKeyException` on **all** unwrap failures — never `BadPaddingException` (Bleichenbacher channel). `RSAOAEPCipherSpi` and `RSAPKCS1CipherSpi` already collapse `BadPaddingException` into `InvalidKeyException` at the unwrap boundary; new wrap/unwrap SPIs must follow.

A bug where the wrong exception type leaks (e.g. `OpenSSLException extends RuntimeException` thrown from a place that should surface `BadPaddingException`) breaks both fallback and tests, and is invisible to a positive-only roundtrip.

**Native references must outlive every JNI/FFI call**

Every Java SPI that holds a native pointer through a `NativeReference` / `Disposer` must keep the holding object reachable across every native call. A GC pause between "read the native handle into a local long" and "make the JNI/FFI call" can otherwise reclaim the holder, run the disposer (freeing the native ctx), and leave the call dereferencing freed memory. The bug is non-deterministic and only appears under load.

Two patterns the codebase uses:

- Java 8 (`src/main/java/`): `synchronized(this) { native call }` — the synchronisation keeps `this` reachable for the lock's duration.
- Java 9+ (`src/main/java9/` and later): `try { native call } finally { Reference.reachabilityFence(this); }` — explicit fence, the modern preference.

Every multi-release `javaN/` override of an SPI re-implements this pairing. The same applies to helpers like `RSAComponents.getRequired`/`getOptional` which hold `PKEYKeySpec spec` across two NI calls — `synchronized(spec)` (Java 8) and `Reference.reachabilityFence(spec)` (Java 9+) both appear in the codebase. New SPIs must follow one or the other; a raw native call without either is a latent bug even if testing happens to pass.

**Multi-release source-set API stability — public surface MUST be identical**

When the same class lives in multiple `src/main/javaN/` directories, the **public/protected API surface must be identical** across all versions. The multi-release jar loads the JDK-version-appropriate copy at runtime, but downstream code is *compiled* against the Java 8 ABI (the lowest baseline). Implications:

- A new public method added to `java25/MyClass` but not to `java/MyClass` is invisible to callers compiled against the jar — they get the Java 8 ABI which doesn't see the method, even on JDK 25.
- A public method removed from `java25/MyClass` but kept in `java/MyClass` triggers `IllegalAccessError` on JDK 25 when the older API contract is invoked from the multi-release jar.
- Internal (`private` / package-private) methods may differ freely between versions.
- A `javaN/` copy can use Java-N-specific APIs internally, but the parameter and return types of public methods must remain Java-8-expressible.

The existing `## Multi-release source layout (critical)` warns about applying changes to every override copy but doesn't articulate the ABI-stability rule. Drift surfaces only when downstream code is compiled against the older view and run on the newer JDK — which most local test runs don't exercise. The `DefaultRandSourceParityTest` is a precedent for source-level parity guards; consider similar tests for any class with substantial cross-version overrides.

Adding a method to a project-internal interface (`RandSource`, `MDServiceNI`, `SecureRandomProvider`, etc.) requires updating EVERY implementation — production classes, multi-release overrides (`src/main/javaN/`), AND test fakes. Test fakes are the easiest to miss because they often live as static inner classes inside larger test files (`TestUtil.TestRandSource`, the `*RandSource` family in `BridgeRandLimitTest`). The compile error is "X is not abstract and does not override abstract method Y" — search the test tree by interface name before declaring an interface change done. Prefer `default` methods on the interface when the new behaviour has a sensible no-op fallback (the test fakes inherit the default and you don't need to touch them); use abstract methods only when every implementation must make a deliberate choice. Also remember the FFI-aware Java 25 override of the interface itself (e.g. `src/main/java25/.../RandSource.java`) — when the base interface declares a new abstract method, the Java 25 override must declare it too, or the multi-release jar serves up a Java 25 view missing the method.

**SPI state-machine guards — `requireInitialised()` pattern**

JCE SPIs are state machines with strict transition contracts:

- `Cipher`: created → init → update* → doFinal → ready-for-re-init.
- `Signature`: created → initSign/initVerify → update* → sign/verify → ready-for-re-init.
- `Mac`: created → init → update* → doFinal (auto-resets to ready-for-update).
- `setParameter` must precede `init` for parameter-driven SPIs (PSS, OAEP); forbidden mid-`update`.

Calling `update` before `init`, or `setParameter` after `update` started, is illegal — the SPI must throw `IllegalStateException` with a clear message. NPE from a null native handle is the wrong failure mode; callers expect typed exceptions for invalid-state transitions.

`RSAOAEPCipherSpi.requireInitialised()` is the canonical pattern. Every entry point that depends on prior state needs an explicit guard, including the four-argument `engineUpdate(byte[], int, int, byte[], int)` and `engineDoFinal(byte[], int, int, byte[], int)` overloads which are easy to miss when adding the basic two-argument variants. The native-side init-failure-leaks-state bug fixed in `rsa_ctx_init_sign` was the same problem one layer down — partial state slipping past a state-check.

**`engineSetParameter` contract: null resets, wrong type rejects**

JCE convention for `engineSetParameter(AlgorithmParameterSpec)`:

- `null` resets the SPI to its defaults — must NOT throw.
- A well-typed but unsupported spec → `InvalidAlgorithmParameterException` with a specific message ("only MGF1 supported", "trailer field must be 1", etc.).
- An unrelated type (e.g. `IvParameterSpec` passed to PSS) → `InvalidAlgorithmParameterException` with "expected XParameterSpec, got Y" — NOT `ClassCastException` or a generic `IllegalArgumentException`.
- Calling after `update` has started → `ProviderException("cannot call setParameter in the middle of update")` — see `EdSignatureSpi` for the precedent.

`RSAPSSSignatureSpi` and `RSAOAEPCipherSpi` follow the null-resets / non-null-validates pattern. New SPIs that accept `AlgorithmParameterSpec` must explicitly handle the null case before any `instanceof` chain — otherwise `null instanceof X` evaluates false and the SPI rejects null with the wrong message.

**Modern defaults policy and cross-provider parity**

The project deliberately deviates from JCE historical defaults: PSS defaults to SHA-256/MGF1-SHA-256 not SHA-1; OAEP same; new parameter-driven SPIs follow this convention. Implications worth codifying:

- A caller running `Signature.getInstance("RSASSA-PSS").initSign(...).update(m).sign()` against Jostle gets a **different signature** than the same call against SunJCE or BC. This is intentional, but the deviation matters for downstream interop.
- Cross-provider agreement tests must pass explicit `PSSParameterSpec` / `OAEPParameterSpec` objects — they can't rely on default-vs-default parity because the defaults differ.
- New SPI defaults belong in a per-SPI `private static final String DEFAULT_DIGEST = "SHA-256"` constant, with the deviation documented in the class header (see `RSAPSSSignatureSpi`'s class-level Javadoc for the canonical pattern).

**`SecureRandom` acquisition is expensive — cache, don't allocate per call**

`new SecureRandom()` blocks on system entropy seeding (at first call per JVM, sometimes longer on Linux without `/dev/urandom` warmup) and the JCE retries through providers on every constructor call if instantiation fails. Per-operation `new SecureRandom()` adds up:

- Use `CryptoServicesRegistrar.getSecureRandom()` — the existing project helper that delegates to a cached instance.
- The `RandSource` SPI parameter pattern wraps this for native callers; pure-Java code that doesn't go through the native bridge needs the same caching discipline.
- Test code: cache one `SecureRandom` per test class (the established `private static final SecureRandom RANDOM = new SecureRandom();` pattern), not per `@Test` method.
- For tests that loop over random inputs, the `seededRandom(testName)` helper (in `RSATest`, `RSAOAEPCipherTest`, `RSAPKCS1CipherTest`) seeds a `SHA1PRNG` from a logged value so a flaky run can be replayed — use that pattern when reproducibility matters.

**Provider registration: static-init order and resilient `configure()`**

`JostleProvider.setup()` calls each `Prov<NAME>.configure(this)` in sequence in a static initializer chain. A `configure()` that throws (e.g. an algorithm whose native dependency is missing) takes the whole provider down with `ExceptionInInitializerError` rather than the targeted exception type — and once a class fails its initializer, the JVM never retries it for the lifetime of the process. Defensive measure: each `Prov<NAME>.configure` should fail soft when an individual algorithm can't be registered (log it, continue to the next algorithm) rather than letting one missing native symbol break every algorithm in the provider.

**Auto-unboxing NPE on collection / map access**

Map lookups against JCE provider attributes return `null` when the attribute is absent. Auto-unboxing the result silently NPEs:

```java
Integer keyLen = (Integer) provider.getService("Cipher", alg).getAttribute("KeyLen");
int n = keyLen;  // NPE if KeyLen attribute not registered
```

The same trap holds for `Map<String, Integer> tagLengthsByMode = ...; int tagLen = tagLengthsByMode.get(mode);` when `mode` is absent. Use `Optional`, `getOrDefault(key, fallback)`, or explicit null checks at every map-access boundary that crosses the JCE attribute system or any Map-keyed-by-algorithm-name lookup.

**`equals` / `hashCode` consistency for key types**

Key classes returned to JCE callers (`JORSAPublicKey`, `JORSAPrivateKey`, `JOEdPublicKey`, etc.) can end up as HashMap keys at the application layer. The current implementations inherit `Object`'s identity-based `equals` / `hashCode`, which is the safe default for opaque native-handle wrappers but is at odds with the spec'd contract some callers assume for `java.security.Key` types. The JCA spec doesn't *require* value equality on `Key`, but downstream code using `Map<PublicKey, ...>` or set-based deduplication may depend on it.

This is a deliberate decision per key class: either implement value equality (computing equality from the underlying components — modulus + public exponent for an RSA public key, for example), or document the identity-only behaviour in the class Javadoc so a caller using `equals` knows what to expect. Whatever the choice, it must be consistent: `equals` and `hashCode` always agree, and both behave the same way across the public/private halves of the same key type.

**Validate resource-consumption parameters at the JCE boundary**

Key sizes, iteration counts, salt lengths, modulus bits — anything that drives native-side allocation or computation — should be bounds-checked at the JCE entry point (`KeyPairGenerator.initialize`, `SecretKeyFactory.engineGenerateSecret`, `engineSetParameter` for parameter-driven SPIs, etc.) rather than letting OpenSSL surface a generic `OpenSSLException` from deep in the stack. Two reasons. (1) **Typed exception with a useful message.** A caller passing `keysize = 768` should get `InvalidParameterException("RSA key size 768 is out of range [1024, 16384]")`, not a generic `OpenSSLException` that points at `crypto/rsa/rsa_lib.c`. (2) **DoS protection.** RSA keygen is O(bits³); a caller passing `keysize = 1_000_000` won't OOM in practice but consumes substantial CPU before OpenSSL rejects it. A request-time bound at the JCE boundary fails fast.

Use the right exception type for each surface — JCE specifies different types for the two `KeyPairGenerator.initialize` overloads, and the contract for some other SPI methods is similarly precise:

1. `KeyPairGenerator.initialize(int keysize)` → `InvalidParameterException` (a `RuntimeException`).
2. `KeyPairGenerator.initialize(AlgorithmParameterSpec)` → `InvalidAlgorithmParameterException` (a checked exception).
3. `Cipher.engineInit(...)` for unsupported parameters → `InvalidAlgorithmParameterException`.
4. `Signature.engineSetParameter(AlgorithmParameterSpec)` for invalid spec → `InvalidAlgorithmParameterException` with a message that names the parameter (e.g. "trailer field must be 1", "public exponent must be odd").

`RSAKeyPairGenerator` is the canonical reference: `MIN_KEY_SIZE_BITS = 1024` (security floor — RSA below 1024 is broken cryptographically), `MAX_KEY_SIZE_BITS = 16384` (DoS protection), odd-public-exponent check (even `e` shares a factor of 2 with `phi(n)` and produces a structurally broken key). The numeric bounds are project-wide policy, not per-instance — pick conservative values and codify them as `private static final` constants with a Javadoc comment naming the rationale.

A shared private helper (e.g. `validateKeySize(int)` returning a non-null error message or null) keeps the wrap-in-correct-exception logic at the call site, avoiding the trap of a single helper that throws a checked exception that the `int`-only surface can't propagate.
