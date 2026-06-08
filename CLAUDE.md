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


## Detailed guides

The detailed conventions are split into topical guides and auto-imported below.
Claude Code resolves `@`-imports recursively, so the full ruleset is loaded into
context exactly as before — these files just keep CLAUDE.md navigable.

@.claude/guides/native-code.md
@.claude/guides/testing.md
@.claude/guides/java-spi.md
