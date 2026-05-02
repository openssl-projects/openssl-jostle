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

1. **Bridge layer (`interface/jni/`, `interface/ffi/`)** validates input (null checks, range checks, byte-array access) and translates between Java and C calling conventions. JNI **must** request critical pointers via JVM and surface failures explicitly; FFI **must** receive the full byte-array size as a parameter so it can do its own range checks. Both layers must return identical error codes for identical inputs.
2. **Abstraction layer (`interface/util/`)** is the only place that calls OpenSSL. It maintains state in structs across the JCA new → init → update → final → reset lifecycle.
3. Functions returning a pointer take `int32_t *err` as the last parameter; everything else returns a status code (`bc_err_codes.h`). Negative codes are errors, non-negative are byte counts / success.
4. Use `get_global_jostle_ossl_lib_ctx()` when calling `EVP_*_fetch` / `EVP_*_new_from_name`. Never call OpenSSL with a `NULL` lib ctx — operations need the lib ctx that hosts the Java RAND bridge.
5. `jo_assert` is for catastrophic conditions only (allocation failure, internal invariant). **Never use it for user-supplied input** — user errors must surface as error codes the bridge layer translates to JCE exceptions.
6. Operations-test macros (`OPS_FAILED_ACCESS_1`, `OPS_OPENSSL_ERROR_3`, `OPS_FAILED_INIT_2`, etc.) defined in `interface/util/ops.h` are placed inside conditionals so tests can fault-inject failure paths. They expand to `is_ops_set(N) ||` in OPS builds and to nothing otherwise; the `OPS_OFFSET_*` macros let tests differentiate between multiple call sites that produce the same error code.

## SecureRandom flow

Every native call that consumes entropy must accept a `RandSource` parameter. On the native side, the bridge layer null-checks and calls `rand_set_java_srand_call(rnd_src)` (sets a thread-local). The Java RAND bridge inside the OpenSSL provider then up-calls into Java for entropy.

`rnd_src` is **not** valid across calls — it's only live for the duration of the function it was passed into. Cache the Java reference on the SPI side, not in C state.

Direct buffer access (JNI critical regions) cannot make up-calls — fetch random data before entering critical sections, or after leaving them.

## Style and submission

1. Checkstyle config: `config/checkstyle/checkstyle.xml`. PRs must pass.
2. Match existing code style — Java looks Java, C looks C. Look at `MDServiceSPI`/`MDServiceNI`/`md.c` as the canonical reference for newer transformations; some older code follows an earlier pattern where error handling lived in the SPI rather than in `*NI` default methods.
3. SPI sub-packages under `org.openssl.jostle.jcajce.provider` are usually named after the transformation (`mldsa`, `kdf`); `Prov<NAME>` classes register them with the provider.
4. AUTHORS.md, LICENSE, CONTRIBUTING.md exist — read CONTRIBUTING.md before significant changes; it is the source of truth for code organization, testing expectations, and the JNI-FFI split.

## Useful debug entrypoints

`org.openssl.jostle.util.DumpInfo` (run via the standard `java --module-path .../openssl-jostle-1.0-SNAPSHOT.jar --module org.openssl.jostle.prov/org.openssl.jostle.util.DumpInfo`) prints the loaded provider, OS/arch, JVM version, the resolved interface (JNI/FFI), and which native libs were extracted. Use it to confirm a build picked up the right native libraries.
