# Verification checklist

Walk through this list after completing the implementation but BEFORE asking the user to commit. The items here catch the layers most commonly forgotten.

## Native layer

### `interface/util/<algo>.c` + `.h`

1. [ ] Every entry point uses `jo_assert` on bridge-validated inputs (pointers, curve names, lengths). NO `if (X) return JO_*` on inputs that the bridge already validated.
2. [ ] State checks on outer-pointer fields (`spec->key == NULL`) and OpenSSL-output bounds (`sig_len > INT32_MAX`) ARE permitted as `if/return` — these are the only legitimate util-layer error returns.
3. [ ] `ERR_clear_error()` at the top of each operation.
4. [ ] `1 != X` form on every fallible OpenSSL call (not `if (!X)` or bare `if (X)`).
5. [ ] Every resource (`EVP_PKEY *`, `EVP_PKEY_CTX *`, `EVP_MD_CTX *`, `BIGNUM *`, `OSSL_PARAM_BLD *`, `OSSL_PARAM *`) declared at top, initialised to NULL, freed at `goto exit:` with the NULL-tolerant freer.
6. [ ] `BN_clear_free` / `OPENSSL_clear_free` for secret material — never `BN_free` / `OPENSSL_free`.
7. [ ] No `memset` on secrets — use `OPENSSL_cleanse` (the project also auto-cleanses via the clear-free allocators).
8. [ ] No `strcpy`, `strcat`, `sprintf`, `gets`. `strncpy` only with explicit NUL-termination. `strncmp(s, "FOO", sizeof("FOO"))` is strict equality (includes NUL); `strncmp(s, "FOO", strlen("FOO"))` is prefix. Both are fine if used intentionally.
9. [ ] Every fallible OpenSSL call wrapped with `OPS_OPENSSL_ERROR_N <cond>` AND matched return wrapped with `OPS_OFFSET_OPENSSL_ERROR_N(<offset>)`. Flag number and offset number AGREE per site.
10. [ ] Offset block is unique within the file. Cross-file offset reuse is permitted (CLAUDE.md) but worth a comment in each affected file.
11. [ ] `INT32_MAX` (not `INT_MAX`) for "fits in int32_t" bounds — pairs with `JO_*_INT32` error codes and the `int32_t` parameter / return types.

### `interface/jni/<algo>_ni_jni.c`

1. [ ] Every byte-array parameter goes through `load_bytearray_ctx` / `release_bytearray_ctx`, paired symmetrically across all exit paths.
2. [ ] Every `GetStringUTFChars` paired with `ReleaseStringUTFChars` on every exit path.
3. [ ] Length parameters: `< 0` → `JO_*_IS_NEGATIVE`; zero-where-meaningless → typed error; `> INT32_MAX` → `JO_*_TOO_LONG_INT32`.
4. [ ] Offset+length pairs use `check_bytearray_in_range(&ctx, off, len)` BEFORE any pointer arithmetic.
5. [ ] `OPS_FAILED_ACCESS_N` macros wrap each `load_bytearray_ctx` so tests can fault-inject access failures.
6. [ ] Every error code is typed (`JO_*_NULL`, `JO_*_FAILED_ACCESS`, etc.) — never a generic `JO_FAIL` for bridge-side rejections.

### `interface/ffi/<algo>_ni_ffi.c`

1. [ ] Identical error codes for identical inputs vs. the JNI bridge. Verify by reading both side-by-side.
2. [ ] Exported function names start with `Jo<MOD>_` prefix. Verify with `nm libinterface_ffi.dylib | grep " T " | grep <prefix>`.
3. [ ] No collision with libcrypto exports: `comm -12 <(nm libinterface_ffi.dylib | grep " T " | awk '{print $3}' | sed 's/^_//' | sort -u) <(nm $OPENSSL_PREFIX/lib/libcrypto.3.dylib | grep " T " | awk '{print $3}' | sed 's/^_//' | sort -u)` should produce zero matches.
4. [ ] `check_in_range(size, off, len)` for offset+length pairs (FFI receives the buffer SIZE directly, not via a ctx wrapper).

### `interface/CMakeLists.txt`

1. [ ] New `.h`/`.c` files added to **every** target list. There are typically 6 sections (JNI debug, JNI release, FFI debug, FFI release, etc.). Use `replace_all` on the sibling-file pattern.
2. [ ] Rebuild with `./gradlew :jostle:compileJava` (generates JNI headers) followed by `./interface/build.sh` — header generation must precede native build.

## Java layer

### NI interface + JNI + FFI impls

1. [ ] `XServiceNI` interface extends `DefaultServiceNI`.
2. [ ] `handleErrorCodes(int code)` default method covers every new typed error code with a typed exception + specific message.
3. [ ] `XServiceJNI` declares each method `native`.
4. [ ] `XServiceFFI` (in `src/main/java25/`) declares the FFI method handles with `Linker.Option.critical(true)` where safe.
5. [ ] FFI `lookup.find("Jo<MOD>_*")` matches the renamed FFI exports.
6. [ ] `NISelector` has a static field for the new service.

### Spec class

1. [ ] Implements `java.security.spec.KeySpec`.
2. [ ] Constructor rejects null / empty / non-positive / out-of-range with `IllegalArgumentException` + a specific message string.
3. [ ] Defensive cloning on byte-array fields — `org.openssl.jostle.util.Arrays.clone(...)` (NOT `.clone()` directly).
4. [ ] Digest names normalised via `DigestUtil.getCanonicalDigestName(...)`.

### SPI class

1. [ ] Extends the right JCE SPI abstract class.
2. [ ] State-machine guards on every entry: `requireInitialised()` + clear error-type contract per state.
3. [ ] Exception types match the JCE contract (CLAUDE.md "Throw the right JCE exception type"). Wrong types break provider-chain fallback.
4. [ ] All `if/else` bodies braced (no `if (foo) return bar;` form).
5. [ ] Native-handle keep-alive: `synchronized(this)` on Java 8 baseline OR `Reference.reachabilityFence(this)` in `try { } finally { }` on Java 9+ (multi-release override).
6. [ ] If using post-Java-8 APIs (`NamedParameterSpec`, `KEMGenerateSpec`, etc.), gate via reflection or provide a multi-release override copy. Multi-release ABI must be IDENTICAL public surface across all `javaN/` copies.
7. [ ] `engineSetParameter(null)` resets to defaults (CLAUDE.md "engineSetParameter contract: null resets, wrong type rejects"). Mid-update `setParameter` is `ProviderException`.

### Multi-release sync

1. [ ] If the SPI has a `java9/` or `java25/` override, every behaviour change in the main copy is mirrored. Public method signatures (return type, params, throws clause) are byte-identical.
2. [ ] No new public method appears only in a `javaN/` copy without also being in the baseline `java/`.

### `Prov<NAME>` + `JostleProvider.setup()`

1. [ ] `Prov<NAME>.configure(JostleProvider)` registers every algorithm name AND every OID alias.
2. [ ] Wired into `JostleProvider.setup()` (constructor) — `new Prov<NAME>().configure(this);`. **This is the single most-forgotten line.**
3. [ ] No case-insensitive collisions in registration (`provider.addAlgorithmImplementation("Type", "XwithY", ...)` plus `"XWITHY"` will conflict).
4. [ ] `SupportedKeyClasses` and `SupportedKeyFormats` attributes set on each transformation.

### Error codes & key types

1. [ ] New `JO_*` macros in `interface/util/bc_err_codes.h` if you added typed bridge errors.
2. [ ] Matching `ErrorCode.java` enum entries with the right negative integer.
3. [ ] Matching cases in the relevant NI's `handleErrorCodes` default method, with typed exceptions and specific messages.
4. [ ] If adding a new key type: matching `KS_*` macro in `key_spec.h` + `OSSLKeyType` enum entry with name + OID aliases.

## Tests

### Coverage matrix

1. [ ] **Positive roundtrip** — produce → consume on the same instance, then on independent instances.
2. [ ] **BC agreement (both directions)** — Jostle produces / BC consumes AND BC produces / Jostle consumes. Multiple random trials per test (typically 5–25).
3. [ ] **Tampered input rejection** — at least one negative-path test with a specific exception-message assertion.
4. [ ] **Boundary tests** — for fixed-length inputs (key size, IV, nonce, output length), probe `min - 1`, `min`, `max`, `max + 1`.
5. [ ] **`*LimitTest`** — NI-level tests for every input-validation site in the bridge. Range-check probes use exactly `boundary + 1` values, not arbitrary large numbers.
6. [ ] **`*OpsTest`** — one test per OPS-instrumented site. Bridge-side `OPS_FAILED_ACCESS_*` tests are JNI-only (guard with `Assumptions.assumeFalse(Loader.isFFI())`).
7. [ ] **Reset/reuse** — two operations on one SPI instance; negative-then-positive sequence; positive-then-negative; role-flip (Signature only).
8. [ ] **Offset-write contract** — for any `engineGenerateSecret(byte[], int)` / `Cipher.doFinal(out, off)` etc., use the 4-step pattern (random fill, prefix snapshot, functional comparison, shifted-window negative).
9. [ ] **Exception messages asserted** — every `catch (X expected)` block validates the message via `assertEquals` (fixed messages) or `startsWith` / `contains` (variable messages).

### Style

1. [ ] `org.openssl.jostle.util.Arrays.areEqual(...)` (not `java.util.Arrays.equals(...)`).
2. [ ] `org.openssl.jostle.util.Arrays.clone(...)` (not `byteArray.clone()`).
3. [ ] All `if`/`else` bodies braced — no single-line `if (foo) return bar;` form.

## Pre-commit

1. [ ] `./gradlew :jostle:unitTest25JNI :jostle:unitTest25FFI :jostle:integrationTest25JNI :jostle:integrationTest25FFI` — all green on both bridges.
2. [ ] If new OPS sites were added: rebuild with `JOSTLE_OPS_TEST=1 ./interface/build.sh`, then re-run the integration test tasks to confirm the new OPS tests pass.
3. [ ] Build artefacts (`interface/CMakeFiles/`, `interface/Makefile`, `libinterface_*.dylib`, `jostle/src/main/resources/`) are NOT staged.
4. [ ] Source + test files ARE staged.
