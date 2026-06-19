# Java SPI & provider review

The JPMS packaging rule and the JCE SPI / provider-plumbing review checklist.
Auto-imported by CLAUDE.md.

### Update `module-info.java` when you add a package

Each module has a JPMS descriptor at `<module>/src/main/jdk1.9/module-info.java` (e.g. `core/src/main/jdk1.9/module-info.java`) listing every exported package. The Java 8 sources under `<module>/src/main/java` and the descriptor are bundled into the same multi-release jar; the descriptor is the source of truth for what's visible when downstream code runs on JDK 9+ with `--module-path`. A package that exists in the source tree but isn't listed in `module-info.java` is invisible to modular consumers — class-path consumers still see it, which is why the omission is easy to miss locally.

When you add a class, ask which case applies:

- **Existing package** (e.g. dropping `ECBModeCipher` into `org.bouncycastle.crypto.modes`, already on line 40 of `core/.../module-info.java`) — no descriptor change needed. `module-info.java` exports packages, not classes.
- **New package** (a directory that doesn't yet exist under any `org.bouncycastle.*` tree) — add `exports org.bouncycastle.your.new.package;` to the corresponding module's `module-info.java`. The modules are `core`, `prov`, `util`, `pkix`, `tls`, `mail` / `jmail`, `pg` — pick the one whose `src/main/java` your new package physically lives under.

Symmetrically, if you delete or merge away an entire package, remove its `exports` entry. The compile-time signal that catches a missed entry — `module org.bouncycastle.lts.core does not export org.bouncycastle.crypto.foo` — only fires for modular downstream consumers, so a class-path-only test run won't surface it.


### OpenSSL is the single source of truth for fixed values — query and cache, never transcribe

Jostle delegates its cryptography to OpenSSL, so OpenSSL — not Jostle — owns every fixed numeric fact about an algorithm: digest output size and block size, XOF default length, cipher block size and IV/nonce length, valid key lengths, signature length, KEM encapsulation / ciphertext / shared-secret length, MAC length, DRBG security strength and maximum request size, EC field sizes, and so on. **Do NOT re-implement any of these as a hardcoded lookup table, `switch`/`case`, `if`-ladder, enum field, or `static final` constant — especially on the Java side.** A transcribed value is a second source of truth that drifts silently: OpenSSL changes a default between releases, a custom provider overrides it, a variant's real bound differs from the number someone typed, and the divergence is invisible to every positive test because both the table and the native layer are internally self-consistent — they just disagree, and the table is wrong.

The rule, in order of preference:

1. **Ask OpenSSL at the point of use.** If the value is cheap to fetch and not on a hot path, query the native layer each time (`EVP_MD_get_size`, `EVP_CIPHER_get_block_size`, `OSSL_RAND_PARAM_STRENGTH`, `OSSL_RAND_PARAM_MAX_REQUEST`, `EVP_PKEY_get_size`, etc.) and use what it returns.
2. **Query once and cache** when the value is fixed per variant and the query is expensive or called often. The canonical helper is `org.openssl.jostle.jcajce.provider.cache.NativeLengthCache<K>` — one `static final` instance per consumer (SPI / enum), `get` returns `UNKNOWN` on a miss, the consumer probes native once and `cache`s the result, and `putIfAbsent` makes a concurrent double-probe benign (both threads compute the same fixed value). Its class Javadoc states the principle verbatim: "OpenSSL is the single source of truth … no transcribed table that can drift from native truth."
3. **Never** hand-write the number. If you find yourself typing `case "SHA-256": return 32;` or `private static final int[] STRENGTHS = {128, 192, 256};`, stop — that is the anti-pattern this rule exists to prevent.

Canonical right-way examples in this codebase, all of which replaced a transcribed table:

1. `RandAlgorithm.maxStrengthFor` queries `OSSL_RAND_PARAM_STRENGTH` (via `ni_drbgStrength`) and memoizes per mechanism/variant through a `NativeLengthCache` — it used to be a hardcoded strength table that had already drifted (SHA-1 was listed at 160, OpenSSL reports 128).
2. `rand.c` reads each DRBG's chunking bound from `OSSL_RAND_PARAM_MAX_REQUEST` on the live context — the `65536` literal survives only as a fallback when the query fails.
3. The `*Lengths` consolidation: digest output size, MAC length, cipher block size, signature length, and KEM encapsulation length are each probed from native once and memoized in `NativeLengthCache`, rather than tabulated per algorithm.

Two practical constraints when caching:

1. **Query lazily, never in a static initializer or enum constructor.** Those run before `rand_libctx` / the global lib ctx exists, so the native call fails or returns garbage. Trigger the first probe at SPI-construction time or first use (the `maxStrengthFor` lazy-query lesson).
2. **Key the cache by whatever uniquely identifies the variant** (the enum constant, the canonical algorithm name, or a composite). One cache per consumer so key spaces never collide across families.

**Disambiguation from "Hard-code security-critical OpenSSL parameters" (native-code.md).** These rules sound opposite but govern opposite directions of data flow. That rule is about a value *we set* to pin a security property OpenSSL would otherwise leave to a mutable default (`implicit_rejection = 1`, the RSA padding mode, a PSS salt-length sentinel) — an **input we choose**, which must be set explicitly so the intent survives drift, and backed by a runtime hard-guard test. This rule is about a value *OpenSSL defines and reports* (a size, a strength, a limit) — an **output we read**, which must never be transcribed. The test: *are we telling OpenSSL something, or asking it something?* Telling → hard-code the value explicitly and guard it. Asking → query and cache, never tabulate. Genuinely external constants that OpenSSL does not own — JCE algorithm names, ASN.1 OID strings, a per-mode default tag length chosen for BouncyCastle parity — are outside this rule; but anything OpenSSL can be asked for must be asked, not typed.


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

**AEAD param-spec acceptance: if an SPI takes a tag-carrying AEAD spec, examine whether it should also take `IvParameterSpec`**

The standard JCE has no `CCMParameterSpec`; `GCMParameterSpec` (tag length in bits + nonce) is the de-facto AEAD parameter holder for *all* AEAD modes. BouncyCastle's provider accepts three specs for any AEAD mode (GCM/CCM/OCB): `GCMParameterSpec`, BC's own `org.bouncycastle.jcajce.spec.AEADParameterSpec`, and plain `IvParameterSpec` (nonce only, tag length defaulted). Whenever you add or review an AEAD cipher SPI that accepts a tag-carrying AEAD spec (`GCMParameterSpec` or `AEADParameterSpec`), examine whether it should *also* accept `IvParameterSpec` for BC parity — a caller holding only a nonce is a common case, and rejecting it is a gratuitous interop gap.

1. **The IV-only path needs a default tag length, and that default MUST match BouncyCastle** or byte-for-byte agreement breaks. BC's default is per-mode, not universal: GCM defaults to 128 bits, but **CCM defaults to 64 bits** (`CCMBlockCipher.init` uses `getMacSize(forEncryption, 64)` on the `ParametersWithIV` path). Never copy one mode's default to another — read the BC source for the specific mode.
2. **Encrypt AND decrypt must accept it.** The easiest miss is broadening `engineInit` for one direction only.
3. **Prove it with a BC-agreement test on the `IvParameterSpec` path** — init both providers with the same `IvParameterSpec` and assert byte-identical ciphertext+tag (this is precisely what catches a wrong default tag length), plus a Jostle decrypt round-trip.
4. Reference: `CCMCipherSpi` accepts `GCMParameterSpec` + `IvParameterSpec` (64-bit default via `CCM_DEFAULT_TAG_BITS`); `BlockCipherSpi`'s GCM accepts `IvParameterSpec` with a 128-bit default. `AESAgreementTest.aesCCM_ivParameterSpec_agreesWithBC` is the canonical agreement test.

**`SecureRandom` acquisition is expensive — cache, don't allocate per call**

`new SecureRandom()` blocks on system entropy seeding (at first call per JVM, sometimes longer on Linux without `/dev/urandom` warmup) and the JCE retries through providers on every constructor call if instantiation fails. Per-operation `new SecureRandom()` adds up:

- Use `CryptoServicesRegistrar.getSecureRandom()` — the existing project helper that delegates to a cached instance.
- The `RandSource` SPI parameter pattern wraps this for native callers; pure-Java code that doesn't go through the native bridge needs the same caching discipline.
- Test code: cache one `SecureRandom` per test class (the established `private static final SecureRandom RANDOM = new SecureRandom();` pattern), not per `@Test` method.
- For tests that loop over random inputs, the `seededRandom(testName)` helper (in `RSATest`, `RSAOAEPCipherTest`, `RSAPKCS1CipherTest`) seeds a `SHA1PRNG` from a logged value so a flaky run can be replayed — use that pattern when reproducibility matters.

**Zeroize the `byte[]` from `key.getEncoded()` after use**

Any SPI that pulls raw key material out of a `Key` via `getEncoded()` (cipher `engineInit`, `engineWrap`, MAC `engineInit`, etc.) MUST zeroize that array once the native layer (or the wrap/unwrap) has consumed it. Leaving the plaintext key bytes in a heap array until GC is an unnecessary exposure window — heap dump, swap-to-disk, or a future refactor that reads the stale buffer. Wrap the use in `try { … } finally { … fill(keyBytes, (byte) 0); }`.

This is safe to clear because the standard `javax.crypto.spec.SecretKeySpec.getEncoded()` (the wrap/init `SecretKey` type in practice) returns a *fresh copy* on every call, so zeroing the returned array cannot corrupt the caller's key. A hypothetical custom `Key` whose `getEncoded()` handed back its internal array would be damaged — we accept that as vanishingly unlikely for `SecretKeySpec` and zeroize regardless, because the defence-in-depth on plaintext key material outweighs that edge case.

Two implementation requirements:
1. Call `getEncoded()` **after** any parameter validation that can throw (e.g. an AEAD tag-length check), and clear in a `finally` — so a rejected `init` never leaves an uncleared key copy and an exception mid-`init` still scrubs it. `BlockCipherSpi.engineInit` obtains `keyBytes` only after the spec branch, immediately before `blockCipherNi.init`, inside a `try/finally` that clears it.
2. `org.openssl.jostle.util.Arrays.fill(byte[], byte)` is NOT null-safe — it delegates to `java.util.Arrays.fill` — and `getEncoded()` may return null, so guard: `if (keyBytes != null) { Arrays.fill(keyBytes, (byte) 0); }`.

`BlockCipherSpi.engineInit` / `engineWrap` are the reference implementations; `engineUnwrap` applies the same `fill` to the decrypted plaintext it produces.

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
