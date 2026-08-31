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

**Asking ANOTHER JCA PROVIDER is the same defect as transcribing, and it hides better.** A transcribed `32` is visibly a second source of truth; `MessageDigest.getInstance("SHA-256").getDigestLength()` looks like a query and is one — of the wrong oracle. It names no provider, so JCA order decides (in practice SUN), and the answer is a fact about the JDK, not about the interface library the operation will actually run on. `HKDFSecretKeyFactory` sourced its RFC 5869 `255 * HashLen` ceiling that way until MT-11; it now probes `MDServiceNI.allocateDigest` / `getDigestOutputLen` / `dispose` through the SAME NI the factory's KDF uses, so JSLFIPS asks the module and JSL asks mainline. Canonicalise BEFORE probing — OpenSSL knows `SHA2-256`, not the JCE spelling `SHA-256`.

**The discriminating test for a query-and-cache fix is the ABSENCE of the wrong oracle, never an equality check.** SHA-256 is 32 bytes whoever is asked, so every "the ceiling is 8160" assertion passes identically before and after the fix — the a3 trap in its purest form. Empty the `Security` registry, prove the removal took effect (`MessageDigest.getInstance` must now throw), and only then assert the value: the provider-sourced implementation can only throw out of its constructor, while the native-sourced one is unaffected. `HkdfDigestLengthSourceTest` is the reference, and its falsification is the demonstration — restoring the SUN source failed the stripped-registry test while the registry-intact control AND all twelve pre-existing `HkdfTest` cases stayed green. Safe to mutate the global registry in a test: the build runs `forkEvery = 1`.

Two practical constraints when caching:

1. **Query lazily, never in a static initializer or enum constructor.** Those run before `rand_libctx` / the global lib ctx exists, so the native call fails or returns garbage. Trigger the first probe at SPI-construction time or first use (the `maxStrengthFor` lazy-query lesson).
2. **Key the cache by whatever uniquely identifies the variant** (the enum constant, the canonical algorithm name, or a composite). One cache per consumer so key spaces never collide across families.

**Disambiguation from "Hard-code security-critical OpenSSL parameters" (native-code.md).** These rules sound opposite but govern opposite directions of data flow. That rule is about a value *we set* to pin a security property OpenSSL would otherwise leave to a mutable default (`implicit_rejection = 1`, the RSA padding mode, a PSS salt-length sentinel) — an **input we choose**, which must be set explicitly so the intent survives drift, and backed by a runtime hard-guard test. This rule is about a value *OpenSSL defines and reports* (a size, a strength, a limit) — an **output we read**, which must never be transcribed. The test: *are we telling OpenSSL something, or asking it something?* Telling → hard-code the value explicitly and guard it. Asking → query and cache, never tabulate. Genuinely external constants that OpenSSL does not own — JCE algorithm names, ASN.1 OID strings, a per-mode default tag length chosen for BouncyCastle parity — are outside this rule; but anything OpenSSL can be asked for must be asked, not typed.


### Review Java SPI and provider plumbing for the bug classes positive-only tests can't catch

The JCE SPI surface is a contract-heavy state machine: subtle exception-type expectations, transition rules, parameter-handling defaults, and provider-fallback semantics that a positive-only roundtrip test never surfaces. Most of these bugs become visible only under specific use patterns — wrong exception type breaking provider fallback, mis-registered cipher transformations silently downgrading the digest, GC reclaiming a key handle mid-call, or a multi-release ABI drift only visible to downstream callers compiled against the older view. When reviewing Java in `jostle/src/main/java/`, `jostle/src/main/java<N>/`, and `jostle/src/test/java/`, look for these classes specifically.

**JCE transformation lookup: form-1 alias vs form-4 fallback**

`Cipher.getInstance("X/Y/Z")` runs through `javax.crypto.Cipher.Transform.getTransforms()`, which tries four lookup forms in order: (1) the exact transformation `"X/Y/Z"` — `engineSetMode`/`engineSetPadding` are NOT called; (2) `"X/Y"` with explicit padding to apply; (3) `"X//Z"` with explicit mode to apply; (4) bare `"X"` with both mode and padding to apply. The first matching service wins. Registering a transformation alias of the bare algorithm — `provider.addAlias("Cipher", "RSA", "RSA/ECB/OAEPWithSHA-512AndMGF1Padding")` — makes form 1 succeed, **bypassing the SPI's `engineSetPadding` entirely**. The SPI silently uses its default values regardless of what the alias claimed. Real bug we hit: every `OAEPWith<digest>AndMGF1Padding` alias collapsed to the SPI's `DEFAULT_DIGEST = "SHA-256"`, caught only when a multi-trial agreement test surfaced an input-length mismatch at the SHA-512 boundary.

Don't register transformation aliases on a primary cipher whose SPI uses `engineSetPadding` to configure itself. Either register each transformation as its own primary (separate SPI per name, the `RSA/ECB/PKCS1Padding` model), or register only the bare algorithm and let JCE fall through to form 4 where `setMode`/`setPadding` actually run.

**Match BouncyCastle's exception TYPE for the same refusal — it is a de facto standard (standing rule, Megan 2026-08-31)**

So much is built on BouncyCastle that its exception types are what callers write `catch` blocks against. **A type divergence is an interop break even when the accept/reject DECISION agrees**: the caller's handler simply does not fire, and since `OpenSSLException` is a `RuntimeException`, it escapes to whatever sits above. So when adding or reviewing a negative path, measure what BC throws for the same input and match the TYPE. Messages stay ours — they need to be clear and accurate, not verbatim BC — and if you believe a caller matches on message text, surface that rather than matching silently.

The trap this rule exists for: **delegating a refusal to OpenSSL delegates the TYPE too.** OpenSSL refused every illegal AES key-wrap length correctly, so delegation looked like the clean choice — and produced `OpenSSLException` where BC raises `IllegalBlockSizeException` (wrap side) and `BadPaddingException` (unwrap side). The fix is to make the *decision* ours so the *type* can be: explicit RFC 3394 / RFC 5649 length rules in `wrap_length_check`, mapping to `JO_WRAP_INPUT_LENGTH_INVALID` and `JO_INVALID_CIPHER_TEXT`, with OpenSSL left in place behind them as backstop. Comment such a check with why it is explicit, or the next reader "simplifies" it back into delegation.

Two boundaries worth knowing, both settled by measurement rather than argument:

1. **A DECISION disagreement is not a type problem and no mapping fixes it.** BC wraps a single 8-byte semiblock and returns 16 bytes; OpenSSL refuses (RFC 3394 defines n >= 2 semiblocks). We adhere to OpenSSL and pin the divergence with a test asserting BOTH halves, so neither a drift toward BC nor a later parity sweep can move it silently.
2. **Ask which side of the CHECKED/UNCHECKED line each type sits on — it decides urgency, and it reverses judgements.** A failed AES key-unwrap integrity check was first left on `OpenSSLException` as an acceptable divergence, then reversed the same day on one measured fact: `OpenSSLException` extends `RuntimeException`, so the BC-shaped `catch (BadPaddingException)` caught **nothing** on the routine attacker-data path and the error escaped to whatever sat above. Type parity reads as cosmetic until you notice that. Where the mismatched type is unchecked and the matched one is checked, the divergence is not a style difference — it is a handler that never runs.

**Measure before claiming parity, and measure every cell.** "Matches BC" from a handful of lengths is not a claim about the mapping — widening one such matrix from six lengths to ten turned "identical in every cell" into one decision disagreement plus a whole column of type mismatches. MT-31 tracks the provider-wide survey.

**Throw the right JCE exception type — provider-chain fallback depends on it**

JCE has strict exception-type contracts that determine both caller-visible behaviour and **whether the JCE moves on to the next registered provider**:

- `init` throwing `InvalidKeyException` or `InvalidAlgorithmParameterException` → JCE retries with the next provider in `Provider[]` order. This is the primary fallback mechanism for "wrong key type for this provider".
- `init` throwing `ProviderException` (a `RuntimeException`) → propagates, no fallback. A native bridge crash that surfaces as `ProviderException` leaves the caller stuck with this provider.
- `engineDoFinal` throws `BadPaddingException` for decrypt-padding failures, `IllegalBlockSizeException` for size mismatches, `ShortBufferException` for the in-place variant when output is too small. A generic `RuntimeException` from `doFinal` breaks `assertThrows` patterns and shoves errors into application-level handlers that expect typed JCE exceptions.
- `engineUnwrap` should surface `InvalidKeyException` on **all** unwrap failures — never `BadPaddingException` (Bleichenbacher channel). `RSAOAEPCipherSpi` and `RSAPKCS1CipherSpi` already collapse `BadPaddingException` into `InvalidKeyException` at the unwrap boundary; new wrap/unwrap SPIs must follow.

A bug where the wrong exception type leaks (e.g. `OpenSSLException extends RuntimeException` thrown from a place that should surface `BadPaddingException`) breaks both fallback and tests, and is invisible to a positive-only roundtrip.

**Capability failures: `ProviderCapabilityException` → the JCE-canonical init exception**

When the loaded provider cannot honour a capability the operation's security contract requires — implicit rejection for PKCS#1 v1.5 decrypt (`JO_IMPLICIT_REJECTION_UNAVAILABLE`, -135), the subgroup order q for DH agreement under FIPS (`JO_DH_Q_REQUIRED`, -136), a real PKCS#3 safe-prime search rather than a named-group substitution (`JO_DH_PARAMGEN_SUBSTITUTED`, -137), Triple-DES encryption when the module refuses that direction and keeps decryption (`JO_TDES_ENCRYPT_UNAVAILABLE`, -167) — the C side returns the distinct typed code and the error handler throws `ProviderCapabilityException`. It extends `OpenSSLException` so generic handlers keep working, and limit tests pin the exact type + message. SPIs translate at their init boundary, per surface:

1. `Cipher` / `KeyAgreement` `engineInit` → `InvalidKeyException` carrying the capability message. This is deliberate: it is the JCE-canonical init failure AND the provider-fallback trigger, so a deployment registering both JSLFIPS and a capable provider falls through to one that can do the operation safely instead of dying on a runtime exception.
2. `AlgorithmParameterGenerator.engineGenerateParameters` → `ProviderException` (its contract has no checked exception).
3. Never let the raw runtime escape `engineInit` — an untranslated `ProviderCapabilityException` breaks fallback and the typed-catch contract alike.

This is the same three-layer shape as `JO_INVALID_CIPHER_TEXT` → `InvalidCipherTextException` → `BadPaddingException` (see the OAEP note in native-code.md), applied to fail-loud capability refusals. When adding a new capability gate, reuse `ProviderCapabilityException` with a new pinned message rather than minting another exception class, and back it with BOTH a real-environment FIPS limit test (the module genuinely lacks the capability) and a base-tree OPS test for the injected branch.

**`engineUnwrap` must reconstruct the key through its OWN provider, and resolve the KeyFactory BEFORE decrypting**

Symptom: `Cipher.unwrap` returned a key that the unwrapping provider itself then refused. Every `engineUnwrap` in the tree called `KeyFactory.getInstance(wrappedKeyAlgorithm)` with no provider, so JCA resolved it against the installed list in order — normally SUN. Two failures, and the second is caller-visible breakage rather than boundary hygiene (MT-10):

1. **Boundary.** A JSLFIPS unwrap produced a key not resident in the FIPS lib ctx at all. Undetectable behaviourally — a SUN EC key signs the bytes the module would.
2. **Correctness.** The returned object was foreign, so the next Jostle operation on it failed MT-14's provider-instance isolation check. `unwrap` handed back something its own provider rejects.

The fix is `UnwrappedKeys.keyFactory(ownProvider, wrappedKeyAlgorithm)` at every `PUBLIC_KEY` / `PRIVATE_KEY` arm. Six rules:

1. **The provider INSTANCE, sourced from construction — never the name.** A name is re-resolvable (`removeProvider` + `addProvider` swaps what it points at) and a `Cipher` obtained through `getInstance(alg, Provider)` need never have been registered under a name at all, so name-pinning would leave exactly the hole MT-14 closed. The RSA cipher SPIs already hold a bound `RSAKeyFactorySpi` and read `keyFactory.ownProviderInstance()`; `BlockCipherSpi` gained a `Provider` on its constructors and every block-cipher registration in both `Prov*` trees passes it.
2. **`SECRET_KEY` is unaffected and stays a `SecretKeySpec`** — no native residency, no provider to bind to, no isolation check to fail. The same line MT-14 drew, and it must stay consistent with it.
3. **Resolve BEFORE `engineDoFinal`.** Resolving afterwards makes the exception type depend on whether the decrypt succeeded: with an unserved algorithm every valid ciphertext raises `NoSuchAlgorithmException` and every invalid one `InvalidKeyException`, which is a padding oracle. It also skips a pointless private-key operation on a call that cannot succeed. Pin the ordering with a test that passes deliberately-garbage ciphertext and requires `NoSuchAlgorithmException` — resolving second would report the decrypt failure instead.
4. **`NoSuchAlgorithmException`, not `InvalidKeyException`, and this does NOT breach the unwrap rule above.** That rule ("all unwrap failures surface as `InvalidKeyException`, never `BadPaddingException`") closes a Bleichenbacher channel and therefore binds *ciphertext-dependent* failures. This one is decided entirely by `wrappedKeyAlgorithm` and the SPI's own provider, both fixed before any ciphertext is examined, so it distinguishes nothing about the plaintext. `NoSuchAlgorithmException` is declared on `engineUnwrap` and on `Cipher.unwrap` for exactly this case, and it is what the JDK throws — SunJCE's `ConstructKeys` raises `NoSuchAlgorithmException("No installed provider can create keys for the ... algorithm")`.
5. **An unbound SPI (direct construction, `providerInstance == null`) fails loudly too.** There is no provider to bind the result to, and reaching for JCA order is the defect. Pinned at `UnwrappedKeys.keyFactory(null, alg)` rather than end-to-end, because `engineUnwrap` is `protected` and every provider-mediated route is bound by construction.
6. **The structural lint is necessary but not sufficient.** `ProviderPinningParityTest` proves the call site names a provider; only a behavioural test proves it names the RIGHT one. Assert the binding (`((OSSLKey) k).getSpec().getProviderInstance()`) and, on the FIPS side, module residency (`SpecNI.getKeyProvider` → `"fips"`). An encoding-comparison test passed throughout the defect's life — `RSAOAEPCipherTest.testOAEP_WrapUnwrap_PublicKey_roundTrip` compared `getEncoded()` and was green while the key came from SUN.

**Behavioural tests prove the MECHANISM; only enumeration proves the WIRING.** Three transformations exercise the three unwrapping SPI classes end to end. They say nothing about the other sixty-odd registration sites, and a `Prov*` lambda that forgot its `provider` argument fails only when somebody unwraps an asymmetric key through THAT transformation — which no test does, so the miss sits there. This is the MT-14 `ProvFIPSXDH` lesson in cipher clothing. `CipherProviderBindingSweepTest` / `FIPSCipherProviderBindingSweepTest` therefore enumerate `getServices()` on each provider, construct every Cipher SPI, and require any class overriding `engineUnwrap` to carry that provider instance — with an unrecognised overriding class a FAILURE, not a skip. A longer hand list is not the fix; it has the same blind spot one entry further along.

Two traps that version one fell into, both instances of rules stated elsewhere in these guides:

1. **Shape-sniffing found a field that was not in the path.** Both KTS ciphers hold a bound `RSAKeyFactorySpi`, so the reflective probe reported them bound — while the thing governing their *unwrap* is an inner `Cipher` they resolve by provider NAME. The sweep printed `namePinned=[]` and looked healthy. Consult the explicit classification BEFORE any shape detection, and falsify the matcher in both directions (it fires on bad code AND stays quiet on good) per the source-lint rule below.
2. **Non-vacuity floors are per-provider.** JSL registers 48 Cipher services, JSLFIPS 25, and a module without Triple-DES fewer still. A single shared threshold either passes vacuously on the smaller provider or fails spuriously on it.

**A pin on a provider NAME is not a pin, and the gap is only visible against a selectively-incapable instance.** MT-5 fixed "no provider at all" by threading a `String providerName` from construction into every inner `getInstance`. That closed the SUN fall-through, and it reads as done. It is not: `removeProvider` + `addProvider` swaps which instance a name resolves to, and `getInstance(alg, Provider)` never required registration at all, so a name still resolves to a DIFFERENT instance than the SPI belongs to. MT-16 converted the two KTS ciphers (`RSAKEMCipherSpi`, `MLKEMKTSCipherSpi`) to the instance, taken from the bound `keyFactory.ownProviderInstance()` rather than carried as a second field — two identity channels can disagree, and the one the SPI already has is the right one. Three things this teaches:

1. **A delegating unwrap inherits its delegate's binding, so the outer pin is load-bearing.** Both KTS ciphers derive a KEK and hand the WHOLE unwrap — `wrappedKeyType` included, so `PUBLIC_KEY`/`PRIVATE_KEY` genuinely reach it — to an inner AES key-wrap `Cipher`. MT-10 made that inner cipher bind correctly to *its* provider; resolving it by name therefore produced a key bound to the wrong instance, which the outer provider then refused (MT-14). An SPI that delegates is not exempt from the binding rule — it is exactly where the rule is easiest to lose.
2. **The structural lint cannot see the difference.** `ProviderPinningParityTest` decides "names a provider" by counting top-level commas in the argument list, so a `String` name and a `Provider` object are indistinguishable to it. That is the right scope for a lint — it catches the unpinned call, which is the loud defect — but it means the lint passed unchanged across MT-16, and it stayed GREEN under the MT-16 falsification too. Do not read a green source lint as evidence about WHICH provider is named.
3. **The behavioural discriminator needs an instance that is deliberately incapable.** See the `StrippedJostleProvider` note in testing.md; there is no other input that separates the two schemes, because the two providers compute identical bytes.

**Naming a "borrowable" algorithm in a test goes stale — discover it.** The test for "a name another provider serves and mine does not" needs such a name, and three plausible guesses were all wrong: JSL aliases `DiffieHellman`, `RSASSA-PSS` and `XDH`, so its KeyFactory surface is a *superset* of the stock JDK's and the JDK offers no instance of that cell at all. `UnwrappedKeyBindingTest` therefore scans BouncyCastle's `getServices()` for the first KeyFactory JSL lacks. On the FIPS side the case is real and stable — `edec` is nonfips-only, so JSLFIPS serves no Ed25519 KeyFactory while both JSL and SunEC do — and `FIPSUnwrappedKeyBindingTest` asserts that precondition rather than assuming it.

**`Linker.Option.critical` forbids upcalls — RandSource-bearing FFI downcalls must arena-copy**

A downcall handle bound with `Linker.Option.critical(true)` may pass heap segments zero-copy, but upcalls into the JVM are illegal for the call's duration. Any NI entry point that binds a `RandSource` — meaning the C side may up-call for entropy — must be marshalled with confined-arena copies plus `linker.upcallStub`, never critical heap segments; `SpecFFI.ni_encap` / `ni_decap` are the reference pair. The trap is retrofit: adding a `rand_src` parameter to an existing C entry point silently invalidates a critical-marshalled Java twin that was correct when the C side made no upcalls — audit the FFI class's `Linker.Option` choice whenever an NI signature gains a RandSource. (JNI has the same rule in different clothes: no up-calls between `GetPrimitiveArrayCritical` and its release — fetch entropy outside critical regions.) Remember the copy direction when converting: inputs must be copied INTO the arena segment before the call (`Arena.allocateFrom`), outputs copied back after — `Arena.allocate` alone leaves an input segment full of zeros.

**Native references must outlive every JNI/FFI call**

Every Java SPI that holds a native pointer through a `NativeReference` / `Disposer` must keep the holding object reachable across every native call. A GC pause between "read the native handle into a local long" and "make the JNI/FFI call" can otherwise reclaim the holder, run the disposer (freeing the native ctx), and leave the call dereferencing freed memory. The bug is non-deterministic and only appears under load.

Two patterns the codebase uses:

- Java 8 (`src/main/java/`): `synchronized(this) { native call }` — the synchronisation keeps `this` reachable for the lock's duration.
- Java 9+ (`src/main/java9/` and later): `try { native call } finally { Reference.reachabilityFence(this); }` — explicit fence, the modern preference.

Every multi-release `javaN/` override of an SPI re-implements this pairing. The same applies to helpers like `RSAComponents.getRequired`/`getOptional` which hold `PKEYKeySpec spec` across two NI calls — `synchronized(spec)` (Java 8) and `Reference.reachabilityFence(spec)` (Java 9+) both appear in the codebase. New SPIs must follow one or the other; a raw native call without either is a latent bug even if testing happens to pass.

**The holder is whatever *field* owns the handle — key classes and borrowed-spec cipher SPIs count too, and passing a field handle to a helper does NOT make it safe.** The obligation is not limited to an SPI's own `NativeReference ref`; it applies to *any* non-private method that makes a native call on a handle reached through an **instance field**. Two field-held cases are easy to miss because the handle is not a `*ref` and the "native call" is not visibly native:

1. **Key classes** (`JOMLDSAPrivateKey`, `JORSAPublicKey`, every `JO*Key`) hold their `PKEYKeySpec spec` as a field (inherited from `AsymmetricKeyImpl`). Their raw getters (`getSeed`, `getPublicData`, `getDirectEncoding`) call `NISelector.<X>ServiceNI.get*(spec.getReference(), …)` inline — an obvious native call — but **`getEncoded()` is *also* a native call**: it hands `spec` to `ASN1Encoder.as*`, and `ASN1Encoder` reads `spec.getReference()` and then never touches `spec` again — **it does NOT fence the spec, it relies on the caller** (see `ASN1Encoder.asPrivateKeyInfo`/`asSubjectPublicKeyInfo`). So "I only passed `spec` as an argument, I never called `getReference()` myself" is a fallacy: the argument becomes dead inside the callee's frame the instant the callee's last use of it returns, and nothing fences it there. Every such method — each inline raw getter **and** `getEncoded` — needs `synchronized(this)` (baseline) + a `javaN/` `reachabilityFence(this)` override, exactly like the Ed/RSA/DH/DSA/EC key classes already do.
2. **Cipher SPIs that borrow a key's spec** — `MLKEMKTSCipherSpi` stores the wrap/unwrap key's `PKEYKeySpec` in a `keySpec` field and guards the `encap`/`decap` call the same way, even though it never allocated a `ref` of its own.

The distinguishing test is **field vs. local**: a handle reached through an *instance field* (`this.spec`, `this.keySpec`) can be reclaimed when `this` dies mid-call and needs the guard; a handle held in a *local variable or parameter* — the fresh `PKEYKeySpec` a `KeyFactory`/`KeyPairGenerator` builds, or the `spec` parameter `ASN1Encoder` itself receives — is kept reachable by that variable's own stack slot and is safe. That is why `DHKeyPairGenerator`/`DSAKeyPairGenerator`, whose `synchronized(paramsSpec)` guards a *local* spec, need no fence twin and no `javaN/` override (no KeyPairGenerator carries one). This whole class shipped once — the ML-KEM/ML-DSA/SLH-DSA key families and the ML-KEM KTS cipher were written without the guard while every peer family had it — so **when you add a new key family or a cipher that borrows a key's spec, apply the pattern to `getEncoded` and every raw getter, not just the methods that call `getReference()` literally.** `NativeReferenceParityTest.everyFieldHeldHandleNativeCallIsGuarded` enforces this: a non-private method reaching a field-held `spec`/`keySpec` (inline `getReference()` or via `ASN1Encoder.as*`) without a monitor or fence fails the build.

**An SPI that reaches `NISelector` statics cannot ever serve JSLFIPS — and the FFI half is a separate, quieter version of the same bug.** Two forms, both found when PQC was added to JSLFIPS:

1. **Java side.** An SPI whose body says `NISelector.MLDSAServiceNI.…` is welded to the base interface library and its `OSSL_LIB_CTX`. There is no way to register it in `JostleFIPSProvider` — it would hand JSLFIPS callers keys made by the base library. Every SPI, key class and `Disposer` must take its NI(s) by constructor, with a convenience constructor delegating to the `NISelector` statics so existing callers are unchanged. `ProvFIPSXDH`'s `new XECKeyPairGenerator(FIPSNISelector.XECServiceNI, FIPSNISelector.SpecNI, …)` is what this buys.
2. **FFI side, and it is not cosmetic.** A `private static final SymbolLookup lookup = SymbolLookup.loaderLookup()` looks harmless — but **both interface libraries export the same `Jo*` symbol names**, so the process-global loader lookup resolves into whichever library loaded first. A FIPS subclass over such a base drives the BASE library while believing it is in the module. Parameterise by `SymbolLookup` (instance field, set in a constructor; move any `static {}` initialiser into it) and have the FIPS subclass pass `FIPSLibraryLookup.get()`. Symptom if you get it wrong: FIPS operations that succeed but are not actually performed by the module, which no functional test detects.

**Provider isolation is per-SPI, not automatic — a family that exists in only one provider has never been tested for it.** The `*KeyImport` helpers enforce `joKey.getSpec().getSpecNI() != keyFactory.ownSpecNI()` for RSA/EC/DSA/DH, but the PQC SPIs had no such check and their translate path constructed a *base-provider* KeyFactory. That was inert while PQC lived in JSL alone and became a live cross-lib-ctx defect the day it was registered in JSLFIPS too. When enabling an existing family in the other provider, audit every key-accepting entry point for the check before assuming it is inherited. Since MT-14 the check applies to **both halves**: a key object belongs to the provider INSTANCE that created it (`PKEYKeySpec.usableBy`), because OpenSSL serves an operation in the key's own provider whatever lib ctx drove the call. Keep the library-level `getSpecNI()` comparison beside it on private keys — it is the only check with teeth in the unbound direct-SPI realm, where both instances are `null`. See testing.md "JSL ↔ JSLFIPS key sharing".

**A new native-reference class must ship BOTH halves of the pairing — not pick one.** "Follow one or the other" is *per JDK level*, not a one-time choice. The `java/` baseline uses `synchronized(this)` (it cannot use `reachabilityFence`, a Java 9 API); a class that holds a `NativeReference` (or caches a handle across calls) and stops at the baseline is *correct* — the monitor keeps `this` reachable on JDK 9+ too — but it silently drifts from every peer SPI, and on JDK 9+ the multi-release jar then serves the monitor-based class instead of the intended fence. So any such baseline class MUST also carry a `javaN/` override that re-implements every `synchronized (this) { … }` block as `try { … } finally { Reference.reachabilityFence(this); }`. The override lives at `java9/` for a class expressible at release 9, or at the lowest `javaN/` the class first compiles at (the EdEC key classes carry theirs at `java15/`, since they implement JDK-15 `EdEC*` interfaces). The transform is mechanical: copy the baseline, swap each block to the fence form, add `import java.lang.ref.Reference;`, and change nothing else — a `diff` of the two files should show only the import plus the `synchronized`→`try/finally` conversions. `RSAPKCS1CipherSpi`, `RSAOAEPCipherSpi`, and `KSServiceSPI` each shipped baseline-only before this was caught; `NativeReferenceParityTest` (`src/test/java/.../multirelease/`) now fails the build if any baseline native-reference class lacks a fence override.

**Before editing a method, `grep` for the class under every `src/main/javaN/` and check whether *that method* is overridden — and remember a subclass can inherit its reachability override from a parent, so the absence of an override is often correct.** The per-algorithm block-cipher SPIs (`AESBlockCipherSpi`, `ARIABlockCipherSpi`, `CAMELLIABlockCipherSpi`, `SM4BlockCipherSpi`, `DESedeBlockCipherSpi`) hold no handle of their own and carry **no** `javaN/` override: the `NativeReference ref` and the reachability-sensitive `update`/`doFinal` calls live in their shared parent `BlockCipherSpi`, which carries the `java9/` fence override the subclasses inherit. So a pure-Java edit to a subclass method that has no override and no reachability concern — e.g. the `key.getEncoded()` zeroize added to each subclass `engineInit` — is served from the single baseline copy on every JDK and needs no mirror; adding an empty `javaN/` copy would be *wrong* (it would drift). The trap is the *other* direction: `ChaCha20BlockCipherSpi` **does** override `engineInit` at `java11/` (to translate `ChaCha20ParameterSpec`→`IvParameterSpec`), so any future edit to `ChaCha20BlockCipherSpi.engineInit` must be applied to **both** copies. The rule is the per-method form of the multi-release-parity rule in CLAUDE.md: an edit must land in the baseline **and** in every `javaN/` copy that overrides the *specific method* being changed — no more, no fewer.

**A `NativeReference` subclass's dispose action must be built from constructor parameters and handed to `super()` — never captured from an instance field.** This is a `this`-escape hazard distinct from the reachability one above. `NativeReference`'s constructor self-registers with the disposal daemon (`DisposalDaemon.addDisposable(this)`), and that registration **eagerly** calls `getDisposeAction()` to capture the cleanup `Runnable` — it must, because once the phantom is enqueued after GC the referent is gone (the standard `java.lang.ref.Cleaner` constraint). That capture therefore runs *inside* the `NativeReference` constructor, i.e. **before the subclass constructor body executes**. So a `RefWrapper` that builds its disposer from a subclass field — the old `protected Runnable createAction() { return new Disposer(this.xxxNi, reference); }` pattern — reads that field while it still holds its default `null` (the `this.xxxNi = xxxNi;` assignment hasn't run yet). The captured disposer then NPEs on the disposal daemon thread when GC finally runs it — a silent native-`EVP_*`-context leak that positive tests never catch (it fires only when the collector happens to process a disposer, so it looks intermittent even though every instance is affected). The rule: the concrete `RefWrapper` constructor passes the fully-built action up — `super(reference, name, new Disposer(ni, reference))` — using its constructor *parameters* (legal before `super()` returns; instance fields are not), and `NativeReference` stores and returns it. Do **not** re-add a `createAction()` override or any disposal path that reads instance state. This was latent for years because RefWrappers referenced the *static* `NISelector.X` (always initialised); the NI-by-constructor refactor moved the NI to a per-instance field read during construction and exposed it across every family at once — see the disposal-fix history and `NativeReference` for the canonical shape.

**Multi-release source-set API stability — public surface MUST be identical**

When the same class lives in multiple `src/main/javaN/` directories, the **public/protected API surface must be identical** across all versions. The multi-release jar loads the JDK-version-appropriate copy at runtime, but downstream code is *compiled* against the Java 8 ABI (the lowest baseline). Implications:

- A new public method added to `java25/MyClass` but not to `java/MyClass` is invisible to callers compiled against the jar — they get the Java 8 ABI which doesn't see the method, even on JDK 25.
- A public method removed from `java25/MyClass` but kept in `java/MyClass` triggers `IllegalAccessError` on JDK 25 when the older API contract is invoked from the multi-release jar.
- Internal (`private` / package-private) methods may differ freely between versions.
- A `javaN/` copy can use Java-N-specific APIs internally, but the parameter and return types of public methods must remain Java-8-expressible.

The existing `## Multi-release source layout (critical)` warns about applying changes to every override copy but doesn't articulate the ABI-stability rule. Drift surfaces only when downstream code is compiled against the older view and run on the newer JDK — which most local test runs don't exercise. `NativeReferenceParityTest` (`src/test/java/.../multirelease/`) is a precedent for source-level parity guards; consider similar tests for any class with substantial cross-version overrides.

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

**Never accumulate sensitive bytes in a plain `ByteArrayOutputStream` — use `ExposedByteArrayOutputStream` and `erase()`**

`java.io.ByteArrayOutputStream` cannot be cleaned, and each of its three escape routes leaves a copy behind. `reset()` only rewinds the count — the bytes stay. `toByteArray()` returns a COPY and leaves the internal buffer populated until GC. And growth via `Arrays.copyOf` abandons every previous buffer with its contents intact and now unreachable, so a stream that grew has already leaked copies that no later cleanup can reach. This is the exact Java twin of the native rule that a buffer holding secrets must grow by malloc + copy + `OPENSSL_clear_free` rather than a bare `realloc` (see "One-shot EVP primitives under a streaming JCA contract" in native-code.md) — same failure, one container up.

The rule: material that is secret, derived from a secret, or whose sensitivity the API does not constrain must not pass through a plain `ByteArrayOutputStream`. Use `org.openssl.jostle.util.io.ExposedByteArrayOutputStream` (BC's `ErasableOutputStream` shape — `getBuffer()` + `erase()`), call `erase()` in a `finally` once the bytes are consumed, and **presize the stream when the final length is computable** so it never grows. Where the length genuinely cannot be known, say so in the Javadoc: `erase()` covers only the final buffer.

**"Whose sensitivity the API does not constrain" is doing real work in that sentence.** The canonical case is `KeyAgreementKDF`'s X9.42 OtherInfo (found in review, 2026-08-27): the wrap OID, counter and key length are public, and the UKM is public in CMS ESDH — so it is tempting to call the whole thing public and move on. But the KDF's signature accepts arbitrary caller-supplied UKM bytes and nothing anywhere constrains them to be public. The question to ask is not "is this material public in the use I have in mind?" but "can a caller put something sensitive here?". If yes, treat it as sensitive; the cost is a presize and a `finally`.

Note what is NOT in scope, so the rule stays cheap to follow: bytes fed straight to `MessageDigest.update` never accumulate and need no stream at all (`MLKEMKTSCipherSpi.kdf3` and `RSAKEMCipherSpi.kdf3` are the reference — they pass `otherInfo` directly and scrub each derived block), and genuinely public accumulations such as concatenated certificate DER need nothing.

**Review hint:** every `new ByteArrayOutputStream` under `jcajce/provider/**` deserves the question "can sensitive bytes reach this?". Grep for it when reviewing a KDF, a key-wrap path, a keystore, or anything that stages material before handing it to native code.

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
