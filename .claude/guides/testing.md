# Test discipline

Checklists and rules for writing Jostle tests — run before declaring a test file
done. Auto-imported by CLAUDE.md.

### Test-discipline checklist — run before declaring a test file done

Whenever you write or modify a roundtrip-style unit test (sign/verify, encrypt/decrypt, MAC, digest, encap/decap, KDF), audit the test against the following two rules **before declaring the work complete**. The full rationale for each rule lives in the named sections below; this checklist is the enforcement summary:

1. **Random inputs.** Every key, IV / nonce, salt, AAD, plaintext, message, and password used in a non-KAT roundtrip MUST be derived from a `SecureRandom` (via `nextBytes`, a `KeyGenerator`, or a `KeyPairGenerator`) — not a hardcoded `byte[]` literal, hex string, or `"...".getBytes()`. KAT tests that pin a published vector are exempt. See **"Vary the chunking, and randomise the inputs"** and **"Run agreement tests against BouncyCastle, with random inputs"** for the full rules.
2. **Negative path.** Every roundtrip primitive covered in the file MUST have at least one accompanying test that proves the operation actually transforms its input: tampered ciphertext → decrypt diverges, tampered message → verify returns false, wrong key → roundtrip fails, distinct inputs → distinct digests / MACs / derived keys. A KAT alone is insufficient — pair it with at least one differentiator. See **"Tests must exercise the negative path"** for the per-primitive expectations.

**Automation.** Run the `audit-test-coverage` skill (in `.claude/skills/audit-test-coverage/`) before declaring a test file done; it scans the test tree for both classes of gap and reports per-file findings. The skill is heuristic but fast, and surfaces the same kinds of issues the historical audits caught (hardcoded `"hello world".getBytes()` in sign/verify roundtrips, BC-agreement KDF tests without a `KDF(salt1) != KDF(salt2)` differentiator, etc.).

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

