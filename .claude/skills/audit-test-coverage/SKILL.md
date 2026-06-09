---
name: audit-test-coverage
description: Scan Jostle's unit-test tree for two recurring discipline gaps — roundtrip tests that use hardcoded keys/messages instead of random inputs, and roundtrip tests with no negative-path differentiator (tampered ciphertext, tampered signature, wrong key, distinct inputs producing distinct outputs). Use this skill whenever the user wants to audit test discipline — including phrases like "audit test coverage", "find tests with hardcoded keys", "check tests for negative-path coverage", "scan for tests that need random inputs", "verify tests have tamper checks", "find tests that don't randomise inputs", and similar. Also useful before declaring a new test file done, after a refactor that changed input-derivation patterns, or as part of a broader test-quality sweep.
---

# Audit unit tests for random-input + negative-path discipline

CLAUDE.md mandates two rules for every roundtrip-style unit test:

1. **Random inputs** — keys, messages, IVs, salts, AADs MUST be derived from `SecureRandom` / `KeyGenerator` / `KeyPairGenerator`, not hardcoded literals (`"...".getBytes()`, `Hex.decode("...")`, `new byte[]{0x01, 0x02, ...}`). KAT tests that pin a published vector are exempt.
2. **Negative path** — every roundtrip primitive in a file MUST have at least one accompanying test proving the operation actually transforms its input: tampered ciphertext → decrypt diverges, tampered message → verify returns false, distinct inputs → distinct digests / MACs / derived keys.

The full rationale lives in CLAUDE.md sections "Tests must exercise the negative path", "Vary the chunking, and randomise the inputs", and "Run agreement tests against BouncyCastle, with random inputs". This skill scans the test tree mechanically and reports gaps so they can be triaged and fixed.

## When to use this skill

Trigger phrases (any of):

1. "audit test coverage" / "scan tests for gaps"
2. "find tests with hardcoded keys" / "find tests with fixed messages"
3. "check tests for negative-path coverage"
4. "which tests don't randomise their inputs"
5. "verify every roundtrip test has a tamper check"
6. Before declaring a test file done — verify the file passes both rules.
7. After bulk-refactoring tests — verify no random-input gap regressed.

## How to run

The script is at `scripts/audit-test-coverage.py`. From the repo root:

```bash
# Scan the entire test tree (default).
python3 .claude/skills/audit-test-coverage/scripts/audit-test-coverage.py

# Scan a single file.
python3 .claude/skills/audit-test-coverage/scripts/audit-test-coverage.py \
    jostle/src/test/java/org/openssl/jostle/test/rsa/RSATest.java

# Scan a directory.
python3 .claude/skills/audit-test-coverage/scripts/audit-test-coverage.py \
    jostle/src/test/java/org/openssl/jostle/test/crypto
```

Exit code is 0 when nothing is flagged, 1 when at least one finding exists. Suitable for CI gating once the test tree is fully clean.

The default scan path covers `jostle/src/test/java/org/openssl/jostle/test/` AND `jostle/src/test/java25/org/openssl/jostle/test/`, and automatically excludes `*LimitTest.java`, `*OpsTest.java`, and `*IntegrationTest.java` since those test categories intentionally use specific fixed values.

## What the script flags

Two finding types:

1. **RANDOM** — a test method body contains a hardcoded literal (`"...".getBytes()`, 1-3 `Hex.decode(...)` calls, or `new byte[]{<literal-bytes>}`) AND a roundtrip primitive (`Cipher.getInstance`, `Signature.getInstance`, `MessageDigest.getInstance`, etc.), AND either no SecureRandom-style source or a strong `"...".getBytes()` literal signal. Reported as `RANDOM  <file>:<lineno>  <test-name>  [primitive]`.
2. **NEGATIVE** — a file contains roundtrip tests for a primitive but no obvious negative-path coverage anywhere in the file (no `assertFalse(verify…)`, no `assertNotEquals`, no `tampered` / `vandalised` / `wrongKey` markers, no `BadPaddingException` catches). Reported as `NEGATIVE  <file>  primitive: <name>`.

The two checks are independent — a file can have a negative-path gap without any random-input gap, and vice versa.

## What the script ignores

False positives are an explicit non-goal: the script over-reports for the strong cases and aggressively skips for known false positives. The exclusion list:

1. **Excluded file suffixes** — `*LimitTest.java`, `*OpsTest.java`, `*IntegrationTest.java`. These test categories intentionally use fixed values (boundary probes, fault-injection setups, ordered scenarios).
2. **Excluded test-name patterns** — methods named `*Throws*`, `*WithoutInit*`, `*WrongClass*`, `*Reject*`, `*Invalid*`, `*Fails*`, `*Destroy*`, `*Vector*`, `*KAT*`, `*Known*`, `*Empty*`, `*Alias*`, `*MidStream*`, `*AfterReset*`, etc. These are error-path / state-machine / KAT / equivalence tests where fixed inputs are correct.
3. **KAT-style assertion shapes** — bodies containing `assertArrayEquals(Hex.decode("..."), ...)` or `assertEquals("<hex>", Hex.toHexString(...))` are treated as KAT and not flagged.
4. **Error-path catch blocks** — bodies containing `catch (IllegalStateException …)`, `catch (BadPaddingException …)`, `catch (CloneNotSupportedException …)`, `assertThrows(InvalidKeyException, …)`, etc. are skipped since they're already negative-path tests.
5. **Multiple Hex.decode pairs** — when a method contains ≥4 `Hex.decode(...)` calls, it's recognised as a KAT-style multi-vector test.

## Interpreting findings

Each finding needs human triage. Common scenarios:

1. **Real RANDOM gap** — the test uses a literal where a `SecureRandom` would be straightforward. Fix: derive each input via `nextBytes` / `KeyGenerator` / `KeyPairGenerator`. The canonical pattern is `seededRandom(testName)` (see `DESedeAgreementTest`) — logs the seed so a flake can be reproduced.
2. **Real NEGATIVE gap** — the file has positive roundtrips but no tampering / wrong-key / distinct-input differentiator. Fix: add at least one test that proves the operation transforms its input. Pattern references:
   1. **Block cipher** — `DESedeAgreementTest.testTamperedCiphertext_doesNotRoundTrip`, `testTamperedPadding_rejectsAtDoFinal`.
   2. **Signature** — `ECDSATest.testEcdsa_TamperedMessage_doesNotVerify`, `RSATest.testPkcs1_VandalisedSignatureFails`.
   3. **AEAD** — `AESAgreementTest.aesGCMSpread` (flip `josteCT[0] ^= 1`, expect `AEADBadTagException`).
   4. **KDF / Digest** — `KDF(salt1) != KDF(salt2)`, `digest(m1) != digest(m2)` differentiator (see `MDTest.testDistinctInputsProduceDistinctDigests`, `PBKdf2Test.testInputsActuallyInfluenceDerivedKey`).
3. **False positive (KAT)** — the test pins a published vector. Suppress by:
   - Renaming the test to include `Vector`, `KAT`, or `Known` in the name.
   - Or assert against a `Hex.decode("...")` constant so the KAT-style detection fires.
4. **False positive (state-machine / error-path)** — the test exercises an error transition. Suppress by:
   - Renaming the test to include `Throws`, `WithoutInit`, `WrongClass`, `Reject`, `Invalid`, or `Fails`.
   - Or adding a `catch` block on an error exception type (`IllegalStateException`, etc.) — the script picks that up.

## Fix recipes

### Fix a RANDOM gap

Replace hardcoded literals with random buffers. Two patterns:

```java
// Class-level helper, modelled on DESedeAgreementTest.
private static final SecureRandom RANDOM = new SecureRandom();

private static SecureRandom seededRandom(String testName) throws Exception
{
    long seed = RANDOM.nextLong();
    System.out.println(testName + " seed=" + seed);
    SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
    sr.setSeed(seed);
    return sr;
}

@Test
public void someRoundtripTest() throws Exception
{
    SecureRandom sr = seededRandom("someRoundtripTest");
    // Random content AND random length per CLAUDE.md "Random message
    // content AND length".
    byte[] msg = new byte[16 + sr.nextInt(256)];
    sr.nextBytes(msg);
    // ... rest of the test
}
```

If the test only needs a quick random buffer and the file already has a class-level `secRand` / `random`, just use `secRand.nextBytes(msg)`. Pin the seed only when reproducibility matters (the seeded pattern is the gold standard).

### Fix a NEGATIVE gap

Add one new `@Test` method to the file proving the operation transforms its input. The smallest useful additions:

```java
@Test
public void testTamperedCiphertext_doesNotRoundTrip() throws Exception
{
    // ... random key, IV, message via SecureRandom ...
    byte[] ct = encrypt(...);
    byte[] tampered = ct.clone();
    tampered[16] ^= (byte) 0x01;
    byte[] decoded = decrypt(tampered);
    Assertions.assertFalse(Arrays.areEqual(msg, decoded),
            "tampered ciphertext must not roundtrip");
}
```

For signatures, KDFs, digests, MACs — the same idea adapted to the primitive's failure mode. See `RSATest`, `ECDSATest`, `MLDSATest`, `MDTest`, `PBKdf2Test` for canonical examples.

## Limitations

1. **Heuristic — not a parser.** The script reads Java source as text and matches patterns; it doesn't understand control flow, scope, or types. A test that looks like a roundtrip but isn't (e.g. iterates over a hardcoded vector list) may be flagged, and vice versa.
2. **File-level negative-path check is coarse.** The script checks whether ANY negative-path marker exists anywhere in the file — it doesn't verify per-primitive coverage. A file with one tampering test for AES-CBC but a roundtrip-only test for AES-GCM will pass the check, even though the GCM tampering is the higher-value test. Manual review still matters for files with multiple primitives.
3. **Skip-list maintenance.** When a new test-name idiom appears that should be skipped (e.g. a new error-path test suffix), add the lowercase fragment to `SKIP_TEST_NAME_HINTS` near the top of the script.
4. **No suggestion of WHICH input is hardcoded.** The script flags the test method but doesn't pinpoint which line contains the literal. Use `grep -n '\".*\.getBytes\\|Hex\.decode\|new byte\\[\\]\s*{' <file>` to locate the literal once the test name is known.
5. **No cross-file KAT-vector-table recognition.** A file whose KAT vectors live in an inner static class (e.g. `private static final Object[][] VECTORS = ...`) referenced from a single `@Test` method may still be flagged as a hardcoded-literal gap. Rename the test to include `Vector` / `KAT` to suppress.

## Reference

`scripts/audit-test-coverage.py` is self-documenting. The pattern lists at the top of the file (`ROUNDTRIP_PATTERNS`, `RANDOM_INPUT_PATTERNS`, `HARDCODED_LITERAL_PATTERNS`, `NEGATIVE_PATH_PATTERNS`, `SKIP_TEST_NAME_HINTS`, `ERROR_PATH_CATCH_PATTERNS`, `KAT_ASSERTION_PATTERNS`) are the curated catalogues — extend them as new test idioms enter the codebase.
