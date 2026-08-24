/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.fips;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Set;
import java.util.TreeSet;

/**
 * Cross-provider agreement for the FIPS provider's MAC surface.
 * <p>
 * This is the MAC analogue of {@link FIPSAESAgreementTest}: every approved MAC
 * that {@code ProvFIPSMac} registers (HMAC over the approved SHA-1 / SHA-2 /
 * SHA-3 digests, and AES-CMAC) is exercised three ways in the same JVM,
 * comparing the FIPS provider (JSLFIPS) against BOTH the non-FIPS provider
 * (JSL) AND BouncyCastle (BC). MAC output is deterministic given a
 * (key, message) pair, so the strongest possible check applies: the tag must
 * be byte-identical across all three providers — a differentiator a stubbed
 * or wrong-but-self-consistent implementation cannot satisfy against two
 * independent references.
 * <p>
 * For each algorithm and several random (key, message) pairs spanning the
 * block boundaries:
 * <ol>
 *   <li>the one-shot MAC agrees JSLFIPS vs JSL and JSLFIPS vs BC;</li>
 *   <li>the JSLFIPS and reference streaming paths (byte-by-byte and
 *       random-split {@code update}) agree with the one-shot MAC; and</li>
 *   <li>the negative path holds — a one-byte message change and a different
 *       key each change the MAC.</li>
 * </ol>
 * Keys are raw bytes via {@link SecretKeySpec} (MACs have no key-isolation
 * concern). Inputs (keys, message content and length) are drawn from a
 * per-test SHA1PRNG whose seed is logged, so a flaky run is reproducible (per
 * CLAUDE.md).
 * <p>
 * Gated on {@code TEST_FIPS_LIB}; skipped when unset.
 */
public class FIPSMacAgreementTest
{
    private static final String FIPS = JostleFIPSProvider.PROVIDER_NAME;
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    // HMAC over the approved SHA-1 / SHA-2 digests -- names mirror ProvFIPSMac
    // and are registered identically by JSL and BC.
    private static final String[] HMAC_SHA1_SHA2 = {
            "HMACSHA1", "HMACSHA224", "HMACSHA256", "HMACSHA384", "HMACSHA512",
            "HMACSHA512/224", "HMACSHA512/256"
    };

    // HMAC over the approved SHA-3 digests.
    private static final String[] HMAC_SHA3 = {
            "HMACSHA3-224", "HMACSHA3-256", "HMACSHA3-384", "HMACSHA3-512"
    };

    // The cipher-backed MACs, and the variable-length ones. Named rather than
    // inline so everyRegisteredMacIsCovered can account for them.
    private static final String[] CIPHER_BACKED = {"AESCMAC", "AESGMAC"};
    private static final String[] KMAC = {"KMAC128", "KMAC256"};

    // Message lengths straddling the 16 (CMAC) / 64 (SHA-256) / 128 (SHA-512)
    // byte block boundaries; the trailing entry is replaced per trial with a
    // random length.
    private static final int[] LENGTHS = {0, 1, 15, 16, 17, 31, 63, 64, 65, 127, 128, 129, 256, 1000};

    private static final SecureRandom RANDOM = new SecureRandom();

    private static SecureRandom seededRandom(String testName) throws Exception
    {
        long seed = RANDOM.nextLong();
        System.out.println(testName + " seed=" + seed);
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        sr.setSeed(seed);
        return sr;
    }

    /**
     * Class-level gate: the whole class skips when TEST_FIPS_LIB is unset.
     * Gating here rather than per test method fails closed, so a test added
     * later is gated automatically.
     */
    @BeforeAll
    static void before()
    {
        ensureProviders();
    }

    private static void ensureProviders()
    {
        FIPSTestUtil.assumeFipsProvider();
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * A random key sized for the algorithm: AES-CMAC needs a 16/24/32-byte AES
     * key; HMAC accepts any size at or above
     * {@link FIPSTestUtil#HMAC_MIN_KEY_BYTES}.
     */
    private static SecretKey randomKey(String name, SecureRandom sr)
    {
        if (name.equals("AESCMAC"))
        {
            int size = new int[]{16, 24, 32}[sr.nextInt(3)];
            byte[] keyBytes = new byte[size];
            sr.nextBytes(keyBytes);
            return new SecretKeySpec(keyBytes, "AES");
        }
        else
        {
            byte[] keyBytes = new byte[FIPSTestUtil.HMAC_MIN_KEY_BYTES + sr.nextInt(51)];
            sr.nextBytes(keyBytes);
            return new SecretKeySpec(keyBytes, name);
        }
    }

    private static byte[] macOneShot(String name, String provider, SecretKey key, byte[] msg) throws Exception
    {
        Mac mac = Mac.getInstance(name, provider);
        mac.init(key);
        return mac.doFinal(msg);
    }

    private static byte[] macByteWise(String name, String provider, SecretKey key, byte[] msg) throws Exception
    {
        Mac mac = Mac.getInstance(name, provider);
        mac.init(key);
        for (byte b : msg)
        {
            mac.update(b);
        }
        return mac.doFinal();
    }

    private static byte[] macRandomSplit(String name, String provider, SecretKey key, byte[] msg, SecureRandom sr) throws Exception
    {
        Mac mac = Mac.getInstance(name, provider);
        mac.init(key);
        int offset = 0;
        while (offset < msg.length)
        {
            int chunk = Math.min(1 + sr.nextInt(97), msg.length - offset);
            mac.update(msg, offset, chunk);
            offset += chunk;
        }
        return mac.doFinal();
    }

    /**
     * For one algorithm and one reference provider: over the length matrix,
     * assert the JSLFIPS one-shot MAC is byte-identical to the reference
     * one-shot MAC, and that both providers' streaming paths agree with it.
     */
    private void crossMac(String name, String ref, SecureRandom sr) throws Exception
    {
        for (int i = 0; i < LENGTHS.length; i++)
        {
            int len = (i == LENGTHS.length - 1) ? 512 + sr.nextInt(2048) : LENGTHS[i];

            SecretKey key = randomKey(name, sr);
            byte[] msg = new byte[len];
            sr.nextBytes(msg);

            String tag = name + " len=" + len + " ref=" + ref;

            byte[] fips = macOneShot(name, FIPS, key, msg);

            // Agreement: the reference one-shot MAC must equal JSLFIPS's.
            Assertions.assertArrayEquals(fips, macOneShot(name, ref, key, msg),
                    tag + ": one-shot JSLFIPS vs " + ref);

            // Chunking: JSLFIPS streaming paths agree with JSLFIPS one-shot ...
            Assertions.assertArrayEquals(fips, macByteWise(name, FIPS, key, msg),
                    tag + ": JSLFIPS byte-wise");
            Assertions.assertArrayEquals(fips, macRandomSplit(name, FIPS, key, msg, sr),
                    tag + ": JSLFIPS random-split");

            // ... and the reference's streaming path agrees with it too.
            Assertions.assertArrayEquals(fips, macRandomSplit(name, ref, key, msg, sr),
                    tag + ": " + ref + " random-split");
        }
    }

    /**
     * Negative path: prove the MAC actually depends on its inputs. A one-byte
     * message change and a different key must each change the JSLFIPS MAC.
     */
    private void differentiators(String name, SecureRandom sr) throws Exception
    {
        SecretKey key = randomKey(name, sr);
        byte[] msg = new byte[1 + sr.nextInt(1024)];
        sr.nextBytes(msg);

        byte[] base = macOneShot(name, FIPS, key, msg);

        // A single-byte change in the message must change the MAC.
        byte[] tampered = Arrays.clone(msg);
        int pos = sr.nextInt(tampered.length);
        tampered[pos] ^= (byte) (1 + sr.nextInt(255));
        Assertions.assertFalse(Arrays.areEqual(base, macOneShot(name, FIPS, key, tampered)),
                name + ": tampered message produced identical MAC");

        // A different key must change the MAC.
        SecretKey otherKey = randomKey(name, sr);
        Assertions.assertFalse(Arrays.areEqual(base, macOneShot(name, FIPS, otherKey, msg)),
                name + ": different key produced identical MAC");
    }

    private void runFamily(String[] names, SecureRandom sr) throws Exception
    {
        for (String name : names)
        {
            crossMac(name, JSL, sr);
            crossMac(name, BC, sr);
            differentiators(name, sr);
        }
    }

    /**
     * Completeness guard: every Mac JSLFIPS registers must be covered by one of
     * the agreement tests in this class.
     * <p>
     * The base twin {@code MacAgreementTest} cannot forget a MAC, because it
     * DISCOVERS its algorithm list from {@code provider.getServices()}. This
     * class uses hand-written arrays instead, so it can — and it did: KMAC was
     * registered in both providers and swept into the base agreement
     * automatically while the FIPS side silently had no streaming agreement
     * coverage at all. That is the exact failure this guard exists to make
     * impossible, and it is the FIPS analogue of
     * {@code MacAgreementTest.everyRegisteredMacIsCovered}.
     * <p>
     * Deliberately a coverage check rather than a re-write to discovery: the
     * per-family tests differ in key type and reference, so the arrays earn
     * their place — what was missing was anything that noticed a gap in them.
     */
    @Test
    public void everyRegisteredMacIsCovered()
    {
        Provider provider = FIPSTestUtil.assumeFipsProvider();

        Set<String> covered = new TreeSet<String>();
        covered.addAll(java.util.Arrays.asList(HMAC_SHA1_SHA2));
        covered.addAll(java.util.Arrays.asList(HMAC_SHA3));
        covered.addAll(java.util.Arrays.asList(CIPHER_BACKED));
        covered.addAll(java.util.Arrays.asList(KMAC));

        Set<String> registered = new TreeSet<String>();
        for (Provider.Service service : provider.getServices())
        {
            if ("Mac".equals(service.getType()))
            {
                registered.add(service.getAlgorithm());
            }
        }
        Assertions.assertFalse(registered.isEmpty(), "JSLFIPS registered no Mac services");

        Set<String> uncovered = new TreeSet<String>(registered);
        uncovered.removeAll(covered);
        Assertions.assertTrue(uncovered.isEmpty(),
                "JSLFIPS registers Mac services with no agreement coverage in this class: "
                        + uncovered + "\nAdd them to a runFamily group — registration without "
                        + "agreement testing is exactly how KMAC shipped one-shot-only.");

        // And the reverse, so a rename leaves a dead entry rather than silently
        // testing nothing.
        Set<String> stale = new TreeSet<String>(covered);
        stale.removeAll(registered);
        Assertions.assertTrue(stale.isEmpty(),
                "this class names Mac services JSLFIPS does not register: " + stale);
    }

    @Test
    public void hmacSha1AndSha2Agree() throws Exception
    {
        SecureRandom sr = seededRandom("hmacSha1AndSha2Agree");
        runFamily(HMAC_SHA1_SHA2, sr);
    }

    @Test
    public void hmacSha3Agree() throws Exception
    {
        SecureRandom sr = seededRandom("hmacSha3Agree");
        runFamily(HMAC_SHA3, sr);
    }

    @Test
    public void aesCmacAgrees() throws Exception
    {
        SecureRandom sr = seededRandom("aesCmacAgrees");
        runFamily(new String[]{"AESCMAC"}, sr);
    }

    /**
     * AES-GMAC across all three providers.
     * <p>
     * GMAC needs a nonce, so it does not fit {@link #runFamily}'s
     * {@code init(key)} shape and gets its own driver. Everything else is the
     * same contract: the tag must be byte-identical JSLFIPS vs JSL and JSLFIPS
     * vs BC, over random keys, random (legal) IV lengths and the length matrix,
     * with the streaming paths agreeing with the one-shot on both sides.
     * <p>
     * Registered unconditionally — {@code EVP_MAC_fetch("GMAC")} succeeds under
     * {@code fips=yes} on both supported modules
     * ({@code fips-c-review/probes/gmac_probe.c} Q1) — so there is no
     * capability branch here, unlike XDH or Ed.
     */
    /**
     * KMAC128 / KMAC256 at their DEFAULT parameters, which is what
     * {@code init(key)} with no spec selects: an empty customisation string and
     * the algorithm's own output length.
     * <p>
     * FIPSKMACTest already compares JSLFIPS against BC over the parameterised
     * surface, but only one-shot. This adds the streaming half — byte-wise and
     * random-split against both JSL and BC — because the FIPS side runs a
     * different interface library against a different lib ctx, so its buffering
     * is not covered by the base provider's chunking tests.
     * <p>
     * No spec is passed on purpose: {@code crossMac} drives every MAC through
     * one {@code init(key)} path, and KMAC's defaults are exactly what a caller
     * who supplies no spec must get.
     */
    @Test
    public void kmacAgrees() throws Exception
    {
        runFamily(KMAC, seededRandom("kmacAgrees"));
    }

    @Test
    public void aesGmacAgrees() throws Exception
    {
        SecureRandom sr = seededRandom("aesGmacAgrees");
        int[] ivLengths = {1, 8, 11, 12, 13, 16, 32};

        for (String name : new String[]{"AESGMAC", "AES-GMAC"})
        {
            for (int i = 0; i < LENGTHS.length; i++)
            {
                int len = (i == LENGTHS.length - 1) ? 512 + sr.nextInt(2048) : LENGTHS[i];

                byte[] keyBytes = new byte[new int[]{16, 24, 32}[sr.nextInt(3)]];
                sr.nextBytes(keyBytes);
                SecretKey key = new SecretKeySpec(keyBytes, "AES");

                byte[] iv = new byte[ivLengths[sr.nextInt(ivLengths.length)]];
                sr.nextBytes(iv);
                IvParameterSpec spec = new IvParameterSpec(iv);

                byte[] msg = new byte[len];
                sr.nextBytes(msg);

                String tag = name + " keyLen=" + keyBytes.length + " ivLen=" + iv.length
                        + " msgLen=" + len;

                byte[] fips = gmacOneShot(name, FIPS, key, spec, msg);
                Assertions.assertEquals(16, fips.length, tag + ": tag length");

                Assertions.assertArrayEquals(fips, gmacOneShot(name, JSL, key, spec, msg),
                        tag + ": one-shot JSLFIPS vs JSL");
                Assertions.assertArrayEquals(fips, gmacOneShot(name, BC, key, spec, msg),
                        tag + ": one-shot JSLFIPS vs BC");
                Assertions.assertArrayEquals(fips, gmacSplit(name, FIPS, key, spec, msg, sr),
                        tag + ": JSLFIPS random-split");
                Assertions.assertArrayEquals(fips, gmacSplit(name, BC, key, spec, msg, sr),
                        tag + ": BC random-split vs JSLFIPS one-shot");
            }
        }

        // Differentiators: the tag must depend on the message, the key AND the
        // nonce. Without the last one an implementation that dropped the IV
        // would still agree with nothing, but one that mishandled it silently
        // could still pass every equality check above with a fixed IV.
        byte[] keyBytes = new byte[16];
        sr.nextBytes(keyBytes);
        SecretKey key = new SecretKeySpec(keyBytes, "AES");
        byte[] iv = new byte[12];
        sr.nextBytes(iv);
        byte[] msg = new byte[1 + sr.nextInt(512)];
        sr.nextBytes(msg);

        byte[] base = gmacOneShot("AESGMAC", FIPS, key, new IvParameterSpec(iv), msg);

        byte[] tampered = Arrays.clone(msg);
        tampered[sr.nextInt(tampered.length)] ^= (byte) (1 + sr.nextInt(255));
        Assertions.assertFalse(Arrays.areEqual(base,
                        gmacOneShot("AESGMAC", FIPS, key, new IvParameterSpec(iv), tampered)),
                "GMAC: tampered message produced an identical tag");

        byte[] iv2 = Arrays.clone(iv);
        iv2[sr.nextInt(iv2.length)] ^= (byte) 0x01;
        Assertions.assertFalse(Arrays.areEqual(base,
                        gmacOneShot("AESGMAC", FIPS, key, new IvParameterSpec(iv2), msg)),
                "GMAC: a one-bit IV change produced an identical tag");

        byte[] otherKey = new byte[16];
        sr.nextBytes(otherKey);
        Assertions.assertFalse(Arrays.areEqual(base,
                        gmacOneShot("AESGMAC", FIPS, new SecretKeySpec(otherKey, "AES"),
                                new IvParameterSpec(iv), msg)),
                "GMAC: a different key produced an identical tag");
    }

    /**
     * {@code Mac.clone()} over GMAC is the one place the two supported modules
     * DISAGREE, so this asserts the CONTRACT rather than either module's answer.
     * <p>
     * Measured ({@code fips-c-review/probes/gmac_probe.c} Q4): 3.1.2 refuses
     * {@code EVP_MAC_CTX_dup} for GMAC with "not able to copy ctx" while
     * serving the MAC itself perfectly, and 3.5.7 allows it. The refusal is
     * GMAC-specific — HMAC and CMAC dup fine on both, which the control below
     * pins so a module that lost cloning wholesale cannot pass as "3.1.2".
     * <p>
     * Both branches are real requirements. Where dup works, the clone must
     * CONTINUE the absorbed state (compared against an independent BC MAC over
     * the whole message — divergence is not continuation). Where it does not,
     * the failure must arrive as {@code CloneNotSupportedException}, the
     * JCE-declared answer, and NOT as a native runtime exception escaping
     * {@code clone()}.
     */
    @Test
    public void gmacCloneFollowsTheModulesCapability() throws Exception
    {
        SecureRandom sr = seededRandom("gmacCloneFollowsTheModulesCapability");

        byte[] keyBytes = new byte[16];
        sr.nextBytes(keyBytes);
        SecretKey key = new SecretKeySpec(keyBytes, "AES");
        byte[] iv = new byte[12];
        sr.nextBytes(iv);
        IvParameterSpec spec = new IvParameterSpec(iv);
        byte[] msg = new byte[128];
        sr.nextBytes(msg);
        int split = 37;

        // CONTROL first: HMAC must clone on every supported module. If this
        // fails, a CloneNotSupportedException below is not the GMAC-specific
        // refusal this test is about.
        Mac hmacSrc = Mac.getInstance("HMACSHA256", FIPS);
        hmacSrc.init(new SecretKeySpec(keyBytes, "HMACSHA256"));
        hmacSrc.update(msg, 0, split);
        Mac hmacCopy = (Mac) hmacSrc.clone();
        hmacCopy.update(msg, split, msg.length - split);
        Assertions.assertArrayEquals(
                macOneShot("HMACSHA256", BC, new SecretKeySpec(keyBytes, "HMACSHA256"), msg),
                hmacCopy.doFinal(),
                "the HMAC clone control failed — this module cannot clone ANY mac, so the "
                        + "GMAC branch below would be measuring the wrong thing");

        Mac source = Mac.getInstance("AESGMAC", FIPS);
        source.init(key, spec);
        source.update(msg, 0, split);

        Mac copy;
        try
        {
            copy = (Mac) source.clone();
        }
        catch (CloneNotSupportedException e)
        {
            // 3.1.2 branch. Pin the message, and prove the refusal is confined
            // to cloning: the source MAC must still finish correctly.
            Assertions.assertEquals("unable to clone mac", e.getMessage());
            source.update(msg, split, msg.length - split);
            Assertions.assertArrayEquals(
                    gmacOneShot("AESGMAC", BC, key, spec, msg), source.doFinal(),
                    "the module refused to clone GMAC and also disturbed the source");
            return;
        }

        // 3.5.7 branch: the clone must CONTINUE, judged against BC over the
        // whole message — a hollow clone diverges from the source but cannot
        // match this.
        copy.update(msg, split, msg.length - split);
        Assertions.assertArrayEquals(gmacOneShot("AESGMAC", BC, key, spec, msg), copy.doFinal(),
                "the GMAC clone did not continue the absorbed state");

        // ... and the source is independent of it.
        source.update(msg, split, msg.length - split);
        Assertions.assertArrayEquals(gmacOneShot("AESGMAC", BC, key, spec, msg), source.doFinal(),
                "the source was disturbed by cloning");
    }

    private static byte[] gmacOneShot(String name, String provider, SecretKey key,
                                      IvParameterSpec spec, byte[] msg) throws Exception
    {
        Mac mac = Mac.getInstance(name, provider);
        mac.init(key, spec);
        return mac.doFinal(msg);
    }

    private static byte[] gmacSplit(String name, String provider, SecretKey key,
                                    IvParameterSpec spec, byte[] msg, SecureRandom sr) throws Exception
    {
        Mac mac = Mac.getInstance(name, provider);
        mac.init(key, spec);
        int offset = 0;
        while (offset < msg.length)
        {
            int chunk = Math.min(1 + sr.nextInt(97), msg.length - offset);
            mac.update(msg, offset, chunk);
            offset += chunk;
        }
        return mac.doFinal();
    }
}
