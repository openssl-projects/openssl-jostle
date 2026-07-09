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
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.security.Security;

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
     * key; HMAC accepts any reasonable size.
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
            byte[] keyBytes = new byte[1 + sr.nextInt(64)];
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

    @Test
    public void hmacSha1AndSha2Agree() throws Exception
    {
        ensureProviders();
        SecureRandom sr = seededRandom("hmacSha1AndSha2Agree");
        runFamily(HMAC_SHA1_SHA2, sr);
    }

    @Test
    public void hmacSha3Agree() throws Exception
    {
        ensureProviders();
        SecureRandom sr = seededRandom("hmacSha3Agree");
        runFamily(HMAC_SHA3, sr);
    }

    @Test
    public void aesCmacAgrees() throws Exception
    {
        ensureProviders();
        SecureRandom sr = seededRandom("aesCmacAgrees");
        runFamily(new String[]{"AESCMAC"}, sr);
    }
}
