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

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;

/**
 * Mac through the FIPS provider ("JSLFIPS"): the approved HMACs and AES-CMAC
 * agree with the non-FIPS provider and BouncyCastle in the same JVM, MACs
 * differentiate on key and message changes, reuse behaves, and the
 * MACs the module does not serve are absent. Gated on TEST_FIPS_LIB; skipped when
 * unset.
 */
public class FIPSMacTest
{
    private static final SecureRandom RANDOM = new SecureRandom();

    // ProvFIPSMac's registrations; every name BC also registers, for
    // three-way agreement.
    private static final String[] APPROVED = {
            "HMACSHA1", "HMACSHA224", "HMACSHA256", "HMACSHA384", "HMACSHA512",
            "HMACSHA512/224", "HMACSHA512/256",
            "HMACSHA3-224", "HMACSHA3-256", "HMACSHA3-384", "HMACSHA3-512",
            "AESCMAC"
    };

    private static final String[] NOT_SERVED_BY_MODULE = {
            "POLY1305", "HMACMD5", "HMACSM3", "HMACRIPEMD160"
    };

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
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private static SecretKeySpec randomKey(String algorithm, int size)
    {
        byte[] keyBytes = new byte[size];
        RANDOM.nextBytes(keyBytes);
        return new SecretKeySpec(keyBytes, algorithm);
    }

    @Test
    public void approvedMacsAgreeAcrossProviders()
        throws Exception
    {
        for (String name : APPROVED)
        {
            for (int t = 0; t < 5; t++)
            {
                // CMAC requires an AES-sized key; HMAC takes any size at or
                // above the module's 112-bit floor (FIPSTestUtil.HMAC_MIN_KEY_BYTES).
                SecretKeySpec key = name.equals("AESCMAC")
                        ? randomKey("AES", new int[]{16, 24, 32}[RANDOM.nextInt(3)])
                        : randomKey(name, FIPSTestUtil.HMAC_MIN_KEY_BYTES + RANDOM.nextInt(51));
                byte[] message = new byte[1 + RANDOM.nextInt(1024)];
                RANDOM.nextBytes(message);

                Mac fips = Mac.getInstance(name, JostleFIPSProvider.PROVIDER_NAME);
                fips.init(key);
                byte[] tag = fips.doFinal(message);

                Mac jsl = Mac.getInstance(name, JostleProvider.PROVIDER_NAME);
                jsl.init(key);
                Assertions.assertArrayEquals(tag, jsl.doFinal(message), name + ": JSLFIPS vs JSL");

                Mac bc = Mac.getInstance(name, BouncyCastleProvider.PROVIDER_NAME);
                bc.init(key);
                Assertions.assertArrayEquals(tag, bc.doFinal(message), name + ": JSLFIPS vs BC");

                // Differentiators: a changed message and a changed key must
                // both change the MAC.
                byte[] tampered = message.clone();
                tampered[RANDOM.nextInt(tampered.length)] ^= (byte) (1 + RANDOM.nextInt(255));
                Mac fips2 = Mac.getInstance(name, JostleFIPSProvider.PROVIDER_NAME);
                fips2.init(key);
                Assertions.assertFalse(java.util.Arrays.equals(tag, fips2.doFinal(tampered)),
                        name + ": tampered message produced identical MAC");

                // Ensure the "different" key genuinely differs. At the 14-byte
                // floor a same-length redraw collides with negligible
                // probability, but the loop costs nothing and keeps the
                // differentiator sound if the floor ever drops again.
                SecretKeySpec otherKey;
                do
                {
                    otherKey = name.equals("AESCMAC")
                            ? randomKey("AES", key.getEncoded().length)
                            : randomKey(name, key.getEncoded().length);
                }
                while (java.util.Arrays.equals(key.getEncoded(), otherKey.getEncoded()));
                Mac fips3 = Mac.getInstance(name, JostleFIPSProvider.PROVIDER_NAME);
                fips3.init(otherKey);
                Assertions.assertFalse(java.util.Arrays.equals(tag, fips3.doFinal(message)),
                        name + ": different key produced identical MAC");
            }
        }
    }

    @Test
    public void chunkingAndReuse()
        throws Exception
    {
        SecretKeySpec key = randomKey("HMACSHA256", 32);
        byte[] message = new byte[257 + RANDOM.nextInt(1024)];
        RANDOM.nextBytes(message);

        Mac mac = Mac.getInstance("HMACSHA256", JostleFIPSProvider.PROVIDER_NAME);
        mac.init(key);
        byte[] expected = mac.doFinal(message);

        // Mac auto-resets after doFinal: same instance, same answer.
        mac.update(message);
        Assertions.assertArrayEquals(expected, mac.doFinal(), "reuse after doFinal");

        // Byte-wise and random-split chunking agree with one-shot.
        for (byte b : message)
        {
            mac.update(b);
        }
        Assertions.assertArrayEquals(expected, mac.doFinal(), "byte-wise");

        int offset = 0;
        while (offset < message.length)
        {
            int chunk = Math.min(1 + RANDOM.nextInt(97), message.length - offset);
            mac.update(message, offset, chunk);
            offset += chunk;
        }
        Assertions.assertArrayEquals(expected, mac.doFinal(), "random splits");
    }

    @Test
    public void aliasesResolve()
        throws Exception
    {
        SecretKeySpec key = randomKey("HMACSHA256", 32);
        byte[] message = new byte[64];
        RANDOM.nextBytes(message);

        Mac byName = Mac.getInstance("HMACSHA256", JostleFIPSProvider.PROVIDER_NAME);
        byName.init(key);
        Mac byAlias = Mac.getInstance("HMAC-SHA256", JostleFIPSProvider.PROVIDER_NAME);
        byAlias.init(key);
        Assertions.assertArrayEquals(byName.doFinal(message), byAlias.doFinal(message));
    }

    @Test
    public void macsNotServedByModuleRejected()
        throws Exception
    {
        for (String name : NOT_SERVED_BY_MODULE)
        {
            Assertions.assertThrows(NoSuchAlgorithmException.class,
                    () -> Mac.getInstance(name, JostleFIPSProvider.PROVIDER_NAME),
                    name + " must not resolve through JSLFIPS");
        }

        // ... while the non-FIPS provider still serves them in the same JVM.
        Assertions.assertNotNull(Mac.getInstance("POLY1305", JostleProvider.PROVIDER_NAME));
    }

    /**
     * getMacLength() reports the correct tag length for every approved MAC
     * before any doFinal, locking ProvFIPSMac's function-name-to-digest
     * mapping. A wrong-but-self-consistent tag would not reveal an
     * addMac(...) regression; the declared length would.
     */
    @Test
    public void getMacLengthPerApprovedAlgorithm()
        throws Exception
    {
        Object[][] expected = new Object[][]{
                {"HMACSHA1", 20},
                {"HMACSHA224", 28},
                {"HMACSHA256", 32},
                {"HMACSHA384", 48},
                {"HMACSHA512", 64},
                {"HMACSHA512/224", 28},
                {"HMACSHA512/256", 32},
                {"HMACSHA3-224", 28},
                {"HMACSHA3-256", 32},
                {"HMACSHA3-384", 48},
                {"HMACSHA3-512", 64},
                {"AESCMAC", 16},
        };

        for (Object[] row : expected)
        {
            String name = (String) row[0];
            int expectedLen = (Integer) row[1];
            Mac mac = Mac.getInstance(name, JostleFIPSProvider.PROVIDER_NAME);
            Assertions.assertEquals(expectedLen, mac.getMacLength(), "mac length for " + name);
        }
    }

    /**
     * An explicit Mac.reset() mid-stream discards the accumulated update
     * bytes while keeping the key: init(key), update(msg), reset(),
     * doFinal(msg) must equal a fresh JSLFIPS instance init(key).doFinal(msg).
     * chunkingAndReuse covers only the post-doFinal auto-reset.
     */
    @Test
    public void explicitResetDiscardsAccumulatedState()
        throws Exception
    {
        SecretKeySpec key = randomKey("HMACSHA256", 32);
        byte[] message = new byte[257 + RANDOM.nextInt(1024)];
        RANDOM.nextBytes(message);

        Mac mac = Mac.getInstance("HMACSHA256", JostleFIPSProvider.PROVIDER_NAME);
        mac.init(key);

        // Accumulate, explicitly reset, then compute the MAC of message.
        mac.update(message);
        mac.reset();
        byte[] afterReset = mac.doFinal(message);

        Mac fresh = Mac.getInstance("HMACSHA256", JostleFIPSProvider.PROVIDER_NAME);
        fresh.init(key);
        Assertions.assertArrayEquals(fresh.doFinal(message), afterReset);
    }

    /**
     * Mac.init(null) through the FIPS provider rejects with
     * InvalidKeyException("key is null") for the approved MACs, pinning the
     * JCE engineInit(Key) path and the fallback-driving exception type.
     */
    @Test
    public void initNullKeyThrowsInvalidKeyException()
        throws Exception
    {
        for (String name : new String[]{"HMACSHA256", "AESCMAC"})
        {
            Mac mac = Mac.getInstance(name, JostleFIPSProvider.PROVIDER_NAME);
            InvalidKeyException ex = Assertions.assertThrows(InvalidKeyException.class,
                    () -> mac.init(null), name);
            Assertions.assertEquals("key is null", ex.getMessage(), name);
        }
    }
}
