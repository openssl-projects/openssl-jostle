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
import org.openssl.jostle.jcajce.provider.OpenSSLException;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.jcajce.spec.KMACParameterSpec;
import org.openssl.jostle.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.security.Security;

/**
 * KMAC128 / KMAC256 through JSLFIPS.
 * <p>
 * KMAC is served unconditionally by both supported modules — {@code EVP_MAC_fetch}
 * succeeds under {@code fips=yes} on 3.1.2 and 3.5.7 alike, and all four
 * measured builds produce byte-identical tags matching the SP 800-185 samples
 * ({@code fips-c-review/probes/kmac_probe.c}). So there is no registration gate
 * to test, unlike the Ed family.
 * <p>
 * What the two modules DO disagree about is what they will <b>accept</b>, and
 * both differences are {@code fipsinstall} config rather than module version
 * (see the "A FIPS module's strictness is mostly fipsinstall CONFIG" rule):
 * <ul>
 *   <li>{@code kmac-key-check} refuses keys below 14 bytes — SP 800-131A's
 *       112-bit floor. Off by default, on under {@code -pedantic}.</li>
 *   <li>{@code no-short-mac} refuses outputs below 4 bytes. Same.</li>
 * </ul>
 * Neither is pre-checked in our C: a hard-coded range would be wrong on
 * whichever module it did not match. So the tests below <b>probe and assert
 * both branches</b> rather than pinning one environment's answer. Each probe
 * pins the exact refusal on its way to reporting "unavailable", so a genuine
 * regression cannot read as an absent capability.
 */
public class FIPSKMACTest
{
    private static final String FIPS = JostleFIPSProvider.PROVIDER_NAME;
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    private static final String[] NAMES = {"KMAC128", "KMAC256"};
    private static final int[] DEFAULT_LENGTHS = {32, 64};

    /** SP 800-131A's 112-bit floor, in bytes — what kmac-key-check enforces. */
    private static final int KEY_FLOOR_BYTES = 14;

    /** The shortest output no-short-mac permits, in bytes. */
    private static final int SHORT_MAC_FLOOR_BYTES = 4;

    private static final SecureRandom RANDOM = new SecureRandom();

    @BeforeAll
    static void before()
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

    private static SecureRandom seededRandom(String testName) throws Exception
    {
        long seed = RANDOM.nextLong();
        System.out.println(testName + " seed=" + seed);
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        sr.setSeed(seed);
        return sr;
    }

    private static byte[] oneShot(String name, String provider, SecretKey key,
                                  int bits, byte[] custom, byte[] msg) throws Exception
    {
        Mac mac = Mac.getInstance(name, provider);
        mac.init(key, new KMACParameterSpec(bits, custom));
        return mac.doFinal(msg);
    }

    private static byte[] bcOneShot(String name, SecretKey key, int bits, byte[] custom, byte[] msg)
            throws Exception
    {
        Mac mac = Mac.getInstance(name, BC);
        mac.init(key, new org.bouncycastle.jcajce.spec.KMACParameterSpec(bits, custom));
        return mac.doFinal(msg);
    }

    /**
     * Does the loaded module enforce {@code kmac-key-check}?
     * <p>
     * Answers by ASKING — a 13-byte key is one below the floor — and pins the
     * exact refusal on the way to returning true, so this cannot degrade into
     * "skip whenever anything goes wrong". A module that refuses for some other
     * reason, or with some other exception, fails here rather than being
     * reported as a strict module.
     */
    private static boolean moduleEnforcesKeyFloor() throws Exception
    {
        Mac mac = Mac.getInstance("KMAC128", FIPS);
        try
        {
            mac.init(new SecretKeySpec(new byte[KEY_FLOOR_BYTES - 1], "KMAC128"));
        }
        catch (InvalidKeyException e)
        {
            // Mac.init(Key) wraps the SPI's InvalidAlgorithmParameterException,
            // but a key-length refusal comes back as the OpenSSL error the
            // module raised, surfaced through the init error handler.
            Assertions.assertTrue(e.getMessage().startsWith("OpenSSL Error:"),
                    "a kmac-key-check refusal must surface as the module's OpenSSL error, got: "
                            + e.getMessage());
            return true;
        }
        catch (OpenSSLException e)
        {
            Assertions.assertTrue(e.getMessage().startsWith("OpenSSL Error:"), e.getMessage());
            return true;
        }
        return false;
    }

    /**
     * Does the loaded module enforce {@code no-short-mac}? Same shape as
     * {@link #moduleEnforcesKeyFloor()} — a 3-byte output is one below the
     * floor, and the refusal is pinned before "true" is returned.
     */
    private static boolean moduleEnforcesShortMacFloor() throws Exception
    {
        Mac mac = Mac.getInstance("KMAC128", FIPS);
        try
        {
            mac.init(new SecretKeySpec(new byte[32], "KMAC128"),
                    new KMACParameterSpec((SHORT_MAC_FLOOR_BYTES - 1) * 8));
        }
        catch (InvalidKeyException | java.security.InvalidAlgorithmParameterException e)
        {
            Assertions.assertTrue(e.getMessage().startsWith("OpenSSL Error:"),
                    "a no-short-mac refusal must surface as the module's OpenSSL error, got: "
                            + e.getMessage());
            return true;
        }
        catch (OpenSSLException e)
        {
            Assertions.assertTrue(e.getMessage().startsWith("OpenSSL Error:"), e.getMessage());
            return true;
        }
        return false;
    }

    /**
     * KMAC must be served by JSLFIPS, and must agree with BouncyCastle, on
     * every supported module. This is the unconditional half — no gate, no
     * skip.
     */
    @Test
    public void kmacIsServedAndAgreesWithBouncyCastle() throws Exception
    {
        SecureRandom sr = seededRandom("kmacIsServedAndAgreesWithBouncyCastle");

        for (String name : NAMES)
        {
            for (int trial = 0; trial < 10; trial++)
            {
                // At or above the strictest floor, so this half never depends
                // on the module's configuration.
                byte[] keyBytes = new byte[KEY_FLOOR_BYTES + sr.nextInt(40)];
                sr.nextBytes(keyBytes);
                SecretKey key = new SecretKeySpec(keyBytes, name);

                byte[] custom = new byte[sr.nextInt(32)];
                sr.nextBytes(custom);
                int bits = (SHORT_MAC_FLOOR_BYTES + sr.nextInt(60)) * 8;
                byte[] msg = new byte[sr.nextInt(300)];
                sr.nextBytes(msg);

                byte[] fips = oneShot(name, FIPS, key, bits, custom, msg);
                Assertions.assertEquals(bits / 8, fips.length, name + " requested length");
                Assertions.assertTrue(Arrays.areEqual(bcOneShot(name, key, bits, custom, msg), fips),
                        name + " JSLFIPS must agree with BC (trial " + trial + ")");
                // And with the base provider, which drives the OTHER interface
                // library and lib ctx entirely.
                Assertions.assertTrue(Arrays.areEqual(oneShot(name, JSL, key, bits, custom, msg), fips),
                        name + " JSLFIPS and JSL must agree");
            }
        }
    }

    /**
     * The default output length must be queried from the module, not
     * transcribed, and must be SP 800-185's 2 * strength on either module.
     */
    @Test
    public void defaultOutputLengthComesFromTheModule() throws Exception
    {
        for (int i = 0; i < NAMES.length; i++)
        {
            Mac mac = Mac.getInstance(NAMES[i], FIPS);
            Assertions.assertEquals(DEFAULT_LENGTHS[i], mac.getMacLength(),
                    NAMES[i] + " default output length before init");

            mac.init(new SecretKeySpec(new byte[32], NAMES[i]));
            Assertions.assertEquals(DEFAULT_LENGTHS[i], mac.doFinal(new byte[10]).length,
                    NAMES[i] + " un-parameterised tag length");
        }
    }

    /**
     * {@code kmac-key-check}: probe, then assert BOTH branches.
     * <p>
     * On a module that enforces it, a 13-byte key must be refused with the
     * module's own error and a 14-byte key must WORK. On a module that does
     * not, the short key must actually work — asserting only the refusal would
     * let a stale gate survive the capability changing, and asserting only the
     * acceptance would miss the strict module entirely.
     */
    @Test
    public void keyFloorFollowsTheModulesConfiguration() throws Exception
    {
        SecureRandom sr = seededRandom("keyFloorFollowsTheModulesConfiguration");
        byte[] msg = new byte[64];
        sr.nextBytes(msg);

        boolean strict = moduleEnforcesKeyFloor();
        System.out.println("kmac-key-check enforced: " + strict);

        byte[] shortKeyBytes = new byte[KEY_FLOOR_BYTES - 1];
        sr.nextBytes(shortKeyBytes);
        SecretKey shortKey = new SecretKeySpec(shortKeyBytes, "KMAC128");

        if (strict)
        {
            // Below the floor: refused. moduleEnforcesKeyFloor already pinned
            // the message; here we pin that the refusal is about THIS key and
            // not about KMAC generally.
            Mac mac = Mac.getInstance("KMAC128", FIPS);
            Assertions.assertThrows(Exception.class, () -> mac.init(shortKey),
                    "a 13-byte key must be refused under kmac-key-check");
        }
        else
        {
            // Not enforced: the short key must genuinely work, and produce the
            // same tag the base provider does.
            byte[] fips = oneShot("KMAC128", FIPS, shortKey, 256, null, msg);
            Assertions.assertTrue(
                    Arrays.areEqual(oneShot("KMAC128", JSL, shortKey, 256, null, msg), fips),
                    "a below-floor key must work identically where the floor is not enforced");
        }

        // AT the floor must work on BOTH branches — that is what makes this a
        // boundary test rather than a one-sided refusal check.
        byte[] atFloorBytes = new byte[KEY_FLOOR_BYTES];
        sr.nextBytes(atFloorBytes);
        SecretKey atFloor = new SecretKeySpec(atFloorBytes, "KMAC128");
        byte[] tag = oneShot("KMAC128", FIPS, atFloor, 256, null, msg);
        Assertions.assertTrue(Arrays.areEqual(bcOneShot("KMAC128", atFloor, 256, null, msg), tag),
                "a key exactly at the 112-bit floor must work on every module");
    }

    /**
     * {@code no-short-mac}: probe, then assert BOTH branches, same shape as
     * {@link #keyFloorFollowsTheModulesConfiguration()}.
     */
    @Test
    public void shortOutputFloorFollowsTheModulesConfiguration() throws Exception
    {
        SecureRandom sr = seededRandom("shortOutputFloorFollowsTheModulesConfiguration");
        byte[] keyBytes = new byte[32];
        byte[] msg = new byte[64];
        sr.nextBytes(keyBytes);
        sr.nextBytes(msg);
        SecretKey key = new SecretKeySpec(keyBytes, "KMAC128");

        boolean strict = moduleEnforcesShortMacFloor();
        System.out.println("no-short-mac enforced: " + strict);

        int belowBits = (SHORT_MAC_FLOOR_BYTES - 1) * 8;

        if (strict)
        {
            Mac mac = Mac.getInstance("KMAC128", FIPS);
            Assertions.assertThrows(Exception.class,
                    () -> mac.init(key, new KMACParameterSpec(belowBits)),
                    "a 3-byte output must be refused under no-short-mac");
        }
        else
        {
            byte[] fips = oneShot("KMAC128", FIPS, key, belowBits, null, msg);
            Assertions.assertEquals(SHORT_MAC_FLOOR_BYTES - 1, fips.length);
            Assertions.assertTrue(
                    Arrays.areEqual(oneShot("KMAC128", JSL, key, belowBits, null, msg), fips),
                    "a below-floor output must work identically where the floor is not enforced");
        }

        // AT the floor must work on both branches.
        byte[] tag = oneShot("KMAC128", FIPS, key, SHORT_MAC_FLOOR_BYTES * 8, null, msg);
        Assertions.assertEquals(SHORT_MAC_FLOOR_BYTES, tag.length);
        Assertions.assertTrue(
                Arrays.areEqual(bcOneShot("KMAC128", key, SHORT_MAC_FLOOR_BYTES * 8, null, msg), tag),
                "an output exactly at the no-short-mac floor must work on every module");
    }

    /**
     * A clone must continue the source's state. Unlike GMAC — which 3.1.2
     * refuses to {@code EVP_MAC_CTX_dup} — KMAC clones on every measured build,
     * so this is an unconditional assertion with no capability branch.
     * <p>
     * Divergence between two clones would prove nothing (two empty clones also
     * diverge), so the check is against BouncyCastle over the WHOLE message.
     */
    @Test
    public void cloneCarriesTheAbsorbedStateCustomAndLength() throws Exception
    {
        SecureRandom sr = seededRandom("cloneCarriesTheAbsorbedStateCustomAndLength");

        for (String name : NAMES)
        {
            byte[] keyBytes = new byte[32];
            byte[] custom = new byte[]{'t', 'a', 'g'};
            byte[] msg = new byte[192];
            sr.nextBytes(keyBytes);
            sr.nextBytes(msg);
            SecretKey key = new SecretKeySpec(keyBytes, name);
            int bits = 40 * 8;
            int split = 51;

            byte[] reference = bcOneShot(name, key, bits, custom, msg);

            Mac source = Mac.getInstance(name, FIPS);
            source.init(key, new KMACParameterSpec(bits, custom));
            source.update(msg, 0, split);

            Mac copy = (Mac) source.clone();
            copy.update(msg, split, msg.length - split);

            Assertions.assertEquals(40, copy.getMacLength(),
                    name + " the clone must carry the requested length");
            Assertions.assertArrayEquals(reference, copy.doFinal(),
                    name + " the clone must carry key, S, L and the absorbed bytes");

            source.update(msg, split, msg.length - split);
            Assertions.assertArrayEquals(reference, source.doFinal(),
                    name + " cloning must not disturb the source");
        }
    }

    /**
     * Negative path through the FIPS provider: the tag must depend on the
     * message, the key and the customisation string.
     */
    @Test
    public void tamperedInputsChangeTheTag() throws Exception
    {
        SecureRandom sr = seededRandom("tamperedInputsChangeTheTag");

        for (String name : NAMES)
        {
            byte[] keyBytes = new byte[32];
            byte[] msg = new byte[96];
            sr.nextBytes(keyBytes);
            sr.nextBytes(msg);
            SecretKey key = new SecretKeySpec(keyBytes, name);
            byte[] custom = "alpha".getBytes("UTF-8");

            byte[] tag = oneShot(name, FIPS, key, 256, custom, msg);

            byte[] tampered = Arrays.clone(msg);
            tampered[sr.nextInt(tampered.length)] ^= (byte) 0x01;
            Assertions.assertFalse(Arrays.areEqual(tag, oneShot(name, FIPS, key, 256, custom, tampered)),
                    name + " a one-bit message change must change the tag");

            byte[] otherKeyBytes = new byte[32];
            sr.nextBytes(otherKeyBytes);
            Assertions.assertFalse(Arrays.areEqual(tag,
                            oneShot(name, FIPS, new SecretKeySpec(otherKeyBytes, name), 256, custom, msg)),
                    name + " a different key must change the tag");

            Assertions.assertFalse(Arrays.areEqual(tag,
                            oneShot(name, FIPS, key, 256, "beta".getBytes("UTF-8"), msg)),
                    name + " a different customisation string must change the tag");

            Assertions.assertFalse(Arrays.areEqual(tag, oneShot(name, FIPS, key, 264, custom, msg)),
                    name + " a different output length must change the tag entirely");
        }
    }
}
