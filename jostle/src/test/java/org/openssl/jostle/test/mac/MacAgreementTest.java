/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.mac;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.List;
import java.util.TreeSet;

/**
 * Cross-provider agreement for the WHOLE base-provider ({@code JSL}) MAC
 * surface, against BouncyCastle.
 * <p>
 * This is the non-FIPS counterpart of {@link
 * org.openssl.jostle.test.fips.FIPSMacAgreementTest}, and it covers a strictly
 * wider set: everything JSLFIPS serves plus the MACs the FIPS module does not
 * (Poly1305, and HMAC over MD5, MD5-SHA1, SM3 and RIPEMD-160). A MAC that only
 * the base provider registers has no FIPS-side test at all, so without this
 * file its only cross-implementation check was whatever {@link MacTest}
 * happened to cover.
 * <p>
 * A MAC tag is a deterministic function of (key, message) — and of the nonce
 * too, for GMAC — so byte-equality against an independent implementation is
 * the strongest available check: a stub, a truncation, or a wrong-but-
 * self-consistent native path cannot match BouncyCastle's answer.
 * <p>
 * <b>The algorithm list is discovered, not transcribed.</b> It comes from
 * {@code provider.getServices()}, so a MAC registered later is swept in
 * automatically rather than silently going untested — the failure mode a
 * hand-written list has. {@link #everyRegisteredMacIsCovered()} makes that
 * explicit: it fails if any registered Mac is neither compared against BC's
 * JCE nor against a named lightweight reference.
 * <p>
 * <b>Interop reference order</b> (CLAUDE.md): BC's JCE surface where it
 * registers the algorithm — which is all but one of them — otherwise BC's
 * lightweight API driven directly. {@code HMACMD5SHA1} is the exception: BC
 * registers no such JCE name, so the reference is BC's {@code HMac} over a
 * test-local {@link MD5SHA1Digest} built from BC's own {@code MD5Digest} and
 * {@code SHA1Digest} per the algorithm's definition. A missing BC JCE name is
 * not a reason to skip agreement testing.
 * <p>
 * Inputs (keys, IVs, message content and length) come from a per-test SHA1PRNG
 * whose seed is logged, so a flaky run is reproducible.
 */
public class MacAgreementTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    /**
     * The one registered MAC BouncyCastle does not expose through the JCE, so
     * the sweep compares it against a lightweight reference instead. Kept as a
     * named constant so {@link #everyRegisteredMacIsCovered()} can account for
     * it rather than treating it as an unexplained gap.
     */
    private static final String NO_BC_JCE_NAME = "HMACMD5SHA1";

    /** Message lengths straddling the 16 / 64 / 128-byte block boundaries. */
    private static final int[] LENGTHS = {0, 1, 15, 16, 17, 31, 63, 64, 65, 127, 128, 129, 256, 1000};

    private static final SecureRandom RANDOM = new SecureRandom();

    @BeforeAll
    static void before()
    {
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

    /** Every Mac primary the base provider registers, sorted. */
    private static List<String> registeredMacs()
    {
        Provider provider = Security.getProvider(JSL);
        TreeSet<String> names = new TreeSet<String>();
        for (Provider.Service s : provider.getServices())
        {
            if ("Mac".equals(s.getType()))
            {
                names.add(s.getAlgorithm());
            }
        }
        Assertions.assertFalse(names.isEmpty(), "the provider registered no Mac services");
        return new ArrayList<String>(names);
    }

    /**
     * A random key sized for the algorithm. CMAC and GMAC take an AES key
     * (16/24/32); Poly1305 takes exactly 32; HMAC takes any length.
     */
    private static SecretKey randomKey(String name, SecureRandom sr)
    {
        if (name.contains("CMAC") || name.contains("GMAC"))
        {
            byte[] k = new byte[new int[]{16, 24, 32}[sr.nextInt(3)]];
            sr.nextBytes(k);
            return new SecretKeySpec(k, "AES");
        }
        if (name.equals("POLY1305"))
        {
            byte[] k = new byte[32];
            sr.nextBytes(k);
            return new SecretKeySpec(k, "POLY1305");
        }
        byte[] k = new byte[14 + sr.nextInt(51)];
        sr.nextBytes(k);
        return new SecretKeySpec(k, name);
    }

    /** GMAC is the only registered MAC that needs a parameter spec. */
    private static AlgorithmParameterSpec specFor(String name, SecureRandom sr)
    {
        if (!name.contains("GMAC"))
        {
            return null;
        }
        byte[] iv = new byte[new int[]{1, 8, 11, 12, 13, 16, 32}[sr.nextInt(7)]];
        sr.nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    private static byte[] oneShot(String name, String provider, SecretKey key,
                                  AlgorithmParameterSpec spec, byte[] msg) throws Exception
    {
        Mac mac = Mac.getInstance(name, provider);
        mac.init(key, spec);
        return mac.doFinal(msg);
    }

    private static byte[] byteWise(String name, String provider, SecretKey key,
                                   AlgorithmParameterSpec spec, byte[] msg) throws Exception
    {
        Mac mac = Mac.getInstance(name, provider);
        mac.init(key, spec);
        for (byte b : msg)
        {
            mac.update(b);
        }
        return mac.doFinal();
    }

    private static byte[] randomSplit(String name, String provider, SecretKey key,
                                      AlgorithmParameterSpec spec, byte[] msg,
                                      SecureRandom sr) throws Exception
    {
        Mac mac = Mac.getInstance(name, provider);
        mac.init(key, spec);
        int offset = 0;
        while (offset < msg.length)
        {
            int take = Math.min(1 + sr.nextInt(97), msg.length - offset);
            mac.update(msg, offset, take);
            offset += take;
        }
        return mac.doFinal();
    }

    /**
     * The core sweep: for every registered MAC that BC also exposes through the
     * JCE, over the length matrix, the Jostle tag must equal BouncyCastle's
     * byte for byte — and both providers' streaming paths must agree with it.
     * <p>
     * Both streaming directions are covered deliberately: Jostle chunked
     * against BC one-shot catches a buffering bug on our side, and BC chunked
     * against Jostle one-shot catches one on theirs (or, more usefully, tells
     * a future reader which side moved when the two stop agreeing).
     */
    @Test
    public void everyRegisteredMacAgreesWithBouncyCastle() throws Exception
    {
        SecureRandom sr = seededRandom("everyRegisteredMacAgreesWithBouncyCastle");
        int compared = 0;

        for (String name : registeredMacs())
        {
            if (name.equals(NO_BC_JCE_NAME))
            {
                continue;   // covered by hmacMd5Sha1AgreesWithBcLightweight
            }

            for (int i = 0; i < LENGTHS.length; i++)
            {
                int len = (i == LENGTHS.length - 1) ? 512 + sr.nextInt(2048) : LENGTHS[i];

                SecretKey key = randomKey(name, sr);
                AlgorithmParameterSpec spec = specFor(name, sr);
                byte[] msg = new byte[len];
                sr.nextBytes(msg);

                String tag = name + " keyLen=" + key.getEncoded().length + " msgLen=" + len;

                byte[] jostle = oneShot(name, JSL, key, spec, msg);
                Assertions.assertTrue(jostle.length > 0, tag + ": empty tag");

                Assertions.assertArrayEquals(jostle, oneShot(name, BC, key, spec, msg),
                        tag + ": one-shot JSL vs BC");
                Assertions.assertArrayEquals(jostle, byteWise(name, JSL, key, spec, msg),
                        tag + ": JSL byte-wise vs BC one-shot");
                Assertions.assertArrayEquals(jostle, randomSplit(name, JSL, key, spec, msg, sr),
                        tag + ": JSL random-split");
                Assertions.assertArrayEquals(jostle, randomSplit(name, BC, key, spec, msg, sr),
                        tag + ": BC random-split vs JSL one-shot");
            }
            compared++;
        }

        // Guard against the sweep going vacuous — a provider-discovery change
        // that returned nothing would otherwise "pass".
        Assertions.assertTrue(compared >= 15,
                "only " + compared + " MACs were compared against BC; the sweep has lost coverage");
    }

    /**
     * {@code HMACMD5SHA1} against a BouncyCastle LIGHTWEIGHT reference.
     * <p>
     * BC registers no JCE name for it, so per the interop-reference order the
     * fallback is BC's own primitives driven directly: {@code HMac} over the
     * MD5‖SHA-1 concatenated digest that OpenSSL calls {@code MD5-SHA1} (the
     * TLS 1.0/1.1 PRF hash). Composing the reference from the other side's
     * primitives keeps this a genuine cross-implementation check rather than a
     * comparison of Jostle with itself.
     */
    @Test
    public void hmacMd5Sha1AgreesWithBcLightweight() throws Exception
    {
        SecureRandom sr = seededRandom("hmacMd5Sha1AgreesWithBcLightweight");

        for (int i = 0; i < LENGTHS.length; i++)
        {
            int len = (i == LENGTHS.length - 1) ? 512 + sr.nextInt(2048) : LENGTHS[i];

            byte[] keyBytes = new byte[14 + sr.nextInt(51)];
            sr.nextBytes(keyBytes);
            byte[] msg = new byte[len];
            sr.nextBytes(msg);

            String tag = NO_BC_JCE_NAME + " keyLen=" + keyBytes.length + " msgLen=" + len;
            SecretKey key = new SecretKeySpec(keyBytes, NO_BC_JCE_NAME);

            byte[] expected = bcLightweightHmacMd5Sha1(keyBytes, msg);
            Assertions.assertEquals(36, expected.length,
                    "MD5-SHA1 is a 36-byte concatenated digest");

            byte[] jostle = oneShot(NO_BC_JCE_NAME, JSL, key, null, msg);
            Assertions.assertArrayEquals(expected, jostle, tag + ": one-shot vs BC lightweight");
            Assertions.assertArrayEquals(expected, byteWise(NO_BC_JCE_NAME, JSL, key, null, msg),
                    tag + ": byte-wise");
            Assertions.assertArrayEquals(expected,
                    randomSplit(NO_BC_JCE_NAME, JSL, key, null, msg, sr), tag + ": random-split");
        }

        // Differentiators — without these an implementation ignoring part of
        // its input could still match on the cases above by coincidence of
        // construction.
        byte[] keyBytes = new byte[32];
        byte[] msg = new byte[200];
        sr.nextBytes(keyBytes);
        sr.nextBytes(msg);
        SecretKey key = new SecretKeySpec(keyBytes, NO_BC_JCE_NAME);
        byte[] base = oneShot(NO_BC_JCE_NAME, JSL, key, null, msg);

        byte[] tampered = Arrays.clone(msg);
        tampered[sr.nextInt(tampered.length)] ^= (byte) (1 + sr.nextInt(255));
        Assertions.assertFalse(Arrays.areEqual(base, oneShot(NO_BC_JCE_NAME, JSL, key, null, tampered)),
                NO_BC_JCE_NAME + ": tampered message produced an identical tag");

        byte[] otherKey = new byte[32];
        sr.nextBytes(otherKey);
        Assertions.assertFalse(Arrays.areEqual(base,
                        oneShot(NO_BC_JCE_NAME, JSL, new SecretKeySpec(otherKey, NO_BC_JCE_NAME), null, msg)),
                NO_BC_JCE_NAME + ": a different key produced an identical tag");
    }

    /**
     * Negative path for the whole surface: the tag must depend on the message
     * and on the key. A roundtrip-shaped agreement test alone would accept an
     * implementation that hashed only a prefix of its input.
     */
    @Test
    public void tamperedMessageAndWrongKeyChangeEveryTag() throws Exception
    {
        SecureRandom sr = seededRandom("tamperedMessageAndWrongKeyChangeEveryTag");

        for (String name : registeredMacs())
        {
            SecretKey key = randomKey(name, sr);
            AlgorithmParameterSpec spec = specFor(name, sr);
            byte[] msg = new byte[1 + sr.nextInt(1024)];
            sr.nextBytes(msg);

            byte[] base = oneShot(name, JSL, key, spec, msg);

            byte[] tampered = Arrays.clone(msg);
            tampered[sr.nextInt(tampered.length)] ^= (byte) (1 + sr.nextInt(255));
            Assertions.assertFalse(Arrays.areEqual(base, oneShot(name, JSL, key, spec, tampered)),
                    name + ": tampered message produced an identical tag");

            // A change in the LAST byte specifically — catches an
            // implementation that drops a trailing partial block.
            byte[] lastChanged = Arrays.clone(msg);
            lastChanged[lastChanged.length - 1] ^= (byte) 0x80;
            Assertions.assertFalse(Arrays.areEqual(base, oneShot(name, JSL, key, spec, lastChanged)),
                    name + ": a change to the final byte produced an identical tag");

            SecretKey otherKey = randomKey(name, sr);
            Assertions.assertFalse(Arrays.areEqual(base, oneShot(name, JSL, otherKey, spec, msg)),
                    name + ": a different key produced an identical tag");
        }
    }

    /**
     * Reset and reuse across the whole surface: one instance driven twice must
     * give the right tag each time, and repeating an input must repeat the tag
     * exactly (every registered MAC is deterministic).
     */
    @Test
    public void resetAndReuseAgreesForEveryMac() throws Exception
    {
        SecureRandom sr = seededRandom("resetAndReuseAgreesForEveryMac");

        for (String name : registeredMacs())
        {
            SecretKey key = randomKey(name, sr);
            AlgorithmParameterSpec spec = specFor(name, sr);
            byte[] msgA = new byte[100];
            byte[] msgB = new byte[37];
            sr.nextBytes(msgA);
            sr.nextBytes(msgB);

            byte[] refA = referenceTag(name, key, spec, msgA);
            byte[] refB = referenceTag(name, key, spec, msgB);

            Mac mac = Mac.getInstance(name, JSL);
            mac.init(key, spec);

            Assertions.assertArrayEquals(refA, mac.doFinal(msgA), name + ": first message");
            Assertions.assertArrayEquals(refB, mac.doFinal(msgB),
                    name + ": second message after auto-reset");
            Assertions.assertArrayEquals(refA, mac.doFinal(msgA), name + ": repeat is deterministic");

            mac.update(msgB);
            mac.reset();
            Assertions.assertArrayEquals(refA, mac.doFinal(msgA),
                    name + ": after an explicit mid-message reset");
        }
    }

    /**
     * Coverage guard: every registered Mac must be reachable by one of the two
     * comparison routes above.
     * <p>
     * The sweep skips any name BC's JCE does not serve, which is correct — but
     * an unaccounted-for skip is exactly how a newly registered MAC would go
     * untested while the suite stayed green. This fails on any name that is
     * neither BC-servable nor the one documented lightweight exception.
     */
    @Test
    public void everyRegisteredMacIsCovered()
    {
        List<String> uncovered = new ArrayList<String>();

        for (String name : registeredMacs())
        {
            if (name.equals(NO_BC_JCE_NAME))
            {
                continue;
            }
            try
            {
                Mac.getInstance(name, BC);
            }
            catch (Exception e)
            {
                uncovered.add(name);
            }
        }

        Assertions.assertTrue(uncovered.isEmpty(),
                "registered MACs with no BouncyCastle JCE peer and no lightweight reference:\n  "
                        + String.join("\n  ", uncovered)
                        + "\nAdd a lightweight-API comparison for each (see "
                        + "hmacMd5Sha1AgreesWithBcLightweight) rather than leaving it untested.");
    }

    /** BC's answer where it has one; the lightweight reference otherwise. */
    private static byte[] referenceTag(String name, SecretKey key,
                                       AlgorithmParameterSpec spec, byte[] msg) throws Exception
    {
        if (name.equals(NO_BC_JCE_NAME))
        {
            return bcLightweightHmacMd5Sha1(key.getEncoded(), msg);
        }
        return oneShot(name, BC, key, spec, msg);
    }

    private static byte[] bcLightweightHmacMd5Sha1(byte[] key, byte[] msg)
    {
        HMac hmac = new HMac(new MD5SHA1Digest());
        hmac.init(new KeyParameter(key));
        hmac.update(msg, 0, msg.length);
        byte[] out = new byte[hmac.getMacSize()];
        hmac.doFinal(out, 0);
        return out;
    }

    /**
     * OpenSSL's {@code MD5-SHA1}: the 36-byte concatenation MD5(m)‖SHA-1(m),
     * used as the TLS 1.0/1.1 handshake hash. Built from BouncyCastle's own
     * {@code MD5Digest} and {@code SHA1Digest} so the reference is genuinely
     * independent of Jostle.
     * <p>
     * {@link ExtendedDigest} rather than plain {@link Digest} because
     * {@code HMac} reads {@code getByteLength()} to size its ipad/opad; both
     * constituent digests use a 64-byte block, which is the value OpenSSL
     * reports for the combined digest too.
     */
    private static final class MD5SHA1Digest implements ExtendedDigest
    {
        private final MD5Digest md5 = new MD5Digest();
        private final SHA1Digest sha1 = new SHA1Digest();

        @Override
        public String getAlgorithmName()
        {
            return "MD5-SHA1";
        }

        @Override
        public int getDigestSize()
        {
            return md5.getDigestSize() + sha1.getDigestSize();
        }

        @Override
        public int getByteLength()
        {
            return md5.getByteLength();
        }

        @Override
        public void update(byte in)
        {
            md5.update(in);
            sha1.update(in);
        }

        @Override
        public void update(byte[] in, int inOff, int len)
        {
            md5.update(in, inOff, len);
            sha1.update(in, inOff, len);
        }

        @Override
        public int doFinal(byte[] out, int outOff)
        {
            int written = md5.doFinal(out, outOff);
            written += sha1.doFinal(out, outOff + written);
            return written;
        }

        @Override
        public void reset()
        {
            md5.reset();
            sha1.reset();
        }
    }
}
