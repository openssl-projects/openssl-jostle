/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.md;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.util.Arrays;

import java.security.MessageDigest;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * Cross-provider agreement for the WHOLE base-provider ({@code JSL})
 * MessageDigest surface, against BouncyCastle.
 * <p>
 * Non-FIPS counterpart of {@link
 * org.openssl.jostle.test.fips.FIPSMDAgreementTest}, over a strictly wider
 * set: everything JSLFIPS serves plus MD5, MD5-SHA1, SM3, BLAKE2s-256,
 * BLAKE2b-512 and RIPEMD-160, which have no FIPS-side test at all.
 * <p>
 * <b>Breadth, not depth.</b> One shape — one-shot digest of a random message
 * over every registered name, with a differentiator. Chunking, clone/reset,
 * XOF length contracts and alias resolution stay in {@link MDTest} and
 * {@link ShakeFixedLengthTest}, which keep their own BC comparisons.
 * <p>
 * A digest is a deterministic function of its input, so byte-equality against
 * an independent implementation is the strongest available check.
 * <p>
 * <b>Interop reference order</b> (CLAUDE.md): BC's JCE surface where BC
 * registers the algorithm — twenty of the twenty-one — otherwise the
 * specification's own construction over an independent implementation.
 * {@code MD5-SHA1} is the exception; see {@link #NO_BC_JCE_NAME}.
 * <p>
 * Inputs come from a per-test SHA1PRNG whose seed is logged.
 */
public class MDAgreementTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    /**
     * Every registered digest BouncyCastle also serves, mapped to BC's
     * spelling. Transcribed, not derived: no rule survives {@code SHAKE-128}
     * becoming {@code SHAKE128} while {@code SHAKE128-256} is spelled
     * identically. {@link #everyRegisteredMessageDigestIsCovered()} is what
     * keeps the map honest.
     */
    private static final Map<String, String> BC_NAME = new LinkedHashMap<String, String>();

    static
    {
        BC_NAME.put("SHA1", "SHA-1");
        BC_NAME.put("SHA2-224", "SHA-224");
        BC_NAME.put("SHA2-256", "SHA-256");
        BC_NAME.put("SHA2-384", "SHA-384");
        BC_NAME.put("SHA2-512", "SHA-512");
        BC_NAME.put("SHA2-512/224", "SHA-512/224");
        BC_NAME.put("SHA2-512/256", "SHA-512/256");
        BC_NAME.put("SHA3-224", "SHA3-224");
        BC_NAME.put("SHA3-256", "SHA3-256");
        BC_NAME.put("SHA3-384", "SHA3-384");
        BC_NAME.put("SHA3-512", "SHA3-512");
        BC_NAME.put("SHAKE-128", "SHAKE128");
        BC_NAME.put("SHAKE-256", "SHAKE256");
        BC_NAME.put("SHAKE128-256", "SHAKE128-256");
        BC_NAME.put("SHAKE256-512", "SHAKE256-512");
        BC_NAME.put("BLAKE2S-256", "BLAKE2S-256");
        BC_NAME.put("BLAKE2B-512", "BLAKE2B-512");
        BC_NAME.put("SM3", "SM3");
        BC_NAME.put("MD5", "MD5");
        BC_NAME.put("RIPEMD-160", "RIPEMD160");
    }

    /**
     * The one registered digest BouncyCastle does not expose through the JCE.
     * Compared instead against its own definition — the TLS 1.0/1.1
     * concatenation {@code MD5(m) || SHA1(m)}, 36 bytes — over BC's
     * primitives. Named so the completeness guard reads it as a decision
     * rather than an unexplained gap.
     */
    private static final String NO_BC_JCE_NAME = "MD5-SHA1";

    /** Trials per registered name — one random input probes one point only. */
    private static final int TRIALS = 5;

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

    /** Every MessageDigest primary the base provider registers, sorted. */
    private static Set<String> registeredDigests()
    {
        Provider provider = Security.getProvider(JSL);
        Assertions.assertNotNull(provider, "JSL provider is not registered");

        Set<String> names = new TreeSet<String>();
        for (Provider.Service service : provider.getServices())
        {
            if ("MessageDigest".equals(service.getType()))
            {
                names.add(service.getAlgorithm());
            }
        }
        Assertions.assertFalse(names.isEmpty(), "JSL registered no MessageDigest services");
        return names;
    }

    private static byte[] randomMessage(SecureRandom sr)
    {
        byte[] message = new byte[1 + sr.nextInt(4096)];
        sr.nextBytes(message);
        return message;
    }

    /**
     * {@code MD5(m) || SHA1(m)}, 36 bytes, over BC's primitives — an
     * independent implementation, not a second call into Jostle.
     */
    private static byte[] md5Sha1Reference(byte[] message) throws Exception
    {
        byte[] md5 = MessageDigest.getInstance("MD5", BC).digest(message);
        byte[] sha1 = MessageDigest.getInstance("SHA-1", BC).digest(message);
        return Arrays.concatenate(md5, sha1);
    }

    /**
     * Completeness guard, both directions: every registered MessageDigest must
     * appear in a coverage group, and every name this class claims to cover
     * must still be registered — so a rename leaves a dead entry rather than
     * silently testing nothing.
     * <p>
     * Not interchangeable with the FIPS half's guard: that one reads JSLFIPS's
     * registered set, and the six base-only digests are invisible to it.
     */
    @Test
    public void everyRegisteredMessageDigestIsCovered()
    {
        Set<String> covered = new TreeSet<String>(BC_NAME.keySet());
        covered.add(NO_BC_JCE_NAME);

        Set<String> registered = registeredDigests();

        Set<String> uncovered = new TreeSet<String>(registered);
        uncovered.removeAll(covered);
        Assertions.assertTrue(uncovered.isEmpty(),
                "JSL registers MessageDigest services with no agreement coverage in this class: "
                        + uncovered + "\nAdd each to BC_NAME with the name BouncyCastle knows it by, or "
                        + "— if BC does not register it — give it a reference built from the "
                        + "algorithm's own definition, as MD5-SHA1 has.");

        Set<String> stale = new TreeSet<String>(covered);
        stale.removeAll(registered);
        Assertions.assertTrue(stale.isEmpty(),
                "this class names MessageDigest services JSL does not register: " + stale);
    }

    /**
     * Byte-identical results for the same random input, over several trials of
     * varying length. Per-trial differentiator: a one-byte change must change
     * the digest, so an implementation ignoring part of its input cannot pass
     * by agreeing on one value.
     */
    @Test
    public void everyRegisteredDigestAgreesWithBouncyCastle() throws Exception
    {
        SecureRandom sr = seededRandom("everyRegisteredDigestAgreesWithBouncyCastle");

        for (Map.Entry<String, String> entry : BC_NAME.entrySet())
        {
            String name = entry.getKey();
            String bcName = entry.getValue();

            for (int t = 0; t < TRIALS; t++)
            {
                byte[] message = randomMessage(sr);

                byte[] jsl = MessageDigest.getInstance(name, JSL).digest(message);
                byte[] bc = MessageDigest.getInstance(bcName, BC).digest(message);
                Assertions.assertArrayEquals(bc, jsl, name + " vs BC " + bcName);

                byte[] tampered = message.clone();
                tampered[sr.nextInt(tampered.length)] ^= (byte) (1 + sr.nextInt(255));
                Assertions.assertFalse(
                        Arrays.areEqual(jsl, MessageDigest.getInstance(name, JSL).digest(tampered)),
                        name + ": a one-byte change to the message left the digest unchanged");
            }
        }
    }

    /**
     * {@code MD5-SHA1} against its own definition, since BC has no such JCE
     * name. The length assertion rules out a truncation to the MD5 half alone;
     * the differentiator is the sweep's.
     */
    @Test
    public void md5Sha1AgreesWithItsSpecifiedConstruction() throws Exception
    {
        SecureRandom sr = seededRandom("md5Sha1AgreesWithItsSpecifiedConstruction");

        for (int t = 0; t < TRIALS; t++)
        {
            byte[] message = randomMessage(sr);

            byte[] jsl = MessageDigest.getInstance(NO_BC_JCE_NAME, JSL).digest(message);
            Assertions.assertEquals(36, jsl.length, "MD5-SHA1 must be MD5(16) || SHA1(20)");
            Assertions.assertArrayEquals(md5Sha1Reference(message), jsl,
                    "MD5-SHA1 vs its MD5 || SHA1 definition over BouncyCastle primitives");

            byte[] tampered = message.clone();
            tampered[sr.nextInt(tampered.length)] ^= (byte) (1 + sr.nextInt(255));
            Assertions.assertFalse(
                    Arrays.areEqual(jsl, MessageDigest.getInstance(NO_BC_JCE_NAME, JSL).digest(tampered)),
                    "MD5-SHA1: a one-byte change to the message left the digest unchanged");
        }
    }

    /**
     * Distinct inputs must produce distinct digests, across the whole
     * registered set rather than only the names BC serves — the differentiator
     * a fixed output buffer fails.
     */
    @Test
    public void distinctInputsProduceDistinctDigests() throws Exception
    {
        SecureRandom sr = seededRandom("distinctInputsProduceDistinctDigests");

        for (String name : registeredDigests())
        {
            byte[] a = randomMessage(sr);
            byte[] b = randomMessage(sr);

            byte[] digestA = MessageDigest.getInstance(name, JSL).digest(a);
            byte[] digestB = MessageDigest.getInstance(name, JSL).digest(b);
            Assertions.assertFalse(Arrays.areEqual(digestA, digestB),
                    name + ": distinct inputs produced identical digests");
        }
    }
}
