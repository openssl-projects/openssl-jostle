/*
 *
 *   Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *   Licensed under the Apache License 2.0 (the "License"). You may not use
 *   this file except in compliance with the License.  You can obtain a copy
 *   in the file LICENSE in the source distribution or at
 *   https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;

/**
 * {@code MessageDigest.clone()} and {@code Mac.clone()} must produce an
 * independent continuation of the original's in-progress state.
 *
 * <p>Two properties, and the second is the one a weak test misses:
 *
 * <ol>
 *   <li><b>The clone carries state.</b> Fed the same remaining bytes, original
 *       and clone must agree with each other AND with a reference
 *       implementation over the whole message. A test that only checks
 *       {@code clone()} does not throw would pass for a hollow clone — which,
 *       for a native-backed digest or MAC, is worse than throwing, because it
 *       yields silently wrong output instead of a clear failure.</li>
 *   <li><b>The clone is independent.</b> Fed DIFFERENT remaining bytes, the two
 *       must diverge, and each must equal the reference over its own whole
 *       message. This is what proves the native contexts are separate rather
 *       than one shared context being written twice.</li>
 * </ol>
 *
 * <p>Both are exercised through a second clone taken from the first, since a
 * copy-of-a-copy is where a shallow implementation tends to alias.
 */
public class CloneStateTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    private static final String[] DIGESTS = {"SHA-1", "SHA-256", "SHA-512", "SHA3-256"};
    private static final String[] MACS = {"HmacSHA1", "HmacSHA256", "HmacSHA512"};

    private static final SecureRandom RANDOM = new SecureRandom();

    private static SecureRandom seededRandom(String testName) throws Exception
    {
        long seed = RANDOM.nextLong();
        System.out.println(testName + " seed=" + seed);
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        sr.setSeed(seed);
        return sr;
    }

    @BeforeAll
    static void before()
    {
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    /**
     * Digest clone continues the original: same remainder gives the same result,
     * and both match BouncyCastle over the whole message.
     */
    @Test
    public void digestCloneContinuesSameState() throws Exception
    {
        SecureRandom sr = seededRandom("digestCloneContinuesSameState");

        for (String alg : DIGESTS)
        {
            byte[] head = new byte[1 + sr.nextInt(200)];
            byte[] tail = new byte[1 + sr.nextInt(200)];
            sr.nextBytes(head);
            sr.nextBytes(tail);

            MessageDigest original = MessageDigest.getInstance(alg, JSL);
            original.update(head);

            MessageDigest clone = (MessageDigest) original.clone();

            original.update(tail);
            clone.update(tail);

            byte[] fromOriginal = original.digest();
            byte[] fromClone = clone.digest();
            Assertions.assertTrue(Arrays.areEqual(fromOriginal, fromClone),
                    alg + ": clone diverged from its source on identical input");

            // Reference: BC over head||tail. Proves the clone carried the
            // absorbed bytes rather than starting from empty.
            MessageDigest ref = MessageDigest.getInstance(alg, BC);
            ref.update(head);
            ref.update(tail);
            Assertions.assertTrue(Arrays.areEqual(ref.digest(), fromClone),
                    alg + ": clone did not carry the absorbed state");
        }
    }

    /**
     * Digest clones are independent: a second clone fed different bytes must
     * produce a different result, each matching the reference for its own
     * message. Divergence is what distinguishes two contexts from one aliased
     * context.
     */
    @Test
    public void digestClonesAreIndependentAndDiverge() throws Exception
    {
        SecureRandom sr = seededRandom("digestClonesAreIndependentAndDiverge");

        for (String alg : DIGESTS)
        {
            byte[] head = new byte[1 + sr.nextInt(200)];
            byte[] tailA = new byte[1 + sr.nextInt(200)];
            byte[] tailB = new byte[1 + sr.nextInt(200)];
            sr.nextBytes(head);
            sr.nextBytes(tailA);
            sr.nextBytes(tailB);
            // Guarantee the two remainders differ, so divergence is required
            // rather than merely likely.
            tailB[0] = (byte) (tailA[0] ^ 0x01);

            MessageDigest original = MessageDigest.getInstance(alg, JSL);
            original.update(head);

            MessageDigest first = (MessageDigest) original.clone();
            // Clone of a clone: where a shallow copy tends to alias.
            MessageDigest second = (MessageDigest) first.clone();

            first.update(tailA);
            second.update(tailB);

            byte[] a = first.digest();
            byte[] b = second.digest();
            Assertions.assertFalse(Arrays.areEqual(a, b),
                    alg + ": clones fed different data produced the same digest");

            MessageDigest refA = MessageDigest.getInstance(alg, BC);
            refA.update(head);
            refA.update(tailA);
            Assertions.assertTrue(Arrays.areEqual(refA.digest(), a),
                    alg + ": first clone's result is wrong for its own message");

            MessageDigest refB = MessageDigest.getInstance(alg, BC);
            refB.update(head);
            refB.update(tailB);
            Assertions.assertTrue(Arrays.areEqual(refB.digest(), b),
                    alg + ": second clone's result is wrong for its own message");

            // The source must still be usable and unaffected by either clone.
            original.update(tailA);
            Assertions.assertTrue(Arrays.areEqual(a, original.digest()),
                    alg + ": the source was disturbed by cloning");
        }
    }

    /**
     * MAC clone continues the original, including the key: same remainder gives
     * the same tag, matching BouncyCastle over the whole message.
     */
    @Test
    public void macCloneContinuesSameState() throws Exception
    {
        SecureRandom sr = seededRandom("macCloneContinuesSameState");

        for (String alg : MACS)
        {
            byte[] keyBytes = new byte[1 + sr.nextInt(64)];
            sr.nextBytes(keyBytes);
            SecretKeySpec key = new SecretKeySpec(keyBytes, alg);
            byte[] head = new byte[1 + sr.nextInt(200)];
            byte[] tail = new byte[1 + sr.nextInt(200)];
            sr.nextBytes(head);
            sr.nextBytes(tail);

            Mac original = Mac.getInstance(alg, JSL);
            original.init(key);
            original.update(head);

            Mac clone = (Mac) original.clone();

            original.update(tail);
            clone.update(tail);

            byte[] fromOriginal = original.doFinal();
            byte[] fromClone = clone.doFinal();
            Assertions.assertTrue(Arrays.areEqual(fromOriginal, fromClone),
                    alg + ": clone diverged from its source on identical input");

            Mac ref = Mac.getInstance(alg, BC);
            ref.init(key);
            ref.update(head);
            ref.update(tail);
            Assertions.assertTrue(Arrays.areEqual(ref.doFinal(), fromClone),
                    alg + ": clone did not carry the absorbed state and key");
        }
    }

    /**
     * MAC clones are independent: a second clone fed different bytes must
     * produce a different tag, each matching the reference for its own message.
     */
    @Test
    public void macClonesAreIndependentAndDiverge() throws Exception
    {
        SecureRandom sr = seededRandom("macClonesAreIndependentAndDiverge");

        for (String alg : MACS)
        {
            byte[] keyBytes = new byte[1 + sr.nextInt(64)];
            sr.nextBytes(keyBytes);
            SecretKeySpec key = new SecretKeySpec(keyBytes, alg);
            byte[] head = new byte[1 + sr.nextInt(200)];
            byte[] tailA = new byte[1 + sr.nextInt(200)];
            byte[] tailB = new byte[1 + sr.nextInt(200)];
            sr.nextBytes(head);
            sr.nextBytes(tailA);
            sr.nextBytes(tailB);
            tailB[0] = (byte) (tailA[0] ^ 0x01);

            Mac original = Mac.getInstance(alg, JSL);
            original.init(key);
            original.update(head);

            Mac first = (Mac) original.clone();
            Mac second = (Mac) first.clone();

            first.update(tailA);
            second.update(tailB);

            byte[] a = first.doFinal();
            byte[] b = second.doFinal();
            Assertions.assertFalse(Arrays.areEqual(a, b),
                    alg + ": clones fed different data produced the same tag");

            Mac refA = Mac.getInstance(alg, BC);
            refA.init(key);
            refA.update(head);
            refA.update(tailA);
            Assertions.assertTrue(Arrays.areEqual(refA.doFinal(), a),
                    alg + ": first clone's tag is wrong for its own message");

            Mac refB = Mac.getInstance(alg, BC);
            refB.init(key);
            refB.update(head);
            refB.update(tailB);
            Assertions.assertTrue(Arrays.areEqual(refB.doFinal(), b),
                    alg + ": second clone's tag is wrong for its own message");

            original.update(tailA);
            Assertions.assertTrue(Arrays.areEqual(a, original.doFinal()),
                    alg + ": the source was disturbed by cloning");
        }
    }

    /**
     * A clone taken before any update starts from the same empty state, and a
     * clone taken after doFinal is usable — doFinal resets the source, so the
     * clone must reflect whatever state existed at the moment of the copy.
     */
    @Test
    public void macCloneAtStateBoundaries() throws Exception
    {
        SecureRandom sr = seededRandom("macCloneAtStateBoundaries");

        byte[] keyBytes = new byte[32];
        sr.nextBytes(keyBytes);
        SecretKeySpec key = new SecretKeySpec(keyBytes, "HmacSHA256");
        byte[] msg = new byte[1 + sr.nextInt(200)];
        sr.nextBytes(msg);

        // Clone before any update: both must equal the MAC of the whole message.
        Mac fresh = Mac.getInstance("HmacSHA256", JSL);
        fresh.init(key);
        Mac freshClone = (Mac) fresh.clone();
        fresh.update(msg);
        freshClone.update(msg);
        Assertions.assertTrue(Arrays.areEqual(fresh.doFinal(), freshClone.doFinal()),
                "clone taken before update diverged");

        // Clone after doFinal (which resets): the clone must also be reusable.
        Mac used = Mac.getInstance("HmacSHA256", JSL);
        used.init(key);
        used.update(msg);
        used.doFinal();
        Mac afterFinal = (Mac) used.clone();
        afterFinal.update(msg);
        Mac ref = Mac.getInstance("HmacSHA256", BC);
        ref.init(key);
        ref.update(msg);
        Assertions.assertTrue(Arrays.areEqual(ref.doFinal(), afterFinal.doFinal()),
                "clone taken after doFinal did not behave as a reset context");
    }
}
