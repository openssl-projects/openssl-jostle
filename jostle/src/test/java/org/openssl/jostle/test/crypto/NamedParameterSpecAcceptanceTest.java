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
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.test.multirelease.MultiReleaseOverrides;
import org.openssl.jostle.util.Arrays;

import javax.crypto.KeyAgreement;
import java.lang.reflect.Constructor;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;

/**
 * MT-59: the matching {@code NamedParameterSpec} is ACCEPTED and yields a
 * WORKING key, on every JDK from 11 upward.
 *
 * <h2>This is a POSITIVE-PATH pin, and that is the whole point</h2>
 *
 * <p>MT-59 was a provider refusing input that both references accept. No
 * negative-path survey could see it: those measure what happens to BAD input,
 * and a valid spec is not a fault cell, so an over-refusal is invisible to the
 * entire instrument family by construction. It was found by code review after
 * roughly a thousand measured cells. Its guard therefore has to feed VALID
 * input and require success — a refusal-shaped test would reproduce the blind
 * spot that hid the defect.
 *
 * <p>Accepting is not enough either. A generator could accept the spec and
 * return a correctly-labelled dud, so each cell also OPERATES: the key is
 * encoded, decoded by another provider, and used — a signature verified or a
 * shared secret agreed. That is the {@code OperateCrossing} shape.
 *
 * <h2>Why it lives here and uses reflection</h2>
 *
 * <p>{@code NamedParameterSpec} is a Java 11 API, so this cannot be written
 * directly in {@code src/test/java}, which compiles at release 8. The
 * alternative — {@code src/test/javaN} — would need the file duplicated into
 * four source sets, and one of them does not run at all
 * (<b>MT-60</b>: {@code unitTest21} includes {@code test17}, not
 * {@code test21}). So the spec is built reflectively and the test self-skips
 * where the class is absent: ONE file, running on JDK 8, 11, 17, 21 and 25,
 * under both bridges.
 *
 * <p>That matters because the support is spread across THREE source sets:
 * {@code java11} for XDH, {@code java11} and {@code java15} for Edwards. JDK 17
 * and 21 are the load-bearing legs — they mix a {@code java11} XDH copy with a
 * {@code java15} Edwards copy, so a higher copy that silently dropped the
 * method shows up exactly there and nowhere else.
 */
public class NamedParameterSpecAcceptanceTest
{
    private static Provider jsl;
    private static Provider bc;
    private static Constructor<?> namedParameterSpec;

    @BeforeAll
    public static void setUp()
    {
        jsl = Security.getProvider(JostleProvider.PROVIDER_NAME);
        if (jsl == null)
        {
            jsl = new JostleProvider();
            Security.addProvider(jsl);
        }
        bc = Security.getProvider("BC");
        if (bc == null)
        {
            bc = new BouncyCastleProvider();
            Security.addProvider(bc);
        }
        try
        {
            namedParameterSpec = Class.forName("java.security.spec.NamedParameterSpec")
                    .getConstructor(String.class);
        }
        catch (Throwable preJava11)
        {
            namedParameterSpec = null;
        }
    }

    private static AlgorithmParameterSpec named(String name) throws Exception
    {
        return (AlgorithmParameterSpec) namedParameterSpec.newInstance(name);
    }

    /** Absent below JDK 11; the pin self-skips rather than failing there. */
    private static void requireNamedParameterSpec()
    {
        Assumptions.assumeTrue(namedParameterSpec != null,
                "NamedParameterSpec is a Java 11 API; nothing to pin on this JDK");
    }

    /**
     * Is the {@code java11}/{@code java15} copy the one LOADED?
     *
     * <p>Not the same as "does this JDK have NamedParameterSpec". The base
     * {@code :jostle:test} leg runs against class directories, so it loads the
     * Java 8 baseline on JDK 25 and the support is legitimately absent there.
     * Gating on API presence made this test FAIL on that leg while passing on
     * all five jar legs. See {@link MultiReleaseOverrides}.
     */
    private static boolean supportLoaded()
    {
        return MultiReleaseOverrides.overrideActive(
                org.openssl.jostle.jcajce.provider.xec.XECKeyPairGenerator.class,
                "java.security.spec.NamedParameterSpec");
    }

    /**
     * The matching spec is accepted AND the key works, cross-provider.
     *
     * <p>Ed25519/Ed448 sign here and verify there; X25519/X448 agree to an
     * identical secret. Both are things a dud key cannot fake.
     */
    @Test
    public void aMatchingNamedParameterSpecYieldsAWorkingKey() throws Exception
    {
        requireNamedParameterSpec();
        if (!supportLoaded())
        {
            // The baseline copy is loaded (class-directory classpath), so the
            // refusal is CORRECT here. Assert that branch rather than skipping:
            // a skip would let a genuinely broken baseline pass unnoticed.
            for (String alg : new String[]{"X25519", "X448", "Ed25519", "Ed448"})
            {
                final String a = alg;
                Assertions.assertThrows(java.security.InvalidAlgorithmParameterException.class,
                        () -> KeyPairGenerator.getInstance(a, jsl).initialize(named(a)),
                        a + ": the Java 8 baseline cannot reference NamedParameterSpec and "
                                + "must refuse it");
            }
            return;
        }
        List<String> failures = new ArrayList<String>();

        for (String alg : new String[]{"Ed25519", "Ed448"})
        {
            try
            {
                KeyPairGenerator g = KeyPairGenerator.getInstance(alg, jsl);
                g.initialize(named(alg));
                KeyPair kp = g.generateKeyPair();

                byte[] msg = new byte[64];
                new SecureRandom().nextBytes(msg);
                Signature s = Signature.getInstance(alg, jsl);
                s.initSign(kp.getPrivate());
                s.update(msg);
                byte[] sig = s.sign();

                KeyFactory kf = KeyFactory.getInstance(alg, bc);
                Signature v = Signature.getInstance(alg, bc);
                v.initVerify(kf.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded())));
                v.update(msg);
                if (!v.verify(sig))
                {
                    failures.add(alg + ": the other provider refused a signature from this key");
                }
                // The negative half, or "verified" proves nothing.
                msg[0] ^= (byte) 0x01;
                Signature v2 = Signature.getInstance(alg, bc);
                v2.initVerify(kf.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded())));
                v2.update(msg);
                if (v2.verify(sig))
                {
                    failures.add(alg + ": a tampered message verified - the check is vacuous");
                }
            }
            catch (Throwable t)
            {
                failures.add(alg + " -> " + t.getClass().getName()
                        + (t.getMessage() == null ? "" : ": " + t.getMessage()));
            }
        }

        for (String alg : new String[]{"X25519", "X448"})
        {
            try
            {
                KeyPairGenerator g = KeyPairGenerator.getInstance(alg, jsl);
                g.initialize(named(alg));
                KeyPair a = g.generateKeyPair();
                KeyPair b = g.generateKeyPair();

                KeyAgreement ours = KeyAgreement.getInstance(alg, jsl);
                ours.init(a.getPrivate());
                ours.doPhase(b.getPublic(), true);
                byte[] mine = ours.generateSecret();

                KeyFactory kf = KeyFactory.getInstance(alg, bc);
                KeyAgreement theirs = KeyAgreement.getInstance(alg, bc);
                theirs.init(kf.generatePrivate(new PKCS8EncodedKeySpec(b.getPrivate().getEncoded())));
                theirs.doPhase(kf.generatePublic(new X509EncodedKeySpec(a.getPublic().getEncoded())), true);
                byte[] other = theirs.generateSecret();

                if (!Arrays.areEqual(mine, other))
                {
                    failures.add(alg + ": the two providers derived different secrets");
                }
                boolean allZero = true;
                for (byte x : mine)
                {
                    allZero &= (x == 0);
                }
                if (allZero)
                {
                    failures.add(alg + ": derived secret is all zeros");
                }
            }
            catch (Throwable t)
            {
                failures.add(alg + " -> " + t.getClass().getName()
                        + (t.getMessage() == null ? "" : ": " + t.getMessage()));
            }
        }

        Assertions.assertTrue(failures.isEmpty(),
                "a matching NamedParameterSpec must be accepted and produce a working key: " + failures);
    }

    /**
     * A MISMATCHED spec is still refused, with the type the method declares.
     *
     * <p>Measured 2026-09-02: BouncyCastle raises
     * {@code InvalidAlgorithmParameterException} for all four; the JDK raises
     * it for Edwards but the UNCHECKED {@code InvalidParameterException} for
     * XDH - its own two generators disagree. The declared checked type settles
     * it, so the JDK's XDH answer is recorded as its inconsistency and is NOT a
     * target for a future parity sweep.
     */
    @Test
    public void aMismatchedNamedParameterSpecIsStillRefused() throws Exception
    {
        requireNamedParameterSpec();
        String[][] pairs = {{"X25519", "X448"}, {"X448", "X25519"},
                            {"Ed25519", "Ed448"}, {"Ed448", "Ed25519"}};
        List<String> failures = new ArrayList<String>();
        for (String[] p : pairs)
        {
            try
            {
                KeyPairGenerator.getInstance(p[0], jsl).initialize(named(p[1]));
                failures.add(p[0] + " accepted a " + p[1] + " spec");
            }
            catch (java.security.InvalidAlgorithmParameterException expected)
            {
                Assertions.assertNotNull(expected.getMessage(), p[0]);
            }
            catch (Throwable wrong)
            {
                failures.add(p[0] + " + " + p[1] + " raised " + wrong.getClass().getName());
            }
        }
        Assertions.assertTrue(failures.isEmpty(), "mismatched-spec refusals: " + failures);
    }

    /** A null spec stays refused (MT-52) - the twin must not have relaxed it. */
    @Test
    public void aNullSpecIsStillRefused() throws Exception
    {
        for (String alg : new String[]{"X25519", "X448", "Ed25519", "Ed448"})
        {
            Assertions.assertThrows(java.security.InvalidAlgorithmParameterException.class,
                    () -> KeyPairGenerator.getInstance(alg, jsl).initialize((AlgorithmParameterSpec) null),
                    alg + " must still refuse a null spec");
        }
    }
}
