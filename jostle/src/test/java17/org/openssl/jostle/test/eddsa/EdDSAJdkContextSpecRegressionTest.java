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

package org.openssl.jostle.test.eddsa;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.ed.EdSignatureSpi;
import org.openssl.jostle.jcajce.spec.ContextParameterSpec;
import org.openssl.jostle.jcajce.spec.EdDSAParameterSpec;
import org.openssl.jostle.test.multirelease.MultiReleaseOverrides;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;

/**
 * {@code java.security.spec.EdDSAParameterSpec} (a JDK 15 API) is
 * read typed rather than reflectively — see {@code EdSignatureSpi}'s
 * {@code java15} copy. This is the {@code java17} companion to
 * {@code EdDSATest}, driving the JDK's own spec type directly against
 * {@code ED448} and {@code ED25519CTX} (both accept a context; plain
 * {@code ED25519} does not, so it is not exercised here).
 *
 * <p>The {@code java15} {@code EdSignatureSpi} override is served only from a
 * jar carrying {@code META-INF/versions/15} — see
 * {@link MultiReleaseOverrides}. Both branches are asserted, never skipped:
 * when the override is active, a {@code EdDSAParameterSpec(false, ctx)}
 * signature must be byte-identical to the {@link ContextParameterSpec}
 * equivalent (EdDSA is deterministic) and must verify; when it is not (a
 * class-directory classpath), the JDK type is refused.
 */
public class EdDSAJdkContextSpecRegressionTest
{
    private static final SecureRandom RANDOM = new SecureRandom();

    @BeforeAll
    public static void before()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    private static SecureRandom seededRandom(String testName)
    {
        long seed = RANDOM.nextLong();
        System.out.println(testName + " seed=" + seed);
        SecureRandom sr;
        try
        {
            sr = SecureRandom.getInstance("SHA1PRNG");
        }
        catch (Exception e)
        {
            throw new RuntimeException(e);
        }
        sr.setSeed(seed);
        return sr;
    }

    private static boolean overrideActive()
    {
        return MultiReleaseOverrides.overrideActive(
                EdSignatureSpi.class, "java.security.spec.EdDSAParameterSpec");
    }

    private static KeyPair generate(EdDSAParameterSpec ownSpec, SecureRandom sr) throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EdDSA", JostleProvider.PROVIDER_NAME);
        kpg.initialize(ownSpec, sr);
        return kpg.generateKeyPair();
    }

    @Test
    public void ed448_jdkContextSpecContract() throws Exception
    {
        // RFC 8032 §5.2: SigEd448 always carries a context, default empty —
        // so an absent context is a legitimate, signable case for ED448.
        assertContract("ED448", EdDSAParameterSpec.ED448, true, "ed448_jdkContextSpecContract");
    }

    @Test
    public void ed25519ctx_jdkContextSpecContract() throws Exception
    {
        // Unlike ED448, Ed25519ctx's whole point is requiring a non-empty
        // context (that is what distinguishes it from plain Ed25519), so an
        // absent context is refused by OpenSSL itself — not exercised here.
        assertContract("ED25519CTX", EdDSAParameterSpec.ED25519, false, "ed25519ctx_jdkContextSpecContract");
    }

    private static void assertContract(String transformation, EdDSAParameterSpec ownGenSpec,
                                        boolean emptyContextIsValid, String testName)
            throws Exception
    {
        SecureRandom sr = seededRandom(testName);
        KeyPair kp = generate(ownGenSpec, sr);
        byte[] msg = new byte[1 + sr.nextInt(256)];
        sr.nextBytes(msg);
        byte[] ctx = new byte[1 + sr.nextInt(32)];
        sr.nextBytes(ctx);

        // A prehash spec is always refused, on every level — our code
        // explicitly rejects it once the override is active, and the
        // baseline refuses every non-ContextParameterSpec regardless.
        java.security.spec.EdDSAParameterSpec prehash = new java.security.spec.EdDSAParameterSpec(true);
        Assertions.assertThrows(InvalidAlgorithmParameterException.class,
                () -> sign(transformation, kp, msg, prehash),
                transformation + ": a prehash EdDSAParameterSpec must always be refused");

        java.security.spec.EdDSAParameterSpec withContext = new java.security.spec.EdDSAParameterSpec(false, ctx);
        java.security.spec.EdDSAParameterSpec noContext = new java.security.spec.EdDSAParameterSpec(false);

        if (!overrideActive())
        {
            // The baseline copy is loaded (class-directory classpath), so it
            // cannot reference the JDK 15 type and must refuse it — for this
            // reason alone, independent of whether the context is empty.
            // Assert rather than skip: a skip would let a genuinely broken
            // baseline pass unnoticed.
            Assertions.assertThrows(InvalidAlgorithmParameterException.class,
                    () -> sign(transformation, kp, msg, withContext),
                    transformation + ": the baseline copy cannot reference EdDSAParameterSpec and must refuse it");
            Assertions.assertThrows(InvalidAlgorithmParameterException.class,
                    () -> sign(transformation, kp, msg, noContext),
                    transformation + ": the baseline copy cannot reference EdDSAParameterSpec and must refuse it");
            return;
        }

        // EdDSA is deterministic (RFC 8032): a JDK EdDSAParameterSpec(false, ctx)
        // signature must be byte-identical to the ContextParameterSpec(ctx)
        // equivalent, and must verify against a JDK-spec verifier.
        byte[] viaJdkSpec = sign(transformation, kp, msg, withContext);
        byte[] viaOwnSpec = sign(transformation, kp, msg, new ContextParameterSpec(ctx));
        Assertions.assertArrayEquals(viaOwnSpec, viaJdkSpec,
                transformation + ": JDK EdDSAParameterSpec(false, ctx) must derive what our "
                        + "ContextParameterSpec does — EdDSA is deterministic");
        Assertions.assertTrue(verify(transformation, kp, msg, viaJdkSpec, withContext),
                transformation + ": must verify with the JDK spec that produced it");

        if (!emptyContextIsValid)
        {
            return;
        }

        // EdDSAParameterSpec(false) (no context) must be accepted and equal
        // the null-parameter (no setParameter call) signature.
        byte[] viaEmptyJdkSpec = sign(transformation, kp, msg, noContext);
        byte[] viaNullParam = sign(transformation, kp, msg, null);
        Assertions.assertArrayEquals(viaNullParam, viaEmptyJdkSpec,
                transformation + ": JDK EdDSAParameterSpec(false) (no context) must equal the "
                        + "null-parameter signature");
    }

    private static byte[] sign(String transformation, KeyPair kp, byte[] msg,
                                java.security.spec.AlgorithmParameterSpec spec) throws Exception
    {
        Signature s = Signature.getInstance(transformation, JostleProvider.PROVIDER_NAME);
        s.initSign(kp.getPrivate());
        if (spec != null)
        {
            s.setParameter(spec);
        }
        s.update(msg);
        return s.sign();
    }

    private static boolean verify(String transformation, KeyPair kp, byte[] msg, byte[] sig,
                                   java.security.spec.AlgorithmParameterSpec spec) throws Exception
    {
        Signature v = Signature.getInstance(transformation, JostleProvider.PROVIDER_NAME);
        v.initVerify(kp.getPublic());
        if (spec != null)
        {
            v.setParameter(spec);
        }
        v.update(msg);
        return v.verify(sig);
    }
}
