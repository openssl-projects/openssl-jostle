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

package org.openssl.jostle.test.rsa;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.util.Arrays;

import java.security.AlgorithmParameters;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

/**
 * RSA-PSS works with none of the JDK providers installed.
 *
 * <p>The second half of GitHub issue 58: "ideally one should test that RSA-PSS
 * works, including parameters, without the SUN providers loaded at all".
 * Before the parameters were registered, {@code AlgorithmParameters} for
 * RSASSA-PSS resolved to SunRsaSign, so a deployment that removed the JDK
 * providers — or filtered them with {@code jdk.security.providers.filter} —
 * lost the ability to encode or decode PSS parameters entirely.
 *
 *
 * <p>It empties the GLOBAL provider registry, and restores it in an
 * {@code @AfterEach} that runs whatever the test does. The restore is not
 * belt-and-braces: measured on the base {@code :jostle:test} leg, leaving the
 * registry empty failed 20 tests across {@code RSATest}, {@code SLHDSATest}
 * and {@code XDHTest} with "SHA1PRNG SecureRandom not available" — their
 * seeded-random helper needs SUN. {@code forkEvery = 1} did NOT contain it,
 * and the three unit legs passed only because of class ordering, so a test
 * that mutates global JVM state restores it rather than relying on the fork
 * policy.
 */
public class RSAPSSWithoutJdkProvidersTest
{
    /** The registry as it was, in order, so it can be put back exactly. */
    private Provider[] original;

    @BeforeEach
    public void snapshotTheRegistry()
    {
        original = Security.getProviders();
    }

    /**
     * Restores unconditionally and then ASSERTS the restoration, so a partial
     * one is red here rather than in some unrelated class minutes later. The
     * damage this guards against is silent by nature: the next class in the
     * JVM simply cannot find an algorithm it never asked this class about.
     */
    @AfterEach
    public void restoreTheRegistry()
    {
        if (original == null)
        {
            // @BeforeEach did not complete. Nothing was removed, so there is
            // nothing to put back, and failing here would mask the real cause.
            return;
        }

        for (Provider installed : Security.getProviders())
        {
            Security.removeProvider(installed.getName());
        }
        // insertProviderAt is 1-based and preserves the original precedence;
        // addProvider would append and silently reorder them.
        for (int i = 0; i < original.length; i++)
        {
            Security.insertProviderAt(original[i], i + 1);
        }

        Provider[] restored = Security.getProviders();
        Assertions.assertEquals(original.length, restored.length,
                "provider count not restored: the next class in this JVM will see a different registry");
        for (int i = 0; i < original.length; i++)
        {
            // By NAME and POSITION: precedence is what decides which provider
            // answers an unqualified getInstance, so an out-of-order restore
            // is as damaging as a missing one and looks identical to none.
            Assertions.assertEquals(original[i].getName(), restored[i].getName(),
                    "provider at position " + i + " not restored");
        }

        // Behavioural witness of a different shape from the name comparison:
        // the exact lookup whose absence failed 20 tests in RSATest,
        // SLHDSATest and XDHTest when this class first left the registry empty.
        Assertions.assertDoesNotThrow(
                () -> java.security.SecureRandom.getInstance("SHA1PRNG"),
                "SHA1PRNG is unavailable after the restore");
    }

    @Test
    public void pssSignsVerifiesAndEncodesItsParametersAlone()
        throws Exception
    {
        for (Provider installed : Security.getProviders())
        {
            Security.removeProvider(installed.getName());
        }
        Assertions.assertEquals(0, Security.getProviders().length,
                "the registry was not emptied, so this proves nothing about a JDK-free deployment");

        Provider jsl = new JostleProvider();
        Security.addProvider(jsl);
        Assertions.assertEquals(1, Security.getProviders().length);

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "JSL");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();

        PSSParameterSpec spec =
                new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);

        Signature signer = Signature.getInstance("RSASSA-PSS", "JSL");
        signer.setParameter(spec);
        signer.initSign(keyPair.getPrivate());
        signer.update("payload".getBytes("UTF-8"));
        byte[] produced = signer.sign();

        Signature verifier = Signature.getInstance("RSASSA-PSS", "JSL");
        verifier.setParameter(spec);
        verifier.initVerify(keyPair.getPublic());
        verifier.update("payload".getBytes("UTF-8"));
        Assertions.assertTrue(verifier.verify(produced));

        // Tampered payload must NOT verify, so the cell above is not satisfied
        // by a verify that ignores its input.
        Signature tampered = Signature.getInstance("RSASSA-PSS", "JSL");
        tampered.setParameter(spec);
        tampered.initVerify(keyPair.getPublic());
        tampered.update("payloae".getBytes("UTF-8"));
        Assertions.assertFalse(tampered.verify(produced));

        // The lookup that used to escape to SunRsaSign, with SunRsaSign gone.
        AlgorithmParameters params = AlgorithmParameters.getInstance("RSASSA-PSS");
        Assertions.assertSame(jsl, params.getProvider());
        params.init(spec);
        byte[] der = params.getEncoded();

        AlgorithmParameters back = AlgorithmParameters.getInstance("RSASSA-PSS");
        back.init(der);
        Assertions.assertTrue(Arrays.areEqual(der, back.getEncoded()));
        Assertions.assertEquals("SHA-256",
                back.getParameterSpec(PSSParameterSpec.class).getDigestAlgorithm());

        // And the signature reports parameters without the JDK present.
        Assertions.assertNotNull(signer.getParameters());
    }
}
