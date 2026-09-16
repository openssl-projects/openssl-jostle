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

package org.openssl.jostle.test.fips;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.util.Arrays;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPublicKeySpec;

/**
 * {@code ECKeyFactory.generatePublic(ECPublicKeySpec)} works with none of the
 * JDK providers installed — the JSLFIPS twin of
 * {@link org.openssl.jostle.test.ec.ECKeyFactoryWithoutJdkProvidersRegressionTest}.
 *
 * <p>The FIPS module is a one-shot native initialisation, so
 * {@link FIPSTestUtil#assumeFipsProvider()} runs FIRST (idempotent — returns
 * the existing instance if already registered) and its result is the ONLY
 * provider re-installed into the emptied registry. Curves are asserted per
 * the module's own served set rather than assumed, since 3.1.2 and 3.5.8
 * differ (CLAUDE.md / testing.md).
 */
public class FIPSECKeyFactoryWithoutJdkProvidersRegressionTest
{
    /** Fails closed: the whole class skips when TEST_FIPS_LIB is unset. */
    @BeforeAll
    public static void gate()
    {
        FIPSTestUtil.assumeFipsProvider();
    }

    private Provider[] original;

    @BeforeEach
    public void snapshotTheRegistry()
    {
        original = Security.getProviders();
    }

    @AfterEach
    public void restoreTheRegistry()
    {
        if (original == null)
        {
            return;
        }

        for (Provider installed : Security.getProviders())
        {
            Security.removeProvider(installed.getName());
        }
        for (int i = 0; i < original.length; i++)
        {
            Security.insertProviderAt(original[i], i + 1);
        }

        Provider[] restored = Security.getProviders();
        Assertions.assertEquals(original.length, restored.length,
                "provider count not restored: the next class in this JVM will see a different registry");
        for (int i = 0; i < original.length; i++)
        {
            Assertions.assertEquals(original[i].getName(), restored[i].getName(),
                    "provider at position " + i + " not restored");
        }

        Assertions.assertDoesNotThrow(
                () -> java.security.SecureRandom.getInstance("SHA1PRNG"),
                "SHA1PRNG is unavailable after the restore");
    }

    private static final String[] CANDIDATE_CURVES = {
            "secp256r1", "secp384r1", "secp521r1", "brainpoolP256r1", "sect283k1"
    };

    @Test
    public void ecPublicKeySpecRebuildsWithoutAnyJdkProvider() throws Exception
    {
        // gate() already registered JSLFIPS (native FIPS init is one-shot
        // per JVM); fetch that same instance before emptying the registry.
        JostleFIPSProvider fips = (JostleFIPSProvider) Security.getProvider(JostleFIPSProvider.PROVIDER_NAME);
        Assertions.assertNotNull(fips, "gate() must have registered JSLFIPS");

        for (Provider installed : Security.getProviders())
        {
            Security.removeProvider(installed.getName());
        }
        Security.addProvider(fips);
        Assertions.assertEquals(1, Security.getProviders().length,
                "the registry must carry JSLFIPS alone, so this proves nothing about a JDK-free deployment otherwise");

        int compared = 0;
        for (String curveName : CANDIDATE_CURVES)
        {
            KeyPair keyPair;
            try
            {
                KeyPairGenerator generator =
                        KeyPairGenerator.getInstance("EC", JostleFIPSProvider.PROVIDER_NAME);
                generator.initialize(new ECGenParameterSpec(curveName));
                keyPair = generator.generateKeyPair();
            }
            catch (InvalidAlgorithmParameterException | RuntimeException e)
            {
                // Not every curve is served by every FIPS module
                // configuration — assert the precondition per-curve rather
                // than assuming the base provider's full list applies here.
                continue;
            }

            java.security.interfaces.ECPublicKey originalPub =
                    (java.security.interfaces.ECPublicKey) keyPair.getPublic();
            ECPublicKeySpec rawSpec = new ECPublicKeySpec(originalPub.getW(), originalPub.getParams());

            KeyFactory kf = KeyFactory.getInstance("EC", JostleFIPSProvider.PROVIDER_NAME);
            java.security.PublicKey rebuilt = kf.generatePublic(rawSpec);

            Assertions.assertTrue(Arrays.areEqual(originalPub.getEncoded(), rebuilt.getEncoded()),
                    curveName + ": rebuilt public key's encoding must match the original's");

            Signature signer = Signature.getInstance("NONEwithECDSA", JostleFIPSProvider.PROVIDER_NAME);
            signer.initSign(keyPair.getPrivate());
            signer.update(new byte[32]);
            byte[] sig = signer.sign();

            Signature verifier = Signature.getInstance("NONEwithECDSA", JostleFIPSProvider.PROVIDER_NAME);
            verifier.initVerify(rebuilt);
            verifier.update(new byte[32]);
            Assertions.assertTrue(verifier.verify(sig),
                    curveName + ": rebuilt public key must verify a signature made by the original private key");

            compared++;
        }
        Assertions.assertTrue(compared > 0,
                "no curve in the candidate list is served by this module — widen the list");
    }
}
