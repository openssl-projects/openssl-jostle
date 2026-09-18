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

package org.openssl.jostle.test.ec;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.util.Arrays;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.spec.ECPublicKeySpec;

/**
 * {@code ECKeyFactory.generatePublic(ECPublicKeySpec)} works with none of the
 * JDK providers installed.
 *
 * <p>Before this fix, an {@code ECPublicKeySpec} was rebuilt into a key by
 * encoding it via {@code KeyFactory.getInstance("EC", "SunEC")} and decoding
 * the result through our own SubjectPublicKeyInfo path. With SunEC absent —
 * a JDK-provider-free deployment, or a JVM filtered with
 * {@code jdk.security.providers.filter} — that construction threw
 * {@code InvalidKeySpecException("ECPublicKeySpec support requires the SunEC
 * provider")}, even though the identical key material presented as an
 * {@code X509EncodedKeySpec} worked fine.
 *
 * <p>Registry snapshot/restore skeleton copied verbatim from
 * {@code RSAPSSWithoutJdkProvidersTest}, including the {@code SHA1PRNG}
 * restore witness (this class empties the registry the same way, so the
 * same class-ordering hazard applies).
 */
public class ECKeyFactoryWithoutJdkProvidersRegressionTest
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
     * one is red here rather than in some unrelated class minutes later.
     */
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

    /** JSL serves all five unconditionally; the FIPS twin assumes per curve. */
    private static final String[] CURVES = {
            "secp256r1", "secp384r1", "secp521r1", "brainpoolP256r1", "sect283k1"
    };

    @Test
    public void ecPublicKeySpecRebuildsWithoutAnyJdkProvider() throws Exception
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

        int compared = 0;
        for (String curveName : CURVES)
        {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", "JSL");
            generator.initialize(new java.security.spec.ECGenParameterSpec(curveName));
            KeyPair keyPair = generator.generateKeyPair();

            java.security.interfaces.ECPublicKey originalPub =
                    (java.security.interfaces.ECPublicKey) keyPair.getPublic();
            ECPublicKeySpec rawSpec = new ECPublicKeySpec(originalPub.getW(), originalPub.getParams());

            KeyFactory kf = KeyFactory.getInstance("EC", "JSL");
            java.security.PublicKey rebuilt = kf.generatePublic(rawSpec);

            Assertions.assertTrue(Arrays.areEqual(originalPub.getEncoded(), rebuilt.getEncoded()),
                    curveName + ": rebuilt public key's encoding must match the original's");

            Signature signer = Signature.getInstance("NONEwithECDSA", "JSL");
            signer.initSign(keyPair.getPrivate());
            signer.update(new byte[32]);
            byte[] sig = signer.sign();

            Signature verifier = Signature.getInstance("NONEwithECDSA", "JSL");
            verifier.initVerify(rebuilt);
            verifier.update(new byte[32]);
            Assertions.assertTrue(verifier.verify(sig),
                    curveName + ": rebuilt public key must verify a signature made by the original private key");

            compared++;
        }
        Assertions.assertTrue(compared > 0, "no curve was actually exercised");
    }
}
