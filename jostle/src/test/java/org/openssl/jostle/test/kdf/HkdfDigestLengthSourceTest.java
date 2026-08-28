/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.kdf;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.spec.HKDFParameterSpec;

import javax.crypto.SecretKeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;

/**
 * MT-11: the HKDF output ceiling comes from OpenSSL, not from whichever JCA
 * provider answers {@code MessageDigest.getInstance}.
 *
 * <p>SHA-256 is 32 bytes whoever computes it, so asserting "the ceiling is
 * 8160" passes under either source and proves nothing. The discriminating
 * input is the ABSENCE of a provider serving the digest: with the registry
 * emptied, a provider-sourced implementation can only throw.
 * {@link #ceilingIsStillCorrectWithNoJcaProviderServingTheDigest()} verifies
 * the removal took effect before relying on it.
 *
 * <p>Safe to mutate the global registry: the build runs {@code forkEvery = 1}.
 */
public class HkdfDigestLengthSourceTest
{
    /** Registered name -> RFC 5869 ceiling, 255 * HashLen in bytes. */
    private static final Object[][] CEILINGS = {
            {"HKDF-SHA256", 255 * 32},
            {"HKDF-SHA384", 255 * 48},
            {"HKDF-SHA512", 255 * 64},
    };

    /**
     * Held as an INSTANCE, so every {@code getInstance} below works with the
     * Security registry emptied - {@code getInstance(alg, Provider)} never
     * consults the registry.
     */
    private static JostleProvider jsl;

    private final List<Provider> removed = new ArrayList<Provider>();

    @BeforeAll
    public static void beforeAll() throws Exception
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        jsl = (JostleProvider) Security.getProvider(JostleProvider.PROVIDER_NAME);
        // Force the native interface classes to initialise while the registry
        // is still intact, so the stripped-registry test measures the digest
        // length source and nothing else.
        SecretKeyFactory.getInstance("HKDF-SHA256", jsl);
    }

    @AfterEach
    public void restore()
    {
        for (Provider p : removed)
        {
            if (Security.getProvider(p.getName()) == null)
            {
                Security.addProvider(p);
            }
        }
        removed.clear();
    }

    /** Control, registry intact. Three digests, so a constant source fails too. */
    @Test
    public void theCeilingIsRfc5869sForEveryRegisteredDigest() throws Exception
    {
        assertCeilings();
    }

    /** The discriminator: no provider can answer, so only OpenSSL can. */
    @Test
    public void ceilingIsStillCorrectWithNoJcaProviderServingTheDigest() throws Exception
    {
        for (Provider p : Security.getProviders())
        {
            removed.add(p);
            Security.removeProvider(p.getName());
        }

        // Non-vacuity: prove the strip took effect, or the test passes either way.
        Assertions.assertEquals(0, Security.getProviders().length,
                "the Security registry was not emptied — the discriminator is inert");
        Assertions.assertThrows(NoSuchAlgorithmException.class,
                () -> MessageDigest.getInstance("SHA-256"),
                "SHA-256 is still reachable through JCA, so the old provider-sourced "
                        + "implementation would pass this test too");

        assertCeilings();
    }

    /** Through the SPI, not a field: accept the ceiling, reject one byte more. */
    private void assertCeilings() throws Exception
    {
        for (Object[] row : CEILINGS)
        {
            String algorithm = (String) row[0];
            int ceiling = (Integer) row[1];
            SecretKeyFactory factory = SecretKeyFactory.getInstance(algorithm, jsl);

            byte[] ikm = new byte[32];
            java.util.Arrays.fill(ikm, (byte) 0x0b);

            byte[] atCeiling = factory.generateSecret(
                    new HKDFParameterSpec(ikm.clone(), null, null, ceiling)).getEncoded();
            Assertions.assertEquals(ceiling, atCeiling.length,
                    algorithm + ": 255 * HashLen must be derivable");

            InvalidKeySpecException tooLong = Assertions.assertThrows(
                    InvalidKeySpecException.class,
                    () -> factory.generateSecret(
                            new HKDFParameterSpec(ikm.clone(), null, null, ceiling + 1)),
                    algorithm + ": one byte past 255 * HashLen must be refused");
            Assertions.assertTrue(tooLong.getMessage().contains(String.valueOf(ceiling)),
                    algorithm + ": the refusal must name the real ceiling, but said: "
                            + tooLong.getMessage());
        }
    }
}
