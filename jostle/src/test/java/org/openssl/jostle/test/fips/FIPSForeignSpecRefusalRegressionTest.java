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
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.jcajce.spec.HKDFParameterSpec;

import javax.crypto.SecretKeyFactory;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;

/**
 * {@link org.openssl.jostle.test.kdf.ForeignSpecRefusalRegressionTest}
 * FIPS twin: JSLFIPS, HKDF only (scrypt is deliberately unregistered under
 * JSLFIPS — not an approved KDF). Gated on {@code TEST_FIPS_LIB}; skipped
 * when unset.
 */
public class FIPSForeignSpecRefusalRegressionTest
{
    private static final String FIPS = JostleFIPSProvider.PROVIDER_NAME;
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
    private static final SecureRandom RANDOM = new SecureRandom();

    @BeforeAll
    static void before()
    {
        FIPSTestUtil.assumeFipsProvider();
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test
    public void bcHkdfParameterSpecRefused() throws Exception
    {
        byte[] ikm = new byte[32];
        RANDOM.nextBytes(ikm);
        byte[] salt = new byte[16];
        RANDOM.nextBytes(salt);
        org.bouncycastle.jcajce.spec.HKDFParameterSpec bcSpec =
                new org.bouncycastle.jcajce.spec.HKDFParameterSpec(ikm, salt, null, 32);

        SecretKeyFactory kf = SecretKeyFactory.getInstance("HKDF-SHA256", FIPS);
        InvalidKeySpecException e = Assertions.assertThrows(InvalidKeySpecException.class,
                () -> kf.generateSecret(bcSpec));
        Assertions.assertTrue(e.getMessage().contains("org.openssl.jostle.jcajce.spec.HKDFParameterSpec"),
                "message must name the Jostle class: " + e.getMessage());
    }

    @Test
    public void ourHkdfParameterSpecAgreesWithBc() throws Exception
    {
        byte[] ikm = new byte[32];
        RANDOM.nextBytes(ikm);
        byte[] salt = new byte[16];
        RANDOM.nextBytes(salt);

        byte[] fips = SecretKeyFactory.getInstance("HKDF-SHA256", FIPS)
                .generateSecret(new HKDFParameterSpec(ikm, salt, null, 32)).getEncoded();
        byte[] bc = SecretKeyFactory.getInstance("HKDF-SHA256", BC)
                .generateSecret(new org.bouncycastle.jcajce.spec.HKDFParameterSpec(ikm, salt, null, 32))
                .getEncoded();

        Assertions.assertArrayEquals(bc, fips, "JSLFIPS's HKDFParameterSpec must agree with BC's own");
    }
}
