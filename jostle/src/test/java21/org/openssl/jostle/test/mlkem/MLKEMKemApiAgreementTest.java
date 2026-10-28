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

package org.openssl.jostle.test.mlkem;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.test.TestUtil;

import javax.crypto.KEM;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;

/**
 * The JDK 21 KEM API: neither of our providers registers a javax.crypto.KEM service for ML-KEM, which is reached
 * through the KeyGenerator with KEMGenerateSpec and KEMExtractSpec instead; BouncyCastle serves one. Both halves.
 */
public class MLKEMKemApiAgreementTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

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

    @Test
    public void jslServesNoKemAndBouncyCastleDoes() throws Exception
    {
        Assertions.assertThrows(NoSuchAlgorithmException.class, () -> KEM.getInstance("ML-KEM", JSL));
        Assertions.assertNull(Security.getProvider(JSL).getService("KEM", "ML-KEM"));

        KeyPair kp = KeyPairGenerator.getInstance("ML-KEM-768", BC).generateKeyPair();
        KEM bc = KEM.getInstance("ML-KEM", BC);
        KEM.Encapsulated sent = bc.newEncapsulator(kp.getPublic()).encapsulate();
        Assertions.assertArrayEquals(sent.key().getEncoded(),
                bc.newDecapsulator(kp.getPrivate()).decapsulate(sent.encapsulation()).getEncoded());
    }

    @Test
    public void jslFipsServesNoKem()
    {
        Assumptions.assumeFalse(TestUtil.skipFipsTests(),
                "TEST_FIPS_LIB not set (full path to the FIPS module library)");
        Provider fips = TestUtil.addFipsProvider();
        Assertions.assertThrows(NoSuchAlgorithmException.class, () -> KEM.getInstance("ML-KEM", fips));
        Assertions.assertNull(fips.getService("KEM", "ML-KEM"));
        Assertions.assertEquals(JostleFIPSProvider.PROVIDER_NAME, fips.getName());
    }
}
