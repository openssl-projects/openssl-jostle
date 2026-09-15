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

package org.openssl.jostle.jcajce.provider.bcfks;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.test.TestUtil;

import javax.crypto.SecretKey;
import java.io.ByteArrayInputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.interfaces.RSAPrivateCrtKey;

/**
 * BCFKS is the FIRST keystore the FIPS provider serves. Same real
 * BC-written fixtures as {@link BcFKSKeyStoreSpiTest}, driven through
 * {@code KeyStore.getInstance("BCFKS", "JSLFIPS")} -- PBKDF2, HMAC-SHA512,
 * AES-CCM/KWP and X.509/RSA KeyFactory are all approved services JostleFIPSProvider
 * already registers, so this needs no FIPS-specific code path, only the
 * registration itself.
 */
public class FIPSBcFKSKeyStoreSpiTest
{
    @BeforeEach
    void assumeFips()
    {
        Assumptions.assumeFalse(TestUtil.skipFipsTests(),
                "TEST_FIPS_LIB not set (full path to the FIPS module library)");
    }

    private static KeyStore load(byte[] data, char[] password) throws Exception
    {
        JostleFIPSProvider provider = TestUtil.addFipsProvider();
        KeyStore store = KeyStore.getInstance("BCFKS", provider.getName());
        store.load(new ByteArrayInputStream(data), password);
        return store;
    }

    @Test
    public void shouldParseKWPKeyStoreUnderFips() throws Exception
    {
        KeyStore store = load(BcFKSFixtures.KWP_KEY_STORE, BcFKSKeyStoreSpiTest.testPassword);
        Assertions.assertEquals(4, store.size());

        SecretKey storeDesEde = (SecretKey) store.getKey("secret2", "secretPwd2".toCharArray());
        Assertions.assertEquals("DESede", storeDesEde.getAlgorithm());

        SecretKey storeAes = (SecretKey) store.getKey("secret1", "secretPwd1".toCharArray());
        Assertions.assertEquals("AES", storeAes.getAlgorithm());

        Key storePrivKey = store.getKey("privkey", BcFKSKeyStoreSpiTest.testPassword);
        Assertions.assertTrue(storePrivKey instanceof RSAPrivateCrtKey);
        Assertions.assertEquals(2, store.getCertificateChain("privkey").length);

        Assertions.assertNotNull(store.getCertificate("trusted"));
    }

    @Test
    public void bcfksAnswersToTheFipsNamesToo() throws Exception
    {
        JostleFIPSProvider provider = TestUtil.addFipsProvider();
        // On the FIPS provider, BCFKS also answers to FIPS / FIPS-DEF / BCFKS-DEF.
        for (String name : new String[]{"BCFKS", "FIPS", "FIPS-DEF", "BCFKS-DEF"})
        {
            KeyStore store = KeyStore.getInstance(name, provider.getName());
            store.load(new ByteArrayInputStream(BcFKSFixtures.OLD_KEY_STORE), BcFKSKeyStoreSpiTest.testPassword);
            Assertions.assertEquals(1, store.size(), name);
        }
    }

    /**
     * REGRESSION: the FIPS module has no scrypt, so a store whose KDF is
     * id-scrypt is refused typed -- never routed into the base library (the
     * fix for a native abort found while investigating this class). Same
     * store as {@code BcFKSKeyStoreSpiTest.scryptStoreLoadsUnderJsl_regression},
     * loaded here under JSLFIPS instead of JSL.
     */
    @Test
    public void scryptStoreIsRefusedTyped_regression() throws Exception
    {
        JostleFIPSProvider provider = TestUtil.addFipsProvider();
        KeyStore store = KeyStore.getInstance("BCFKS", provider.getName());
        byte[] scryptStore = BcFKSFixtures.scryptStore();
        java.io.IOException e = Assertions.assertThrows(java.io.IOException.class,
                () -> store.load(new ByteArrayInputStream(scryptStore), BcFKSKeyStoreSpiTest.testPassword));
        Assertions.assertEquals("BCFKS store uses scrypt, which this provider does not serve", e.getMessage());
    }
}
