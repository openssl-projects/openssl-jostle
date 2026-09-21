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
import java.io.ByteArrayOutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;

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

    /**
     * The write path needs only PBKDF2, HMAC-SHA512, AES-CCM and X.509 -- all
     * baseline FIPS module services -- so it works under JSLFIPS exactly as
     * under JSL. Same key material as {@link
     * BcFKSKeyStoreSpiTest#writeThenReadRoundTrip_regression}, round-tripped
     * through JSLFIPS start to finish.
     */
    @Test
    public void writeThenReadRoundTripUnderFips_regression() throws Exception
    {
        JostleFIPSProvider provider = TestUtil.addFipsProvider();
        KeyStore src = load(BcFKSFixtures.KWP_KEY_STORE, BcFKSKeyStoreSpiTest.testPassword);
        PrivateKey privKey = (PrivateKey) src.getKey("privkey", BcFKSKeyStoreSpiTest.testPassword);
        Certificate[] chain = src.getCertificateChain("privkey");
        SecretKey secret1 = (SecretKey) src.getKey("secret1", "secretPwd1".toCharArray());

        char[] storePw = "fips round-trip store password".toCharArray();
        char[] keyPw = "fips round-trip key password".toCharArray();

        KeyStore fresh = KeyStore.getInstance("BCFKS", provider.getName());
        fresh.load(null, storePw);
        fresh.setKeyEntry("mykey", privKey, keyPw, chain);
        fresh.setKeyEntry("mysecret", secret1, keyPw, null);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        fresh.store(out, storePw);

        KeyStore reloaded = KeyStore.getInstance("BCFKS", provider.getName());
        reloaded.load(new ByteArrayInputStream(out.toByteArray()), storePw);

        Assertions.assertEquals(2, reloaded.size());
        Assertions.assertArrayEquals(privKey.getEncoded(), reloaded.getKey("mykey", keyPw).getEncoded());
        Key reloadedSecret = reloaded.getKey("mysecret", keyPw);
        Assertions.assertArrayEquals(secret1.getEncoded(), reloadedSecret.getEncoded());
    }
}
