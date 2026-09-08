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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.Provider;
import java.security.SecureRandom;

/**
 * MT-72b: the FIPS twin of {@code OidRegistrationTest}.
 *
 * <p>Commit {@code 81fe329} registered these OIDs on the BASE provider only, so
 * JSLFIPS was unchanged on both modules and four of the six lookups CMS and
 * PKCS#8 perform still failed there. The capability was always present — the
 * same algorithms worked by NAME — so this was purely a missing registration.
 *
 * <p>Runs against whichever module {@code TEST_FIPS_LIB} names; every algorithm
 * asserted here is served by both 3.1.2 and 3.5.8, so no per-module gating is
 * needed. {@link FIPSOidCrossProviderParityTest} is the guard that would have
 * caught the original omission; this is the behavioural half.
 */
public class FIPSOidRegistrationTest
{
    private static final String AES128_CCM = "2.16.840.1.101.3.4.1.7";
    private static final String AES192_CCM = "2.16.840.1.101.3.4.1.27";
    private static final String AES256_CCM = "2.16.840.1.101.3.4.1.47";
    private static final String ID_PBKDF2 = "1.2.840.113549.1.5.12";
    private static final String EC_PUBLIC_KEY = "1.2.840.10045.2.1";

    private static final SecureRandom RANDOM = new SecureRandom();

    private static Provider fips;

    @BeforeAll
    public static void setUp()
    {
        fips = FIPSTestUtil.assumeFipsProvider();
    }

    /** The lookups CMS and PKCS#8 perform, by OID, on the FIPS provider. */
    @Test
    public void theLookupsCmsAndPkcs8PerformAllResolve() throws Exception
    {
        Assertions.assertNotNull(KeyGenerator.getInstance(AES128_CCM, fips));
        Assertions.assertNotNull(Cipher.getInstance(AES192_CCM, fips));
        Assertions.assertNotNull(SecretKeyFactory.getInstance(ID_PBKDF2, fips));
        Assertions.assertNotNull(AlgorithmParameters.getInstance(EC_PUBLIC_KEY, fips));
    }

    @Test
    public void everyAesCcmOidIsServedAsBothCipherAndKeyGenerator() throws Exception
    {
        for (String oid : new String[]{AES128_CCM, AES192_CCM, AES256_CCM})
        {
            Assertions.assertNotNull(Cipher.getInstance(oid, fips), "Cipher " + oid);
            Assertions.assertNotNull(KeyGenerator.getInstance(oid, fips), "KeyGenerator " + oid);
        }
    }

    /** The pin: each sized OID takes its own key length and refuses the others. */
    @Test
    public void sizedCcmOidsAcceptOnlyTheirOwnKeyLength() throws Exception
    {
        assertKeyLengths(AES128_CCM, 16);
        assertKeyLengths(AES192_CCM, 24);
        assertKeyLengths(AES256_CCM, 32);
    }

    /** Control: the unpinned transformation keeps its length-derived behaviour. */
    @Test
    public void unpinnedCcmStillAcceptsEveryKeyLength() throws Exception
    {
        for (int len : new int[]{16, 24, 32})
        {
            initCcm("AES/CCM/NoPadding", len);
        }
    }

    /** An OID must compute what its primary computes, not merely construct. */
    @Test
    public void theOidProducesTheSameBytesAsTheTransformationName() throws Exception
    {
        byte[] key = new byte[16];
        byte[] nonce = new byte[12];
        byte[] message = new byte[1 + RANDOM.nextInt(256)];
        RANDOM.nextBytes(key);
        RANDOM.nextBytes(nonce);
        RANDOM.nextBytes(message);

        byte[] viaName = ccmEncrypt("AES/CCM/NoPadding", key, nonce, message);
        byte[] viaOid = ccmEncrypt(AES128_CCM, key, nonce, message);

        Assertions.assertTrue(Arrays.areEqual(viaName, viaOid),
                "the OID must produce what the transformation name produces");
        Assertions.assertFalse(Arrays.areEqual(message, viaOid),
                "the operation must transform its input");
    }

    private static void assertKeyLengths(String oid, int accepted) throws Exception
    {
        for (int len : new int[]{16, 24, 32})
        {
            if (len == accepted)
            {
                initCcm(oid, len);
            }
            else
            {
                Assertions.assertThrows(InvalidKeyException.class, () -> initCcm(oid, len),
                        oid + " names a " + accepted + "-byte key; a " + len + "-byte key must be refused");
            }
        }
    }

    private static void initCcm(String name, int keyLen) throws Exception
    {
        Cipher cipher = Cipher.getInstance(name, fips);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[keyLen], "AES"),
                new GCMParameterSpec(64, new byte[12]));
    }

    private static byte[] ccmEncrypt(String name, byte[] key, byte[] nonce, byte[] message)
            throws Exception
    {
        Cipher cipher = Cipher.getInstance(name, fips);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(64, nonce));
        return cipher.doFinal(message);
    }
}
