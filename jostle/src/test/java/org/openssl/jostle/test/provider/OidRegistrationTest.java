/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.provider;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.security.Security;

/**
 * MT-72: OIDs that consumers resolve services by, which were registered for
 * some service types and not others.
 *
 * <h2>Why an OID gap is invisible to ordinary coverage</h2>
 *
 * <p>CMS and PKCS#8 resolve a Cipher, KeyGenerator and SecretKeyFactory <b>by
 * the OID carried in the message</b>, never by name. So an algorithm can be
 * fully served, fully tested and completely unreachable to those callers. The
 * three AES-CCM OIDs were registered as {@code AlgorithmParameters} only, and
 * {@code id-PBKDF2} not at all.
 *
 * <h2>Why the CCM OIDs are pinned primaries and not aliases</h2>
 *
 * <p>Each names a key size. {@code CCMCipherSpi} otherwise derives its cipher
 * from the key LENGTH, so an alias of {@code "AES/CCM/NoPadding"} would make
 * {@code id-aes128-CCM} accept a 256-bit key — a wrong OID accepted for a
 * transformation, which is the defect class the OID audit exists to find.
 * {@link #sizedCcmOidsAcceptOnlyTheirOwnKeyLength()} is the guard, and
 * {@link #unpinnedCcmStillAcceptsEveryKeyLength()} is its control: without the
 * control, an SPI that refused everything would pass the guard.
 */
public class OidRegistrationTest
{
    private static final String AES128_CCM = "2.16.840.1.101.3.4.1.7";
    private static final String AES192_CCM = "2.16.840.1.101.3.4.1.27";
    private static final String AES256_CCM = "2.16.840.1.101.3.4.1.47";
    private static final String ID_PBKDF2 = "1.2.840.113549.1.5.12";

    private static final String JSL = JostleProvider.PROVIDER_NAME;

    @BeforeAll
    public static void setUp()
    {
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    /**
     * The exact lookups that failed for the bc-java CMS and PKCS#8 layers.
     * Named for the consumer rather than the mechanism, so a future reader
     * knows what breaks if they are removed.
     */
    @Test
    public void theLookupsCmsAndPkcs8PerformAllResolve() throws Exception
    {
        Assertions.assertNotNull(KeyGenerator.getInstance(AES128_CCM, JSL),
                "CMS resolves the content-encryption KeyGenerator by OID");
        Assertions.assertNotNull(Cipher.getInstance(AES192_CCM, JSL),
                "CMS resolves the content-encryption Cipher by OID");
        Assertions.assertNotNull(SecretKeyFactory.getInstance(ID_PBKDF2, JSL),
                "PBES2 / PKCS#8 resolves the key-derivation SecretKeyFactory by OID");
    }

    /** Every AES-CCM OID, both service types, so a partial registration fails. */
    @Test
    public void everyAesCcmOidIsServedAsBothCipherAndKeyGenerator() throws Exception
    {
        for (String oid : new String[]{AES128_CCM, AES192_CCM, AES256_CCM})
        {
            Assertions.assertNotNull(Cipher.getInstance(oid, JSL), "Cipher " + oid);
            Assertions.assertNotNull(KeyGenerator.getInstance(oid, JSL), "KeyGenerator " + oid);
        }
    }

    /**
     * The guard. Each sized OID accepts its own key length and refuses the
     * other two with {@link InvalidKeyException} — the JCE-canonical init
     * failure and the provider-fallback trigger.
     */
    @Test
    public void sizedCcmOidsAcceptOnlyTheirOwnKeyLength() throws Exception
    {
        assertKeyLengths(AES128_CCM, 16);
        assertKeyLengths(AES192_CCM, 24);
        assertKeyLengths(AES256_CCM, 32);
    }

    /**
     * The control for the guard above: the UNPINNED transformation keeps its
     * length-derived behaviour. A mechanism that simply refused mismatches
     * everywhere would pass the guard and fail here.
     */
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
        SecureRandom random = new SecureRandom();
        byte[] key = new byte[16];
        byte[] nonce = new byte[12];
        byte[] message = new byte[1 + random.nextInt(256)];
        random.nextBytes(key);
        random.nextBytes(nonce);
        random.nextBytes(message);

        byte[] viaName = ccmEncrypt("AES/CCM/NoPadding", key, nonce, message);
        byte[] viaOid = ccmEncrypt(AES128_CCM, key, nonce, message);

        Assertions.assertTrue(Arrays.areEqual(viaName, viaOid),
                "id-aes128-CCM must produce what AES/CCM/NoPadding produces for the same inputs");
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
                        oid + " names a " + accepted + "-byte key; a " + len
                                + "-byte key must be refused, not silently used");
            }
        }
    }

    private static void initCcm(String name, int keyLen) throws Exception
    {
        Cipher cipher = Cipher.getInstance(name, JSL);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[keyLen], "AES"),
                new GCMParameterSpec(64, new byte[12]));
    }

    private static byte[] ccmEncrypt(String name, byte[] key, byte[] nonce, byte[] message)
            throws Exception
    {
        Cipher cipher = Cipher.getInstance(name, JSL);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(64, nonce));
        return cipher.doFinal(message);
    }
}
