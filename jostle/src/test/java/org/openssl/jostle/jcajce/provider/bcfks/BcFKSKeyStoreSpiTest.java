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
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.BCFKSLoadStoreParameter;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.provider.kdf.BytePasswordKdf;
import org.openssl.jostle.util.Arrays;
import org.openssl.jostle.util.asn1.Der;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.Enumeration;

/**
 * The interop pin: BC-written BCFKS files, loaded through this provider's
 * own {@code KeyStore.getInstance("BCFKS", "JSL")}, produce the same entries
 * BouncyCastle itself reads back (BCFKSStoreTest.shouldParseKWPKeyStore
 * r1rv86 :795-838, shouldParseOldStores via checkStore :1401-1432).
 */
public class BcFKSKeyStoreSpiTest
{
    static char[] testPassword = {'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd'};
    static char[] invalidTestPassword = {'Y', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd'};

    @BeforeAll
    static void before()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    private static KeyStore load(byte[] data, char[] password) throws Exception
    {
        KeyStore store = KeyStore.getInstance("BCFKS", JostleProvider.PROVIDER_NAME);
        store.load(new ByteArrayInputStream(data), password);
        return store;
    }


    /** A failed load resets the store to empty (BC's checkInvalidLoadForPassword, r1rv86). */
    @Test
    public void failedLoadResetsToEmpty() throws Exception
    {
        KeyStore store = load(BcFKSFixtures.OLD_KEY_STORE, testPassword);
        Assertions.assertEquals(1, store.size());

        Assertions.assertThrows(IOException.class,
                () -> store.load(new ByteArrayInputStream(BcFKSFixtures.OLD_KEY_STORE), invalidTestPassword));

        Assertions.assertEquals(0, store.size());
        Assertions.assertFalse(store.aliases().hasMoreElements());
    }

    @Test
    public void engineLoadNullResetsToEmptyStore() throws Exception
    {
        KeyStore store = KeyStore.getInstance("BCFKS", JostleProvider.PROVIDER_NAME);
        store.load(null, null);
        Assertions.assertEquals(0, store.size());
    }

    @Test
    public void writeOperationsRequireAProvider_regression() throws Exception
    {
        // An unbound SPI (direct construction, no provider) has nothing to
        // resolve Cipher/Mac/SecureRandom through, so a write that needs
        // encryption refuses typed rather than reaching for JCA search
        // order. (The byte[]-form setKeyEntry needs no provider at all --
        // it stores caller-supplied bytes verbatim, matching BC -- so it is
        // not part of this contract and is covered by
        // protectedEntryTypesWrittenByBcLoadThroughOurs_regression instead.)
        BcFKSKeyStoreSpi unbound = new BcFKSKeyStoreSpi(null);
        SecretKey key = new SecretKeySpec(new byte[16], "AES");

        Assertions.assertThrows(KeyStoreException.class,
                () -> unbound.engineSetKeyEntry("x", key, testPassword, null));
        unbound.engineLoad(null, null);
        Assertions.assertThrows(IOException.class,
                () -> unbound.engineStore(new ByteArrayOutputStream(), testPassword));
    }

    /** Pin every OID this reader claims to recognise against the exact JCA name. */
    @Test
    public void secretKeyAlgorithmNameMatchesJcaSpellingForEveryRecognisedOid() throws Exception
    {
        Assertions.assertEquals("AES", BcFKSKeyStoreSpi.secretKeyAlgorithmName("2.16.840.1.101.3.4.1"));
        Assertions.assertEquals("DESede", BcFKSKeyStoreSpi.secretKeyAlgorithmName("1.3.14.3.2.17"));
        Assertions.assertEquals("KMAC128", BcFKSKeyStoreSpi.secretKeyAlgorithmName("2.16.840.1.101.3.4.2.21"));
        Assertions.assertEquals("KMAC256", BcFKSKeyStoreSpi.secretKeyAlgorithmName("2.16.840.1.101.3.4.2.22"));
        Assertions.assertEquals("HmacSHA1", BcFKSKeyStoreSpi.secretKeyAlgorithmName("1.2.840.113549.2.7"));
        Assertions.assertEquals("HmacSHA224", BcFKSKeyStoreSpi.secretKeyAlgorithmName("1.2.840.113549.2.8"));
        Assertions.assertEquals("HmacSHA256", BcFKSKeyStoreSpi.secretKeyAlgorithmName("1.2.840.113549.2.9"));
        Assertions.assertEquals("HmacSHA384", BcFKSKeyStoreSpi.secretKeyAlgorithmName("1.2.840.113549.2.10"));
        Assertions.assertEquals("HmacSHA512", BcFKSKeyStoreSpi.secretKeyAlgorithmName("1.2.840.113549.2.11"));
        Assertions.assertEquals("HmacSHA512/224", BcFKSKeyStoreSpi.secretKeyAlgorithmName("1.2.840.113549.2.12"));
        Assertions.assertEquals("HmacSHA512/256", BcFKSKeyStoreSpi.secretKeyAlgorithmName("1.2.840.113549.2.13"));
        Assertions.assertEquals("HmacSHA3-224", BcFKSKeyStoreSpi.secretKeyAlgorithmName("2.16.840.1.101.3.4.2.13"));
        Assertions.assertEquals("HmacSHA3-256", BcFKSKeyStoreSpi.secretKeyAlgorithmName("2.16.840.1.101.3.4.2.14"));
        Assertions.assertEquals("HmacSHA3-384", BcFKSKeyStoreSpi.secretKeyAlgorithmName("2.16.840.1.101.3.4.2.15"));
        Assertions.assertEquals("HmacSHA3-512", BcFKSKeyStoreSpi.secretKeyAlgorithmName("2.16.840.1.101.3.4.2.16"));
        Assertions.assertThrows(IOException.class,
                () -> BcFKSKeyStoreSpi.secretKeyAlgorithmName("1.2.3.4.5"));
    }

    private static byte[] hex(String s)
    {
        int len = s.length();
        byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2)
        {
            out[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return out;
    }

    private static int indexOfSubarray(byte[] haystack, byte[] needle)
    {
        outer:
        for (int i = 0; i <= haystack.length - needle.length; i++)
        {
            for (int j = 0; j < needle.length; j++)
            {
                if (haystack[i + j] != needle[j])
                {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    /**
     * REGRESSION: our own conformant writer's store (p=1, r=8 -- derived AND
     * encoded with p=1) loads on a fresh JSL KeyStore through the plain
     * char[]-password engineLoad. Proves the encoded-p path is PRIMARY,
     * not a coincidental retry match: the legacy-convention MAC (p := r)
     * does NOT agree with the stored one, so only the encoded-p attempt
     * could have verified. A store whose MAC matches under NEITHER
     * convention still fails with the existing message.
     */
    @Test
    public void conformantWriterStoreLoadsWithoutRetry_regression() throws Exception
    {
        String propertyName = BcFKSKeyStoreSpi.SCRYPT_P_EQ_R_PROPERTY;
        String old = System.getProperty(propertyName);
        try
        {
            System.setProperty(propertyName, "false");
            BCFKSLoadStoreParameter.ScryptConfig config =
                    new BCFKSLoadStoreParameter.ScryptConfig.Builder(1024, 8, 1).withSaltLength(20).build();
            byte[] seckeyBytes = hex("000102030405060708090a0b0c0d0e0f");

            KeyStore fresh = KeyStore.getInstance("BCFKS", JostleProvider.PROVIDER_NAME);
            fresh.load(null, testPassword);
            fresh.setKeyEntry("seckey", new SecretKeySpec(seckeyBytes, "AES"), testPassword, null);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            fresh.store(new BCFKSLoadStoreParameter.Builder(out, testPassword)
                    .withStorePBKDFConfig(config)
                    .build());
            byte[] enc = out.toByteArray();

            KeyStore reloaded = KeyStore.getInstance("BCFKS", JostleProvider.PROVIDER_NAME);
            reloaded.load(new ByteArrayInputStream(enc), testPassword);
            SecretKey seckey = (SecretKey) reloaded.getKey("seckey", testPassword);
            Assertions.assertArrayEquals(seckeyBytes, seckey.getEncoded());

            BcFKSFormat.ObjectStore store = BcFKSFormat.parseObjectStore(enc);
            BcFKSFormat.PbkdMac pbkdMac = store.integrityCheck.pbkdMac;
            Der.ScryptParams params = new Der.Reader(pbkdMac.pbkdAlgorithm.parameters).readScryptParams("scrypt-params");
            Assertions.assertEquals(1, params.parallelizationParameter);
            Assertions.assertEquals(8, params.blockSize);

            byte[] pin = BytePasswordKdf.derivationPassword(testPassword, BytePasswordKdf.PURPOSE_INTEGRITY_CHECK);
            byte[] encodedKey = new byte[params.keyLength.intValue()];
            byte[] legacyKey = new byte[params.keyLength.intValue()];
            try
            {
                BytePasswordKdf.scrypt(NISelector.MemoryHardKdfNI, pin, params.salt,
                        (int) params.costParameter, params.blockSize, params.parallelizationParameter,
                        encodedKey, 0, encodedKey.length);
                BytePasswordKdf.scrypt(NISelector.MemoryHardKdfNI, pin, params.salt,
                        (int) params.costParameter, params.blockSize, params.blockSize,
                        legacyKey, 0, legacyKey.length);

                Mac encodedMac = Mac.getInstance(pbkdMac.macAlgorithm.oid, JostleProvider.PROVIDER_NAME);
                encodedMac.init(new SecretKeySpec(encodedKey, pbkdMac.macAlgorithm.oid));
                byte[] macUnderEncodedP = encodedMac.doFinal(store.storeDataRaw);
                Assertions.assertArrayEquals(pbkdMac.mac, macUnderEncodedP);

                Mac legacyMac = Mac.getInstance(pbkdMac.macAlgorithm.oid, JostleProvider.PROVIDER_NAME);
                legacyMac.init(new SecretKeySpec(legacyKey, pbkdMac.macAlgorithm.oid));
                byte[] macUnderLegacyP = legacyMac.doFinal(store.storeDataRaw);
                Assertions.assertFalse(Arrays.areEqual(pbkdMac.mac, macUnderLegacyP),
                        "legacy-convention MAC must not coincidentally match, or this store would not isolate "
                                + "the encoded-p path");
            }
            finally
            {
                Arrays.clear(pin);
                Arrays.clear(encodedKey);
                Arrays.clear(legacyKey);
            }

            // Corrupt the actual MAC bytes: fails under NEITHER convention.
            int macOffset = indexOfSubarray(enc, pbkdMac.mac);
            Assertions.assertTrue(macOffset >= 0, "could not locate the MAC bytes in the encoded store");
            byte[] corrupted = enc.clone();
            corrupted[macOffset] ^= 1;
            KeyStore corruptedLoad = KeyStore.getInstance("BCFKS", JostleProvider.PROVIDER_NAME);
            IOException e = Assertions.assertThrows(IOException.class,
                    () -> corruptedLoad.load(new ByteArrayInputStream(corrupted), testPassword));
            Assertions.assertEquals("BCFKS KeyStore corrupted: MAC calculation failed", e.getMessage());
        }
        finally
        {
            if (old == null)
            {
                System.clearProperty(propertyName);
            }
            else
            {
                System.setProperty(propertyName, old);
            }
        }
    }

    // ---- Entry-type classification ------------------------------------------

    @Test
    public void entryTypeClassification()
    {
        Assertions.assertTrue(BcFKSKeyStoreSpi.isPrivateKeyEntryType(BcFKSFormat.ObjectData.TYPE_PRIVATE_KEY));
        Assertions.assertTrue(BcFKSKeyStoreSpi.isPrivateKeyEntryType(BcFKSFormat.ObjectData.TYPE_PROTECTED_PRIVATE_KEY));
        Assertions.assertFalse(BcFKSKeyStoreSpi.isPrivateKeyEntryType(BcFKSFormat.ObjectData.TYPE_SECRET_KEY));
        Assertions.assertFalse(BcFKSKeyStoreSpi.isPrivateKeyEntryType(BcFKSFormat.ObjectData.TYPE_PROTECTED_SECRET_KEY));
        Assertions.assertFalse(BcFKSKeyStoreSpi.isPrivateKeyEntryType(BcFKSFormat.ObjectData.TYPE_CERTIFICATE));
        Assertions.assertFalse(BcFKSKeyStoreSpi.isPrivateKeyEntryType(BcFKSFormat.ObjectData.TYPE_PBKDF_KEY));

        Assertions.assertTrue(BcFKSKeyStoreSpi.isSecretKeyEntryType(BcFKSFormat.ObjectData.TYPE_SECRET_KEY));
        Assertions.assertTrue(BcFKSKeyStoreSpi.isSecretKeyEntryType(BcFKSFormat.ObjectData.TYPE_PROTECTED_SECRET_KEY));
        Assertions.assertFalse(BcFKSKeyStoreSpi.isSecretKeyEntryType(BcFKSFormat.ObjectData.TYPE_PRIVATE_KEY));
        Assertions.assertFalse(BcFKSKeyStoreSpi.isSecretKeyEntryType(BcFKSFormat.ObjectData.TYPE_PROTECTED_PRIVATE_KEY));
        Assertions.assertFalse(BcFKSKeyStoreSpi.isSecretKeyEntryType(BcFKSFormat.ObjectData.TYPE_CERTIFICATE));
        Assertions.assertFalse(BcFKSKeyStoreSpi.isSecretKeyEntryType(BcFKSFormat.ObjectData.TYPE_PBKDF_KEY));
    }

    // ---- deriveKey: default keyLength, refusal, and caps --------------------

    private static Der.AlgorithmIdentifier algId(String oid, byte[] params) throws Exception
    {
        byte[] full = Der.algorithmIdentifier(oid, params);
        return new Der.Reader(full).readAlgorithmIdentifier("test");
    }

    private static Der.AlgorithmIdentifier pbkdf2AlgId(byte[] salt, int iterationCount, Integer keyLength)
        throws Exception
    {
        return algId("1.2.840.113549.1.5.12", Der.pbkdf2Params(salt, iterationCount, keyLength, null));
    }

    private static Der.AlgorithmIdentifier scryptAlgId(long cost, int blockSize, int parallelization,
                                                         Integer keyLength) throws Exception
    {
        return algId("1.3.6.1.4.1.11591.4.11",
                Der.scryptParams(new byte[16], cost, blockSize, parallelization, keyLength));
    }

    /** REGRESSION: r == p carries no legacy alternative; a genuine mismatch does. */
    @Test
    public void hasLegacyScryptAlternative_regression() throws Exception
    {
        Assertions.assertFalse(BcFKSKeyStoreSpi.hasLegacyScryptAlternative(scryptAlgId(1024, 8, 8, 32)));
        Assertions.assertTrue(BcFKSKeyStoreSpi.hasLegacyScryptAlternative(scryptAlgId(1024, 8, 1, 32)));
        // A non-scrypt KDF has no legacy alternative either.
        Assertions.assertFalse(BcFKSKeyStoreSpi.hasLegacyScryptAlternative(pbkdf2AlgId(new byte[16], 1000, 32)));
    }


    private static Class<? extends Throwable> loadAndCaptureExceptionClass(String providerName, byte[] data,
                                                                            char[] password)
    {
        try
        {
            KeyStore store = KeyStore.getInstance("BCFKS", providerName);
            store.load(new ByteArrayInputStream(data), password);
        }
        catch (Exception e)
        {
            return e.getClass();
        }
        Assertions.fail(providerName + " did not throw for input it should have refused");
        return null;
    }

    // ---- Write path ----------------------------------------------------
    // Real key material throughout: extracted from the KWP fixture BC itself
    // wrote (BcFKSFixtures.KWP_KEY_STORE), never freshly generated -- avoids
    // pulling a certificate builder into the test tree for material this
    // fixture already provides, verified.

    private static KeyStore freshStore(char[] storePassword) throws Exception
    {
        KeyStore ks = KeyStore.getInstance("BCFKS", JostleProvider.PROVIDER_NAME);
        ks.load(null, storePassword);
        return ks;
    }

    @Test
    public void writeThenReadRoundTrip_regression() throws Exception
    {
        KeyStore src = load(BcFKSFixtures.KWP_KEY_STORE, testPassword);
        PrivateKey privKey = (PrivateKey) src.getKey("privkey", testPassword);
        Certificate[] chain = src.getCertificateChain("privkey");
        SecretKey secret1 = (SecretKey) src.getKey("secret1", "secretPwd1".toCharArray());
        Certificate trustedCert = src.getCertificate("trusted");

        char[] storePw = "round-trip store password".toCharArray();
        char[] keyPw = "round-trip key password".toCharArray();

        KeyStore fresh = freshStore(storePw);
        fresh.setKeyEntry("mykey", privKey, keyPw, chain);
        fresh.setKeyEntry("mysecret", secret1, keyPw, null);
        fresh.setCertificateEntry("mycert", trustedCert);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        fresh.store(out, storePw);

        KeyStore reloaded = KeyStore.getInstance("BCFKS", JostleProvider.PROVIDER_NAME);
        reloaded.load(new ByteArrayInputStream(out.toByteArray()), storePw);

        Assertions.assertEquals(3, reloaded.size());
        Assertions.assertArrayEquals(privKey.getEncoded(), reloaded.getKey("mykey", keyPw).getEncoded());
        Certificate[] reloadedChain = reloaded.getCertificateChain("mykey");
        Assertions.assertEquals(chain.length, reloadedChain.length);
        for (int i = 0; i < chain.length; i++)
        {
            Assertions.assertArrayEquals(chain[i].getEncoded(), reloadedChain[i].getEncoded());
        }
        Key reloadedSecret = reloaded.getKey("mysecret", keyPw);
        Assertions.assertArrayEquals(secret1.getEncoded(), reloadedSecret.getEncoded());
        Assertions.assertEquals(secret1.getAlgorithm(), reloadedSecret.getAlgorithm());
        Assertions.assertArrayEquals(trustedCert.getEncoded(), reloaded.getCertificate("mycert").getEncoded());
    }


    // ---- Write-path negative cells, exception TYPE measured against BC ----

    private static Class<? extends Throwable> captureSetKeyEntryExceptionClass(KeyStore ks, Key key, char[] pw,
                                                                                 Certificate[] chain)
    {
        try
        {
            ks.setKeyEntry("x", key, pw, chain);
        }
        catch (Exception e)
        {
            return e.getClass();
        }
        Assertions.fail(ks.getProvider().getName() + " did not refuse an entry it should have refused");
        return null;
    }

    private static Class<? extends Throwable> captureSetCertExceptionClass(KeyStore ks, String alias,
                                                                             Certificate cert)
    {
        try
        {
            ks.setCertificateEntry(alias, cert);
        }
        catch (Exception e)
        {
            return e.getClass();
        }
        Assertions.fail(ks.getProvider().getName() + " did not refuse an entry it should have refused");
        return null;
    }

}
