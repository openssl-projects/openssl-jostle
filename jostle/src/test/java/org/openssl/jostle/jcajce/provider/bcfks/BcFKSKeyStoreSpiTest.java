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
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.kdf.BytePasswordKdf;
import org.openssl.jostle.util.asn1.Der;

import javax.crypto.SecretKey;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.interfaces.RSAPrivateCrtKey;
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

    /**
     * REGRESSION for the byte-password purpose derivation: this BC-written
     * store passing OUR MAC check and decrypting under OUR derivation is what
     * pins the four purpose strings and the concatenation
     * (BytePasswordKdf.derivationPassword) against real BC bytes.
     */
    @Test
    public void shouldParseKWPKeyStore() throws Exception
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", JostleProvider.PROVIDER_NAME);
        Certificate cert = cf.generateCertificate(
                new ByteArrayInputStream(BcFKSFixtures.TRUSTED_CERT_DATA));

        KeyStore store = load(BcFKSFixtures.KWP_KEY_STORE, testPassword);
        Assertions.assertEquals(4, store.size());

        SecretKey storeDesEde = (SecretKey) store.getKey("secret2", "secretPwd2".toCharArray());
        Assertions.assertEquals("DESede", storeDesEde.getAlgorithm());
        Assertions.assertArrayEquals(
                hex("010102020404070708080b0b0d0d0e0e"), storeDesEde.getEncoded());

        SecretKey storeAes = (SecretKey) store.getKey("secret1", "secretPwd1".toCharArray());
        Assertions.assertEquals("AES", storeAes.getAlgorithm());
        Assertions.assertArrayEquals(
                hex("000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f"),
                storeAes.getEncoded());

        Key storePrivKey = store.getKey("privkey", testPassword);
        Assertions.assertTrue(storePrivKey instanceof RSAPrivateCrtKey);
        Assertions.assertEquals(2, store.getCertificateChain("privkey").length);

        Certificate storeCert = store.getCertificate("trusted");
        Assertions.assertEquals(cert, storeCert);

        Assertions.assertNull(store.getCertificate("unknown"));
        Assertions.assertNull(store.getCertificateChain("unknown"));
        Assertions.assertFalse(store.isCertificateEntry("unknown"));
        Assertions.assertFalse(store.isKeyEntry("unknown"));
        Assertions.assertFalse(store.containsAlias("unknown"));
    }

    @Test
    public void shouldParseOldStoresWithPassword() throws Exception
    {
        KeyStore store = load(BcFKSFixtures.OLD_KEY_STORE, testPassword);
        checkOldStore(store);
    }

    @Test
    public void shouldParseOldStoresNoPassword() throws Exception
    {
        KeyStore store = load(BcFKSFixtures.OLD_KEY_STORE_NO_PW, null);
        checkOldStore(store);
    }

    private void checkOldStore(KeyStore store) throws Exception
    {
        Assertions.assertEquals(2, store.getCertificateChain("privkey").length);
        Assertions.assertEquals(1, store.size());
        Enumeration<String> aliases = store.aliases();
        Assertions.assertEquals("privkey", aliases.nextElement());
        Assertions.assertFalse(aliases.hasMoreElements());
    }

    /** REGRESSION: a wrong store password fails the MAC check with BC's own pinned message. */
    @Test
    public void wrongStorePasswordFailsMacCheck_regression()
    {
        KeyStore store;
        try
        {
            store = KeyStore.getInstance("BCFKS", JostleProvider.PROVIDER_NAME);
        }
        catch (Exception e)
        {
            throw new RuntimeException(e);
        }
        IOException e = Assertions.assertThrows(IOException.class,
                () -> store.load(new ByteArrayInputStream(BcFKSFixtures.OLD_KEY_STORE), invalidTestPassword));
        Assertions.assertEquals("BCFKS KeyStore corrupted: MAC calculation failed", e.getMessage());
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

    /**
     * Incorrect entry password: BC's own type (UnrecoverableKeyException,
     * failOnWrongPasswordTest r1rv86); the message text is ours.
     */
    @Test
    public void wrongEntryPasswordFailsTyped_regression() throws Exception
    {
        KeyStore store = load(BcFKSFixtures.KWP_KEY_STORE, testPassword);
        UnrecoverableKeyException e = Assertions.assertThrows(UnrecoverableKeyException.class,
                () -> store.getKey("privkey", invalidTestPassword));
        Assertions.assertTrue(e.getMessage().startsWith("BCFKS KeyStore unable to recover key (privkey):"),
                e.getMessage());
    }

    @Test
    public void engineLoadNullResetsToEmptyStore() throws Exception
    {
        KeyStore store = KeyStore.getInstance("BCFKS", JostleProvider.PROVIDER_NAME);
        store.load(null, null);
        Assertions.assertEquals(0, store.size());
    }

    @Test
    public void writeOperationsAreRefused() throws Exception
    {
        KeyStore store = load(BcFKSFixtures.KWP_KEY_STORE, testPassword);
        Assertions.assertThrows(KeyStoreException.class,
                () -> store.setCertificateEntry("x", store.getCertificate("trusted")));
        Assertions.assertThrows(KeyStoreException.class, () -> store.deleteEntry("trusted"));
        Assertions.assertThrows(IOException.class, () -> store.store(new java.io.ByteArrayOutputStream(), testPassword));
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

    /**
     * REGRESSION: JSL serves scrypt (unlike JSLFIPS -- see
     * FIPSBcFKSKeyStoreSpiTest.scryptStoreIsRefusedTyped_regression). A
     * BC-written scrypt-KDF'd store round-trips through our reader.
     */
    @Test
    public void scryptStoreLoadsUnderJsl_regression() throws Exception
    {
        KeyStore store = load(BcFKSFixtures.scryptStore(), testPassword);
        Assertions.assertEquals(1, store.size());
        Assertions.assertNotNull(store.getCertificate("cert"));
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

    /**
     * JCA contract: getKey on a certificate entry answers null. A recorded
     * divergence from BC, which throws UnrecoverableKeyException there.
     */
    @Test
    public void getKeyOnCertificateEntryReturnsNull_regression() throws Exception
    {
        KeyStore store = load(BcFKSFixtures.KWP_KEY_STORE, testPassword);
        Assertions.assertNull(store.getKey("trusted", testPassword));
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

    @Test
    public void deriveKeyDefaultsToThirtyTwoBytesWhenWireKeyLengthIsAbsent() throws Exception
    {
        // BC's own default (decryptData, r1rv86 :1554) for STORE/PRIVATE_KEY/
        // SECRET_KEY_ENCRYPTION, applied when the caller passes a default.
        BcFKSKeyStoreSpi spi = new BcFKSKeyStoreSpi(null);
        Der.AlgorithmIdentifier pbkd = pbkdf2AlgId(new byte[16], 1000, null);
        byte[] key = spi.deriveKey(pbkd, BytePasswordKdf.PURPOSE_STORE_ENCRYPTION, "x".toCharArray(), 32);
        Assertions.assertEquals(32, key.length);
    }

    @Test
    public void deriveKeyRefusesWithNoDefaultWhenWireKeyLengthIsAbsent_regression() throws Exception
    {
        // The MAC derivation's own contract: no default (BC passes -1 there),
        // the wire keyLength is required.
        BcFKSKeyStoreSpi spi = new BcFKSKeyStoreSpi(null);
        Der.AlgorithmIdentifier pbkd = pbkdf2AlgId(new byte[16], 1000, null);
        IOException e = Assertions.assertThrows(IOException.class,
                () -> spi.deriveKey(pbkd, BytePasswordKdf.PURPOSE_INTEGRITY_CHECK, "x".toCharArray(), null));
        Assertions.assertTrue(e.getMessage().contains("no keyLength found"), e.getMessage());
    }

    @Test
    public void iterationCountBeyondCapIsRefused_regression() throws Exception
    {
        BcFKSKeyStoreSpi spi = new BcFKSKeyStoreSpi(null);
        Der.AlgorithmIdentifier pbkd = pbkdf2AlgId(new byte[16],
                (int) (BcFKSKeyStoreSpi.DEFAULT_MAX_IT_COUNT + 1), 32);
        IOException e = Assertions.assertThrows(IOException.class,
                () -> spi.deriveKey(pbkd, BytePasswordKdf.PURPOSE_INTEGRITY_CHECK, "x".toCharArray(), null));
        Assertions.assertTrue(e.getMessage().contains("greater than"), e.getMessage());
    }

    @Test
    public void zeroKeyLengthIsRefused_regression() throws Exception
    {
        // Der.pbkdf2Params writes keyLength as a plain DER INTEGER, which
        // cannot itself carry a negative value the reader would decode as
        // negative (Der.Reader.readInteger refuses a negative encoding
        // outright), so the cap's lower bound (<= 0) is exercised at zero,
        // the only value that direction can reach through the wire.
        BcFKSKeyStoreSpi spi = new BcFKSKeyStoreSpi(null);
        Der.AlgorithmIdentifier pbkd = pbkdf2AlgId(new byte[16], 1000, 0);
        IOException e = Assertions.assertThrows(IOException.class,
                () -> spi.deriveKey(pbkd, BytePasswordKdf.PURPOSE_INTEGRITY_CHECK, "x".toCharArray(), null));
        Assertions.assertTrue(e.getMessage().contains("invalid keyLength"), e.getMessage());
    }

    @Test
    public void keyLengthBeyondCapIsRefused_regression() throws Exception
    {
        BcFKSKeyStoreSpi spi = new BcFKSKeyStoreSpi(null);
        Der.AlgorithmIdentifier pbkd = pbkdf2AlgId(new byte[16], 1000, 1025);
        IOException e = Assertions.assertThrows(IOException.class,
                () -> spi.deriveKey(pbkd, BytePasswordKdf.PURPOSE_INTEGRITY_CHECK, "x".toCharArray(), null));
        Assertions.assertTrue(e.getMessage().contains("greater than"), e.getMessage());
    }

    @Test
    public void scryptBlockSizeBeyondCapIsRefused_regression() throws Exception
    {
        BcFKSKeyStoreSpi spi = new BcFKSKeyStoreSpi(null);
        Der.AlgorithmIdentifier scrypt = scryptAlgId(16384, 1025, 1, 32);
        IOException e = Assertions.assertThrows(IOException.class,
                () -> spi.deriveKey(scrypt, BytePasswordKdf.PURPOSE_INTEGRITY_CHECK, "x".toCharArray(), null));
        Assertions.assertTrue(e.getMessage().contains("greater than"), e.getMessage());
    }

    /**
     * A cost parameter so large that, if the cap did not refuse it before any
     * derivation, this test would take an extremely long time (or exhaust
     * memory) rather than complete -- the completion itself is part of what
     * this asserts, not just the exception.
     */
    @Test
    public void scryptMemoryBoundIsRefusedBeforeAnyDerivation_regression() throws Exception
    {
        BcFKSKeyStoreSpi spi = new BcFKSKeyStoreSpi(null);
        Der.AlgorithmIdentifier scrypt = scryptAlgId(1 << 30, 8, 1, 32);
        IOException e = Assertions.assertThrows(IOException.class,
                () -> spi.deriveKey(scrypt, BytePasswordKdf.PURPOSE_INTEGRITY_CHECK, "x".toCharArray(), null));
        Assertions.assertTrue(e.getMessage().contains("require more than"), e.getMessage());
    }

    @Test
    public void zeroOrNegativeScryptParametersAreRefused_regression() throws Exception
    {
        BcFKSKeyStoreSpi spi = new BcFKSKeyStoreSpi(null);
        for (Der.AlgorithmIdentifier scrypt : new Der.AlgorithmIdentifier[]{
                scryptAlgId(0, 8, 1, 32), scryptAlgId(1024, 0, 1, 32), scryptAlgId(1024, 8, 0, 32)})
        {
            IOException e = Assertions.assertThrows(IOException.class,
                    () -> spi.deriveKey(scrypt, BytePasswordKdf.PURPOSE_INTEGRITY_CHECK, "x".toCharArray(), null));
            Assertions.assertTrue(e.getMessage().contains("invalid scrypt parameters"), e.getMessage());
        }
    }

    // ---- Whole-store ceiling -----------------------------------------------

    @Test
    public void wholeStoreCeilingIsEnforced_regression() throws Exception
    {
        System.setProperty("org.openssl.jostle.bcfks.max_store_bytes", "10");
        try
        {
            IOException e = Assertions.assertThrows(IOException.class,
                    () -> load(BcFKSFixtures.KWP_KEY_STORE, testPassword));
            Assertions.assertTrue(e.getMessage().contains("10-byte ceiling"), e.getMessage());
        }
        finally
        {
            System.clearProperty("org.openssl.jostle.bcfks.max_store_bytes");
        }
    }

    // ---- Exception-type parity with BouncyCastle, measured at test time ----

    private static void ensureBcProvider()
    {
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
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

    private static void assertSameExceptionClass(byte[] data, char[] password)
    {
        ensureBcProvider();
        Class<? extends Throwable> ours = loadAndCaptureExceptionClass(JostleProvider.PROVIDER_NAME, data, password);
        Class<? extends Throwable> bcs = loadAndCaptureExceptionClass("BC", data, password);
        Assertions.assertEquals(bcs, ours, "exception class diverges from BC 1.86");
    }

    @Test
    public void nonBcfksInputThrowsTheSameExceptionClassAsBc_regression()
    {
        assertSameExceptionClass(new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, testPassword);
    }

    @Test
    public void pkcs12InputThrowsTheSameExceptionClassAsBc_regression() throws Exception
    {
        KeyStore pkcs12 = KeyStore.getInstance("PKCS12", JostleProvider.PROVIDER_NAME);
        pkcs12.load(null, null);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        pkcs12.store(out, "x".toCharArray());
        assertSameExceptionClass(out.toByteArray(), "x".toCharArray());
    }

    @Test
    public void truncatedStoreThrowsTheSameExceptionClassAsBc_regression()
    {
        byte[] truncated = java.util.Arrays.copyOf(BcFKSFixtures.KWP_KEY_STORE, 50);
        assertSameExceptionClass(truncated, testPassword);
    }

    /**
     * BC returns the ENTRY's lastModifiedDate from getCreationDate, not the
     * store's own creation date (BcFKSKeyStoreSpi.java: "we return last
     * modified as it represents date current state of entry was created").
     * This pins that we do too, measured against BC 1.86 at test time rather
     * than a hardcoded date.
     */
    @Test
    public void creationDateMatchesBouncyCastlePerEntry_regression() throws Exception
    {
        ensureBcProvider();
        KeyStore ours = load(BcFKSFixtures.KWP_KEY_STORE, testPassword);
        KeyStore bc = KeyStore.getInstance("BCFKS", "BC");
        bc.load(new ByteArrayInputStream(BcFKSFixtures.KWP_KEY_STORE), testPassword);

        for (String alias : new String[]{"secret2", "secret1", "privkey", "trusted"})
        {
            Assertions.assertEquals(bc.getCreationDate(alias), ours.getCreationDate(alias), alias);
        }
    }

    @Test
    public void unrecognisedKdfOidThrowsTheSameExceptionClassAsBc_regression() throws Exception
    {
        // Hand-built: a well-formed ObjectStore wrapper whose pbkdAlgorithm
        // OID neither reader recognises. The MAC never verifies (garbage
        // bytes), so the derivation attempt -- and its refusal -- happens
        // first, before any comparison.
        byte[] macAlgId = Der.algorithmIdentifier("1.2.840.113549.2.11", new byte[]{0x05, 0x00});
        byte[] unrecognisedPbkdAlgId = Der.algorithmIdentifier("1.2.3.4.5", new byte[]{0x05, 0x00});
        byte[] pbkdMac = Der.sequence(macAlgId, unrecognisedPbkdAlgId, Der.octetString(new byte[64]));
        byte[] time = Der.generalizedTime(new java.util.Date(0L));
        byte[] storeData = Der.sequence(Der.integer(1), macAlgId, time, time, Der.sequence());
        byte[] objectStore = Der.sequence(storeData, pbkdMac);
        assertSameExceptionClass(objectStore, testPassword);
    }
}
