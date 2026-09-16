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
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.interfaces.RSAPrivateCrtKey;
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

    /**
     * REGRESSION: a store BouncyCastle 1.86 wrote with N=1024 r=8 p=1 --
     * releases up to 1.86 derived with the block size where RFC 7914 has the
     * parallelization parameter, so this only opens under that convention.
     */
    @Test
    public void legacyScryptMacStoreLoads_regression() throws Exception
    {
        KeyStore store = load(BcFKSFixtures.LEGACY_SCRYPT_KEY_STORE, testPassword);
        SecretKey seckey = (SecretKey) store.getKey("seckey", testPassword);
        Assertions.assertArrayEquals(hex("000102030405060708090a0b0c0d0e0f"), seckey.getEncoded());
    }

    /**
     * REGRESSION: same store as {@link #legacyScryptMacStoreLoads_regression},
     * signature-checked instead of MAC-checked -- a signature-checked store
     * has no MAC to settle the convention, so this exercises the retry at
     * store DECRYPTION (decryptStoreData) instead.
     */
    @Test
    public void legacyScryptSignedStoreLoads_regression() throws Exception
    {
        PublicKey verificationKey = KeyFactory.getInstance("EC", JostleProvider.PROVIDER_NAME)
                .generatePublic(new X509EncodedKeySpec(BcFKSFixtures.LEGACY_SCRYPT_SIGNED_KEY_STORE_PUB));

        KeyStore store = KeyStore.getInstance("BCFKS", JostleProvider.PROVIDER_NAME);
        store.load(new BCFKSLoadStoreParameter.Builder(
                new ByteArrayInputStream(BcFKSFixtures.LEGACY_SCRYPT_SIGNED_KEY_STORE), verificationKey).build());

        SecretKey seckey = (SecretKey) store.getKey("seckey", testPassword);
        Assertions.assertArrayEquals(hex("000102030405060708090a0b0c0d0e0f"), seckey.getEncoded());
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
        byte[] key = spi.deriveKey(pbkd, BytePasswordKdf.PURPOSE_STORE_ENCRYPTION, "x".toCharArray(), 32, false);
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
                () -> spi.deriveKey(pbkd, BytePasswordKdf.PURPOSE_INTEGRITY_CHECK, "x".toCharArray(), null, false));
        Assertions.assertTrue(e.getMessage().contains("no keyLength found"), e.getMessage());
    }

    @Test
    public void iterationCountBeyondCapIsRefused_regression() throws Exception
    {
        BcFKSKeyStoreSpi spi = new BcFKSKeyStoreSpi(null);
        Der.AlgorithmIdentifier pbkd = pbkdf2AlgId(new byte[16],
                (int) (BcFKSKeyStoreSpi.DEFAULT_MAX_IT_COUNT + 1), 32);
        IOException e = Assertions.assertThrows(IOException.class,
                () -> spi.deriveKey(pbkd, BytePasswordKdf.PURPOSE_INTEGRITY_CHECK, "x".toCharArray(), null, false));
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
                () -> spi.deriveKey(pbkd, BytePasswordKdf.PURPOSE_INTEGRITY_CHECK, "x".toCharArray(), null, false));
        Assertions.assertTrue(e.getMessage().contains("invalid keyLength"), e.getMessage());
    }

    @Test
    public void keyLengthBeyondCapIsRefused_regression() throws Exception
    {
        BcFKSKeyStoreSpi spi = new BcFKSKeyStoreSpi(null);
        Der.AlgorithmIdentifier pbkd = pbkdf2AlgId(new byte[16], 1000, 1025);
        IOException e = Assertions.assertThrows(IOException.class,
                () -> spi.deriveKey(pbkd, BytePasswordKdf.PURPOSE_INTEGRITY_CHECK, "x".toCharArray(), null, false));
        Assertions.assertTrue(e.getMessage().contains("greater than"), e.getMessage());
    }

    @Test
    public void scryptBlockSizeBeyondCapIsRefused_regression() throws Exception
    {
        BcFKSKeyStoreSpi spi = new BcFKSKeyStoreSpi(null);
        Der.AlgorithmIdentifier scrypt = scryptAlgId(16384, 1025, 1, 32);
        IOException e = Assertions.assertThrows(IOException.class,
                () -> spi.deriveKey(scrypt, BytePasswordKdf.PURPOSE_INTEGRITY_CHECK, "x".toCharArray(), null, false));
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
                () -> spi.deriveKey(scrypt, BytePasswordKdf.PURPOSE_INTEGRITY_CHECK, "x".toCharArray(), null, false));
        Assertions.assertTrue(e.getMessage().contains("require more than"), e.getMessage());
    }

    /**
     * REGRESSION: the parallelization parameter is bounded like N -- a cost
     * parameter well within the memory cap, paired with a parallelization
     * parameter alone large enough to exceed it, is refused before any
     * derivation runs (same shape as {@link
     * #scryptMemoryBoundIsRefusedBeforeAnyDerivation_regression}).
     */
    @Test
    public void scryptParallelizationBoundRefusedBeforeDerivation_regression() throws Exception
    {
        BcFKSKeyStoreSpi spi = new BcFKSKeyStoreSpi(null);
        Der.AlgorithmIdentifier scrypt = scryptAlgId(2, 8, 1 << 24, 32);
        IOException e = Assertions.assertThrows(IOException.class,
                () -> spi.deriveKey(scrypt, BytePasswordKdf.PURPOSE_INTEGRITY_CHECK, "x".toCharArray(), null, false));
        Assertions.assertTrue(e.getMessage().contains("require more than"), e.getMessage());
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

    @Test
    public void zeroOrNegativeScryptParametersAreRefused_regression() throws Exception
    {
        BcFKSKeyStoreSpi spi = new BcFKSKeyStoreSpi(null);
        for (Der.AlgorithmIdentifier scrypt : new Der.AlgorithmIdentifier[]{
                scryptAlgId(0, 8, 1, 32), scryptAlgId(1024, 0, 1, 32), scryptAlgId(1024, 8, 0, 32)})
        {
            IOException e = Assertions.assertThrows(IOException.class,
                    () -> spi.deriveKey(scrypt, BytePasswordKdf.PURPOSE_INTEGRITY_CHECK, "x".toCharArray(), null, false));
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

    /** Direction: Jostle writes, BouncyCastle 1.86 reads. */
    @Test
    public void ourWrittenStoreInteropsWithBouncyCastle_regression() throws Exception
    {
        ensureBcProvider();
        KeyStore src = load(BcFKSFixtures.KWP_KEY_STORE, testPassword);
        PrivateKey privKey = (PrivateKey) src.getKey("privkey", testPassword);
        Certificate[] chain = src.getCertificateChain("privkey");
        SecretKey secret1 = (SecretKey) src.getKey("secret1", "secretPwd1".toCharArray());
        Certificate trustedCert = src.getCertificate("trusted");

        char[] storePw = "interop store password".toCharArray();
        char[] keyPw = "interop key password".toCharArray();

        KeyStore fresh = freshStore(storePw);
        fresh.setKeyEntry("mykey", privKey, keyPw, chain);
        fresh.setKeyEntry("mysecret", secret1, keyPw, null);
        fresh.setCertificateEntry("mycert", trustedCert);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        fresh.store(out, storePw);

        KeyStore bc = KeyStore.getInstance("BCFKS", "BC");
        bc.load(new ByteArrayInputStream(out.toByteArray()), storePw);

        Assertions.assertEquals(3, bc.size());
        Assertions.assertArrayEquals(privKey.getEncoded(), bc.getKey("mykey", keyPw).getEncoded());
        Certificate[] bcChain = bc.getCertificateChain("mykey");
        Assertions.assertEquals(chain.length, bcChain.length);
        for (int i = 0; i < chain.length; i++)
        {
            Assertions.assertArrayEquals(chain[i].getEncoded(), bcChain[i].getEncoded());
        }
        Assertions.assertArrayEquals(secret1.getEncoded(), bc.getKey("mysecret", keyPw).getEncoded());
        Assertions.assertArrayEquals(trustedCert.getEncoded(), bc.getCertificate("mycert").getEncoded());

        Assertions.assertEquals(16, storeEncryptionCcmIcvBytes(out.toByteArray()));
    }

    /** The store-encryption CCM tag length this class wrote, read back off the wire. */
    private static int storeEncryptionCcmIcvBytes(byte[] storeBytes) throws Exception
    {
        BcFKSFormat.ObjectStore store = BcFKSFormat.parseObjectStore(storeBytes);
        BcFKSFormat.EncryptedObjectStoreData enc = BcFKSFormat.parseEncryptedObjectStoreData(store.storeDataRaw);
        Der.Pbes2Params pbes2 = new Der.Reader(enc.encryptionAlgorithm.parameters).readPbes2Params("PBES2-params");
        return new Der.Reader(pbes2.encryptionScheme.parameters).readCcmParameters("CCMParameters").icvBytes;
    }

    /**
     * Measured, not asserted: BC's own writer, given no explicit parameters,
     * takes whatever its Cipher defaults to for AES-256-CCM's tag -- an
     * 8-octet (64-bit) tag, not the 16 this class writes. Both interoperate
     * (the sibling test above proves BC reads our 16-octet tag; this proves
     * we read BC's 8-octet one).
     */
    @Test
    public void bcsDefaultCcmTagLengthDivergesFromOurs_regression() throws Exception
    {
        ensureBcProvider();
        KeyStore bc = KeyStore.getInstance("BCFKS", "BC");
        bc.load(null, "bc default tag password".toCharArray());
        bc.setCertificateEntry("cert", load(BcFKSFixtures.KWP_KEY_STORE, testPassword).getCertificate("trusted"));
        ByteArrayOutputStream bcOut = new ByteArrayOutputStream();
        bc.store(bcOut, "bc default tag password".toCharArray());

        Assertions.assertEquals(8, storeEncryptionCcmIcvBytes(bcOut.toByteArray()));

        // And ours still reads it.
        KeyStore ours = KeyStore.getInstance("BCFKS", JostleProvider.PROVIDER_NAME);
        ours.load(new ByteArrayInputStream(bcOut.toByteArray()), "bc default tag password".toCharArray());
        Assertions.assertEquals(1, ours.size());
    }

    /**
     * Direction: BouncyCastle 1.86 writes (the KWP fixture), Jostle reads,
     * deletes one entry, re-writes, BouncyCastle reads again -- the
     * checkStore delete-then-restore round trip (BCFKSStoreTest r1rv86
     * :1414).
     */
    @Test
    public void bcWrittenStoreLoadsThroughOursDeletesAndRestoresThroughBc_regression() throws Exception
    {
        ensureBcProvider();
        char[] storePw = testPassword;
        KeyStore ours = load(BcFKSFixtures.KWP_KEY_STORE, storePw);
        Assertions.assertEquals(4, ours.size());

        ours.deleteEntry("secret2");
        Assertions.assertEquals(3, ours.size());

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ours.store(out, storePw);

        KeyStore bc = KeyStore.getInstance("BCFKS", "BC");
        bc.load(new ByteArrayInputStream(out.toByteArray()), storePw);

        Assertions.assertEquals(3, bc.size());
        Assertions.assertFalse(bc.containsAlias("secret2"));

        SecretKey bcSecret1 = (SecretKey) bc.getKey("secret1", "secretPwd1".toCharArray());
        Assertions.assertEquals("AES", bcSecret1.getAlgorithm());
        Key bcPriv = bc.getKey("privkey", storePw);
        Assertions.assertTrue(bcPriv instanceof RSAPrivateCrtKey);
        Assertions.assertEquals(2, bc.getCertificateChain("privkey").length);
        Assertions.assertNotNull(bc.getCertificate("trusted"));
    }

    /**
     * Measured, not hardcoded: the same wrong-password failure on a store
     * BC itself wrote is the reference for what BC says about our store.
     */
    @Test
    public void wrongStorePasswordOnOurWrittenFileMatchesBcsMessage_regression() throws Exception
    {
        ensureBcProvider();
        char[] storePw = "correct store password".toCharArray();
        char[] wrongPw = "wrong store password".toCharArray();
        Certificate trustedCert = load(BcFKSFixtures.KWP_KEY_STORE, testPassword).getCertificate("trusted");

        KeyStore ours = freshStore(storePw);
        ours.setCertificateEntry("cert", trustedCert);
        ByteArrayOutputStream oursOut = new ByteArrayOutputStream();
        ours.store(oursOut, storePw);

        KeyStore bcWriter = KeyStore.getInstance("BCFKS", "BC");
        bcWriter.load(null, storePw);
        bcWriter.setCertificateEntry("cert", trustedCert);
        ByteArrayOutputStream bcOut = new ByteArrayOutputStream();
        bcWriter.store(bcOut, storePw);

        KeyStore bcReaderOfOurs = KeyStore.getInstance("BCFKS", "BC");
        IOException oursUnderBc = Assertions.assertThrows(IOException.class,
                () -> bcReaderOfOurs.load(new ByteArrayInputStream(oursOut.toByteArray()), wrongPw));

        KeyStore bcReaderOfBc = KeyStore.getInstance("BCFKS", "BC");
        IOException bcUnderBc = Assertions.assertThrows(IOException.class,
                () -> bcReaderOfBc.load(new ByteArrayInputStream(bcOut.toByteArray()), wrongPw));

        Assertions.assertEquals(bcUnderBc.getMessage(), oursUnderBc.getMessage());
    }

    @Test
    public void wrongPerKeyPasswordFailsUnrecoverableBothSides_regression() throws Exception
    {
        ensureBcProvider();
        KeyStore src = load(BcFKSFixtures.KWP_KEY_STORE, testPassword);
        PrivateKey privKey = (PrivateKey) src.getKey("privkey", testPassword);
        Certificate[] chain = src.getCertificateChain("privkey");

        char[] storePw = "wrong-key-pw store password".toCharArray();
        char[] keyPw = "correct key password".toCharArray();
        char[] wrongKeyPw = "wrong key password".toCharArray();

        KeyStore fresh = freshStore(storePw);
        fresh.setKeyEntry("mykey", privKey, keyPw, chain);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        fresh.store(out, storePw);

        KeyStore reloadedOurs = KeyStore.getInstance("BCFKS", JostleProvider.PROVIDER_NAME);
        reloadedOurs.load(new ByteArrayInputStream(out.toByteArray()), storePw);
        Assertions.assertThrows(UnrecoverableKeyException.class,
                () -> reloadedOurs.getKey("mykey", wrongKeyPw));

        KeyStore bc = KeyStore.getInstance("BCFKS", "BC");
        bc.load(new ByteArrayInputStream(out.toByteArray()), storePw);
        Assertions.assertThrows(UnrecoverableKeyException.class, () -> bc.getKey("mykey", wrongKeyPw));
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

    @Test
    public void setKeyEntryPrivateKeyWithoutChainMatchesBcExceptionType_regression() throws Exception
    {
        ensureBcProvider();
        PrivateKey privKey = (PrivateKey) load(BcFKSFixtures.KWP_KEY_STORE, testPassword)
                .getKey("privkey", testPassword);
        char[] pw = "x".toCharArray();

        KeyStore ours = freshStore(pw);
        Class<? extends Throwable> oursType = captureSetKeyEntryExceptionClass(ours, privKey, pw, null);

        KeyStore bc = KeyStore.getInstance("BCFKS", "BC");
        bc.load(null, pw);
        Class<? extends Throwable> bcType = captureSetKeyEntryExceptionClass(bc, privKey, pw, null);

        Assertions.assertEquals(bcType, oursType);
    }

    @Test
    public void setKeyEntrySecretKeyWithChainMatchesBcExceptionType_regression() throws Exception
    {
        ensureBcProvider();
        KeyStore src = load(BcFKSFixtures.KWP_KEY_STORE, testPassword);
        SecretKey secret1 = (SecretKey) src.getKey("secret1", "secretPwd1".toCharArray());
        Certificate[] chain = new Certificate[]{src.getCertificate("trusted")};
        char[] pw = "x".toCharArray();

        KeyStore ours = freshStore(pw);
        Class<? extends Throwable> oursType = captureSetKeyEntryExceptionClass(ours, secret1, pw, chain);

        KeyStore bc = KeyStore.getInstance("BCFKS", "BC");
        bc.load(null, pw);
        Class<? extends Throwable> bcType = captureSetKeyEntryExceptionClass(bc, secret1, pw, chain);

        Assertions.assertEquals(bcType, oursType);
    }

    @Test
    public void setCertificateEntryOverExistingKeyAliasMatchesBcExceptionType_regression() throws Exception
    {
        ensureBcProvider();
        KeyStore src = load(BcFKSFixtures.KWP_KEY_STORE, testPassword);
        SecretKey secret1 = (SecretKey) src.getKey("secret1", "secretPwd1".toCharArray());
        Certificate trustedCert = src.getCertificate("trusted");
        char[] pw = "x".toCharArray();

        KeyStore ours = freshStore(pw);
        ours.setKeyEntry("k", secret1, pw, null);
        Class<? extends Throwable> oursType = captureSetCertExceptionClass(ours, "k", trustedCert);

        KeyStore bc = KeyStore.getInstance("BCFKS", "BC");
        bc.load(null, pw);
        bc.setKeyEntry("k", secret1, pw, null);
        Class<? extends Throwable> bcType = captureSetCertExceptionClass(bc, "k", trustedCert);

        Assertions.assertEquals(bcType, oursType);
    }

    /**
     * Entry types 3 (PROTECTED_PRIVATE_KEY) and 4 (PROTECTED_SECRET_KEY) are
     * only reachable through the byte[]-form {@code setKeyEntry}. BC writes
     * the container; the entry payloads are built with our own {@code
     * encryptEntry} (the same helper {@code engineSetKeyEntry} uses), so
     * this proves our READ-side type-3/4 dispatch against a real BC-written
     * file, not just our own writer's shape.
     */
    @Test
    public void protectedEntryTypesWrittenByBcLoadThroughOurs_regression() throws Exception
    {
        ensureBcProvider();
        KeyStore src = load(BcFKSFixtures.KWP_KEY_STORE, testPassword);
        PrivateKey privKey = (PrivateKey) src.getKey("privkey", testPassword);
        Certificate[] chain = src.getCertificateChain("privkey");
        SecretKey secret1 = (SecretKey) src.getKey("secret1", "secretPwd1".toCharArray());

        char[] entryPw = "protected entry password".toCharArray();

        BcFKSKeyStoreSpi ourSpi = new BcFKSKeyStoreSpi(Security.getProvider(JostleProvider.PROVIDER_NAME));
        byte[] protectedPrivateKeyBytes = ourSpi.encryptEntry(privKey.getEncoded(),
                BytePasswordKdf.PURPOSE_PRIVATE_KEY_ENCRYPTION, entryPw);
        byte[] secretKeyDataBytes = BcFKSFormat.writeSecretKeyData(
                BcFKSKeyStoreSpi.secretKeyAlgorithmOid(secret1.getAlgorithm()), secret1.getEncoded());
        byte[] protectedSecretKeyBytes = ourSpi.encryptEntry(secretKeyDataBytes,
                BytePasswordKdf.PURPOSE_SECRET_KEY_ENCRYPTION, entryPw);

        char[] storePw = "protected store password".toCharArray();
        KeyStore bc = KeyStore.getInstance("BCFKS", "BC");
        bc.load(null, storePw);
        bc.setKeyEntry("protectedPriv", protectedPrivateKeyBytes, chain);
        bc.setKeyEntry("protectedSecret", protectedSecretKeyBytes, null);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        bc.store(out, storePw);

        KeyStore ours = KeyStore.getInstance("BCFKS", JostleProvider.PROVIDER_NAME);
        ours.load(new ByteArrayInputStream(out.toByteArray()), storePw);

        Assertions.assertTrue(ours.isKeyEntry("protectedPriv"));
        Key recoveredPriv = ours.getKey("protectedPriv", entryPw);
        Assertions.assertArrayEquals(privKey.getEncoded(), recoveredPriv.getEncoded());
        Assertions.assertEquals(chain.length, ours.getCertificateChain("protectedPriv").length);

        Assertions.assertTrue(ours.isKeyEntry("protectedSecret"));
        Key recoveredSecret = ours.getKey("protectedSecret", entryPw);
        Assertions.assertArrayEquals(secret1.getEncoded(), recoveredSecret.getEncoded());
    }
}
