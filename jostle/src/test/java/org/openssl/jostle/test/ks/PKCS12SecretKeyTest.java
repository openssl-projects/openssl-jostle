/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.ks;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.PKCS12LoadStoreParameter;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;

/**
 * Secret-key entries in JSL's PKCS12 key store and its variants: every algorithm the two PKCS#12 secretBag forms
 * can both name, written in each form and read back, through both setter APIs; the refusals; and the
 * PKCS12LoadStoreParameter that selects the form. Interop with BouncyCastle and SunJCE is in
 * KSServiceAgreementTest.
 */
public class PKCS12SecretKeyTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final char[] PASSWORD = "store password".toCharArray();
    private static final char[] WRONG = "wrong".toCharArray();

    /** Every algorithm and key length both forms name. */
    static final Object[][] SUPPORTED = {
            {"AES", 16}, {"AES", 24}, {"AES", 32}, {"ARIA", 16}, {"ARIA", 24}, {"ARIA", 32},
            {"Camellia", 16}, {"Camellia", 24}, {"Camellia", 32}, {"DESede", 24},
            {"HmacSHA1", 20}, {"HmacSHA224", 28}, {"HmacSHA256", 32}, {"HmacSHA384", 48}, {"HmacSHA512", 64},
            {"HmacSHA3-224", 28}, {"HmacSHA3-256", 32}, {"HmacSHA3-384", 48}, {"HmacSHA3-512", 64}};

    static final String[] TYPES = {"PKCS12", "PKCS12-3DES-3DES", "PKCS12-AES256-AES128", "PKCS12-PBMAC1"};

    @BeforeAll
    static void before()
    {
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    static SecretKey randomKey(String algorithm, int len)
    {
        byte[] k = new byte[len];
        RANDOM.nextBytes(k);
        return new SecretKeySpec(k, algorithm);
    }

    static byte[] store(KeyStore ks, PKCS12LoadStoreParameter.SecretKeyBagForm form, char[] password)
        throws Exception
    {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ks.store(new PKCS12LoadStoreParameter(out, new KeyStore.PasswordProtection(password), form));
        return out.toByteArray();
    }

    static KeyStore load(String type, byte[] p12, char[] password)
        throws Exception
    {
        KeyStore ks = KeyStore.getInstance(type, JSL);
        ks.load(new ByteArrayInputStream(p12), password);
        return ks;
    }

    /**
     * Every supported algorithm, every variant, both forms, both setters: the key comes back with its JCA name and
     * bytes, as a SecretKeyEntry, and entryInstanceOf answers for secret, private-key and certificate entries.
     */
    @Test
    public void everyAlgorithmRoundTripsInEveryVariantAndForm()
        throws Exception
    {
        for (String type : TYPES)
        {
            for (PKCS12LoadStoreParameter.SecretKeyBagForm form : PKCS12LoadStoreParameter.SecretKeyBagForm.values())
            {
                KeyStore ks = KeyStore.getInstance(type, JSL);
                ks.load(null, null);
                SecretKey[] keys = new SecretKey[SUPPORTED.length];
                for (int i = 0; i < SUPPORTED.length; i++)
                {
                    keys[i] = randomKey((String) SUPPORTED[i][0], (Integer) SUPPORTED[i][1]);
                    if (i % 2 == 0)
                    {
                        ks.setKeyEntry("k" + i, keys[i], PASSWORD, null);
                    }
                    else
                    {
                        ks.setEntry("k" + i, new KeyStore.SecretKeyEntry(keys[i]),
                                new KeyStore.PasswordProtection(PASSWORD));
                    }
                }
                KeyStore loaded = load(type, store(ks, form, PASSWORD), PASSWORD);
                Assertions.assertEquals(SUPPORTED.length, loaded.size(), type + " " + form);
                for (int i = 0; i < SUPPORTED.length; i++)
                {
                    String label = type + " " + form + " " + SUPPORTED[i][0] + "/" + SUPPORTED[i][1];
                    KeyStore.Entry entry = loaded.getEntry("k" + i, new KeyStore.PasswordProtection(PASSWORD));
                    Assertions.assertTrue(entry instanceof KeyStore.SecretKeyEntry, label);
                    SecretKey got = ((KeyStore.SecretKeyEntry) entry).getSecretKey();
                    Assertions.assertEquals(SUPPORTED[i][0], got.getAlgorithm(), label);
                    Assertions.assertArrayEquals(keys[i].getEncoded(), got.getEncoded(), label);
                    Assertions.assertTrue(loaded.isKeyEntry("k" + i), label);
                    Assertions.assertFalse(loaded.isCertificateEntry("k" + i), label);
                    Assertions.assertTrue(loaded.entryInstanceOf("k" + i, KeyStore.SecretKeyEntry.class), label);
                    Assertions.assertFalse(loaded.entryInstanceOf("k" + i, KeyStore.PrivateKeyEntry.class), label);
                    Assertions.assertNull(loaded.getCertificateChain("k" + i), label);
                }
            }
        }
    }

    /** A secret key, a private key with its chain, and a trusted certificate share one store in either form. */
    @Test
    public void secretKeysLiveBesidePrivateKeysAndCertificates()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", JSL);
        KeyPair pair = kpg.generateKeyPair();
        Certificate cert = KSServiceTestCertificates.selfSigned(pair);
        for (PKCS12LoadStoreParameter.SecretKeyBagForm form : PKCS12LoadStoreParameter.SecretKeyBagForm.values())
        {
            KeyStore ks = KeyStore.getInstance("PKCS12", JSL);
            ks.load(null, null);
            SecretKey secret = randomKey("AES", 32);
            ks.setKeyEntry("secret", secret, PASSWORD, null);
            ks.setKeyEntry("private", pair.getPrivate(), PASSWORD, new Certificate[]{cert});
            ks.setCertificateEntry("trusted", cert);
            KeyStore loaded = load("PKCS12", store(ks, form, PASSWORD), PASSWORD);
            Assertions.assertEquals(3, loaded.size(), form.toString());
            Assertions.assertArrayEquals(secret.getEncoded(), loaded.getKey("secret", PASSWORD).getEncoded());
            Assertions.assertArrayEquals(pair.getPrivate().getEncoded(),
                    loaded.getKey("private", PASSWORD).getEncoded());
            Assertions.assertTrue(loaded.entryInstanceOf("private", KeyStore.PrivateKeyEntry.class));
            Assertions.assertTrue(loaded.entryInstanceOf("trusted", KeyStore.TrustedCertificateEntry.class));
            Assertions.assertTrue(loaded.entryInstanceOf("secret", KeyStore.SecretKeyEntry.class));
        }
    }

    /**
     * An algorithm the two forms cannot both name is refused typed at set, whichever setter is used, with the
     * store unchanged.
     */
    @Test
    public void algorithmsWithoutAnOidInBothFormsAreRefused()
        throws Exception
    {
        Object[][] refused = {{"ChaCha20", 32}, {"Blowfish", 16}, {"DES", 8}, {"RC2", 16}, {"Generic", 16},
                {"AES", 20}, {"ARIA", 8}};
        for (Object[] r : refused)
        {
            KeyStore ks = KeyStore.getInstance("PKCS12", JSL);
            ks.load(null, null);
            SecretKey key = randomKey((String) r[0], (Integer) r[1]);
            String expected = "PKCS12 secret-key entries need an algorithm both PKCS#12 secretBag forms can name; "
                    + r[0] + " with a " + r[1] + "-byte key is not one, use BCFKS";
            KeyStoreException e = Assertions.assertThrows(KeyStoreException.class,
                    () -> ks.setKeyEntry("s", key, PASSWORD, null));
            Assertions.assertEquals(expected, e.getMessage());
            e = Assertions.assertThrows(KeyStoreException.class, () -> ks.setEntry("s",
                    new KeyStore.SecretKeyEntry(key), new KeyStore.PasswordProtection(PASSWORD)));
            Assertions.assertEquals(expected, e.getMessage());
            Assertions.assertEquals(0, ks.size());
        }
    }

    /** A chain given with a secret key is not held, and a null password is accepted, as SunJCE does. */
    @Test
    public void chainIgnoredAndNullPasswordAccepted()
        throws Exception
    {
        KeyPair pair = KeyPairGenerator.getInstance("EC", JSL).generateKeyPair();
        Certificate cert = KSServiceTestCertificates.selfSigned(pair);
        KeyStore ks = KeyStore.getInstance("PKCS12", JSL);
        ks.load(null, null);
        SecretKey key = randomKey("AES", 16);
        ks.setKeyEntry("s", key, PASSWORD, new Certificate[]{cert});
        Assertions.assertNull(ks.getCertificateChain("s"));
        Assertions.assertNull(ks.getCertificate("s"));
        ks.setKeyEntry("n", key, null, null);
        Assertions.assertArrayEquals(key.getEncoded(), ks.getKey("n", null).getEncoded());
    }

    /**
     * A secret-key entry given a protection parameter other than a password is refused typed, not cast; a null
     * parameter stays the null password.
     */
    @Test
    public void secretEntryRefusesANonPasswordProtection()
        throws Exception
    {
        KeyStore ks = KeyStore.getInstance("PKCS12", JSL);
        ks.load(null, null);
        SecretKey key = randomKey("AES", 16);
        KeyStore.ProtectionParameter callback = new KeyStore.CallbackHandlerProtection(callbacks -> {
        });
        KeyStoreException e = Assertions.assertThrows(KeyStoreException.class,
                () -> ks.setEntry("s", new KeyStore.SecretKeyEntry(key), callback));
        Assertions.assertEquals("unsupported protection parameter", e.getMessage());
        Assertions.assertFalse(ks.containsAlias("s"));
        ks.setEntry("n", new KeyStore.SecretKeyEntry(key), null);
        Assertions.assertArrayEquals(key.getEncoded(), ks.getKey("n", null).getEncoded());
    }

    /**
     * The password rules. Set in this session, a wrong password is refused. After a SunJCE-form load the entry
     * keeps the store password, so a wrong one is refused. After an RFC 7292 load the bag had no protection of its
     * own, so the key comes back whatever password is given.
     */
    @Test
    public void passwordRulesPerOrigin()
        throws Exception
    {
        KeyStore ks = KeyStore.getInstance("PKCS12", JSL);
        ks.load(null, null);
        SecretKey key = randomKey("HmacSHA256", 32);
        ks.setKeyEntry("s", key, PASSWORD, null);
        Assertions.assertThrows(UnrecoverableKeyException.class, () -> ks.getKey("s", WRONG));

        KeyStore sun = load("PKCS12",
                store(ks, PKCS12LoadStoreParameter.SecretKeyBagForm.SUNJCE, PASSWORD), PASSWORD);
        Assertions.assertArrayEquals(key.getEncoded(), sun.getKey("s", PASSWORD).getEncoded());
        Assertions.assertThrows(UnrecoverableKeyException.class, () -> sun.getKey("s", WRONG));

        KeyStore rfc = load("PKCS12",
                store(ks, PKCS12LoadStoreParameter.SecretKeyBagForm.RFC7292, PASSWORD), PASSWORD);
        Assertions.assertArrayEquals(key.getEncoded(), rfc.getKey("s", WRONG).getEncoded());
        Assertions.assertArrayEquals(key.getEncoded(), rfc.getKey("s", null).getEncoded());
    }

    /**
     * A load reads one OID, the one its form carries; the SPI sets both, so an entry read in one form is written
     * correctly in the other. Read back after each crossing with its JCA name and bytes.
     */
    @Test
    public void entriesCrossBetweenFormsAfterALoad()
        throws Exception
    {
        for (Object[] s : SUPPORTED)
        {
            SecretKey key = randomKey((String) s[0], (Integer) s[1]);
            KeyStore ks = KeyStore.getInstance("PKCS12", JSL);
            ks.load(null, null);
            ks.setKeyEntry("s", key, PASSWORD, null);
            for (PKCS12LoadStoreParameter.SecretKeyBagForm first : PKCS12LoadStoreParameter.SecretKeyBagForm.values())
            {
                PKCS12LoadStoreParameter.SecretKeyBagForm second =
                        first == PKCS12LoadStoreParameter.SecretKeyBagForm.RFC7292
                                ? PKCS12LoadStoreParameter.SecretKeyBagForm.SUNJCE
                                : PKCS12LoadStoreParameter.SecretKeyBagForm.RFC7292;
                KeyStore once = load("PKCS12", store(ks, first, PASSWORD), PASSWORD);
                KeyStore twice = load("PKCS12", store(once, second, PASSWORD), PASSWORD);
                String label = s[0] + "/" + s[1] + " " + first + " then " + second;
                java.security.Key got = twice.getKey("s", PASSWORD);
                Assertions.assertEquals(s[0], got.getAlgorithm(), label);
                Assertions.assertArrayEquals(key.getEncoded(), got.getEncoded(), label);
            }
        }
    }

    /**
     * The parameter: a null form is refused at construction, the default is RFC 7292, a foreign parameter type is
     * refused at load and at store with the key store unchanged, and a null parameter initialises an empty store.
     */
    @Test
    public void loadStoreParameterContract()
        throws Exception
    {
        NullPointerException npe = Assertions.assertThrows(NullPointerException.class,
                () -> new PKCS12LoadStoreParameter(new ByteArrayOutputStream(),
                        new KeyStore.PasswordProtection(PASSWORD), null));
        Assertions.assertEquals("secretKeyBagForm must not be null", npe.getMessage());
        Assertions.assertEquals(PKCS12LoadStoreParameter.SecretKeyBagForm.RFC7292,
                new PKCS12LoadStoreParameter(new ByteArrayOutputStream(), new KeyStore.PasswordProtection(PASSWORD))
                        .getSecretKeyBagForm());

        KeyStore ks = KeyStore.getInstance("PKCS12", JSL);
        ks.load(null, null);
        ks.setKeyEntry("s", randomKey("AES", 16), PASSWORD, null);
        KeyStore.LoadStoreParameter foreign = () -> new KeyStore.PasswordProtection(PASSWORD);
        IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class, () -> ks.load(foreign));
        Assertions.assertEquals("PKCS12LoadStoreParameter required for load", e.getMessage());
        Assertions.assertEquals(1, ks.size(), "a refused load must leave the store as it was");
        Assertions.assertTrue(ks.isKeyEntry("s"));
        e = Assertions.assertThrows(IllegalArgumentException.class, () -> ks.store(foreign));
        Assertions.assertEquals("PKCS12LoadStoreParameter required for store", e.getMessage());

        ks.load((KeyStore.LoadStoreParameter) null);
        Assertions.assertEquals(0, ks.size(), "a null parameter initialises an empty store");
    }
}
