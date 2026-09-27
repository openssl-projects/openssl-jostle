//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

package org.openssl.jostle.test.ks;

import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS12PfxPdu;
import org.bouncycastle.pkcs.PKCS12PfxPduBuilder;
import org.bouncycastle.pkcs.PKCS12SafeBagBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS12SafeBagBuilder;
import org.bouncycastle.pkcs.jcajce.JcePKCS12MacCalculatorBuilder;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEOutputEncryptorBuilder;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * Cross-validates Jostle's PKCS#12 KeyStore against BouncyCastle: for every
 * BC-parity profile, a keystore written by one provider must load (key + chain)
 * in the other. This catches wrong-but-self-consistent output that a Jostle-only
 * round-trip cannot. Random RSA keys + fresh self-signed certs per trial.
 *
 * <p>Only profiles whose algorithms live in OpenSSL's default provider are
 * exercised both ways. BouncyCastle's bare {@code PKCS12} default encrypts certs
 * with 40-bit RC2 (legacy-provider only), so a BC-written bare keystore is not
 * Jostle-readable and is therefore excluded from the BC&rarr;Jostle direction.
 */
public class KSServiceAgreementTest
{
    private static final int TRIALS = 4;

    @BeforeAll
    public static void setUp()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"PKCS12", "PKCS12-3DES-3DES", "PKCS12-AES256-AES128", "PKCS12-PBMAC1"})
    public void jostleWritesBouncyCastleReads(String type)
        throws Exception
    {
        for (int trial = 0; trial < TRIALS; trial++)
        {
            char[] password = ("agree-jostle-" + trial).toCharArray();
            KeyPair keyPair = newRsaKeyPair(JostleProvider.PROVIDER_NAME);
            X509Certificate cert = selfSignedCertificate(keyPair,
                    "CN=Jostle Agreement " + type + " " + trial,
                    BigInteger.valueOf(trial + 1L));

            KeyStore jostle = KeyStore.getInstance(type, JostleProvider.PROVIDER_NAME);
            jostle.load(null, null);
            jostle.setKeyEntry("key", keyPair.getPrivate(), password,
                    new Certificate[] {cert});
            byte[] encoded = store(jostle, password);

            // BC's PKCS12 reader is algorithm-agnostic; read whatever Jostle wrote.
            KeyStore bc = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
            bc.load(new ByteArrayInputStream(encoded), password);
            assertKeyAndChain(bc, keyPair.getPrivate(), cert, password);
        }
    }

    // PKCS12-PBMAC1 is intentionally excluded from this direction: BouncyCastle's
    // PBMAC1 derives a 256-octet PBKDF2 MAC key, but OpenSSL's PKCS12_verify_mac
    // rejects a PBMAC1 key longer than EVP_MAX_MD_SIZE (64 bytes), so Jostle
    // cannot verify a BC-written PBMAC1 keystore. The reverse works -- Jostle's
    // 64-octet PBMAC1 output is read by BouncyCastle (see the test above).
    @ParameterizedTest
    @ValueSource(strings = {"PKCS12-3DES-3DES", "PKCS12-AES256-AES128"})
    public void bouncyCastleWritesJostleReads(String type)
        throws Exception
    {
        for (int trial = 0; trial < TRIALS; trial++)
        {
            char[] password = ("agree-bc-" + trial).toCharArray();
            KeyPair keyPair = newRsaKeyPair(BouncyCastleProvider.PROVIDER_NAME);
            X509Certificate cert = selfSignedCertificate(keyPair,
                    "CN=BC Agreement " + type + " " + trial,
                    BigInteger.valueOf(trial + 1L));

            KeyStore bc = KeyStore.getInstance(type, BouncyCastleProvider.PROVIDER_NAME);
            bc.load(null, null);
            bc.setKeyEntry("key", keyPair.getPrivate(), password,
                    new Certificate[] {cert});
            byte[] encoded = store(bc, password);

            KeyStore jostle = KeyStore.getInstance("PKCS12", JostleProvider.PROVIDER_NAME);
            jostle.load(new ByteArrayInputStream(encoded), password);
            assertKeyAndChain(jostle, keyPair.getPrivate(), cert, password);
        }
    }

    /**
     * A BouncyCastle-built PKCS#12 where the certificate carries a DIFFERENT
     * friendlyName than the key's alias but the SAME localKeyId. Jostle must
     * associate the cert to the key by localKeyId (the convention strict readers
     * use), not by friendlyName. friendlyName-only grouping -- the behaviour
     * before the read-side fix -- would orphan the cert under its own name and
     * leave getCertificateChain(keyAlias) null. This isolates the localKeyId
     * precedence that the standard agreement tests cannot (there the two always
     * agree, so a broken localKeyId path is masked by the friendlyName fallback).
     */
    @Test
    public void bouncyCastleLocalKeyIdAssociatesCertWhenFriendlyNameDiffers()
        throws Exception
    {
        char[] password = "agree-localkeyid".toCharArray();
        KeyPair keyPair = newRsaKeyPair(JostleProvider.PROVIDER_NAME);
        X509Certificate cert = selfSignedCertificate(keyPair,
                "CN=Jostle localKeyId Agreement", BigInteger.valueOf(99));

        byte[] keyId = new byte[20];
        new java.security.SecureRandom().nextBytes(keyId);

        OutputEncryptor keyEncryptor = new JcePKCSPBEOutputEncryptorBuilder(
                NISTObjectIdentifiers.id_aes256_CBC)
                .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(password);

        PKCS12SafeBagBuilder keyBag =
                new JcaPKCS12SafeBagBuilder(keyPair.getPrivate(), keyEncryptor);
        keyBag.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
                new DERBMPString("the-key-alias"));
        keyBag.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId,
                new DEROctetString(keyId));

        PKCS12SafeBagBuilder certBag = new JcaPKCS12SafeBagBuilder(cert);
        certBag.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
                new DERBMPString("a-different-cert-name"));
        certBag.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId,
                new DEROctetString(keyId));

        PKCS12PfxPduBuilder pfxBuilder = new PKCS12PfxPduBuilder();
        pfxBuilder.addData(keyBag.build());
        pfxBuilder.addData(certBag.build());
        PKCS12PfxPdu pfx = pfxBuilder.build(
                new JcePKCS12MacCalculatorBuilder()
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME), password);
        byte[] encoded = pfx.getEncoded();

        KeyStore jostle = KeyStore.getInstance("PKCS12", JostleProvider.PROVIDER_NAME);
        jostle.load(new ByteArrayInputStream(encoded), password);

        Assertions.assertEquals(1, jostle.size());
        Assertions.assertTrue(jostle.isKeyEntry("the-key-alias"));
        Assertions.assertFalse(jostle.containsAlias("a-different-cert-name"));
        Assertions.assertNotNull(jostle.getKey("the-key-alias", password));

        Certificate[] chain = jostle.getCertificateChain("the-key-alias");
        Assertions.assertNotNull(chain);
        Assertions.assertEquals(1, chain.length);
        Assertions.assertArrayEquals(cert.getEncoded(), chain[0].getEncoded());
    }

    private static void assertKeyAndChain(KeyStore ks, PrivateKey expectedKey,
                                          X509Certificate expectedCert, char[] password)
        throws Exception
    {
        Assertions.assertTrue(ks.containsAlias("key"));
        Assertions.assertTrue(ks.isKeyEntry("key"));

        PrivateKey key = (PrivateKey) ks.getKey("key", password);
        Assertions.assertNotNull(key);
        Assertions.assertArrayEquals(expectedKey.getEncoded(), key.getEncoded());

        Certificate[] chain = ks.getCertificateChain("key");
        Assertions.assertNotNull(chain);
        Assertions.assertEquals(1, chain.length);
        Assertions.assertArrayEquals(expectedCert.getEncoded(), chain[0].getEncoded());
    }

    private static byte[] store(KeyStore ks, char[] password)
        throws Exception
    {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ks.store(out, password);
        return out.toByteArray();
    }

    private static KeyPair newRsaKeyPair(String provider)
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", provider);
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    private static X509Certificate selfSignedCertificate(KeyPair keyPair, String dn,
                                                         BigInteger serial)
        throws Exception
    {
        X500Name name = new X500Name(dn);
        Date notBefore = new Date(System.currentTimeMillis() - 3600_000L);
        Date notAfter = new Date(System.currentTimeMillis() + 3600_000L);
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                name, serial, notBefore, notAfter, name, keyPair.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(keyPair.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }

    /**
     * The engineGetEntry protection-parameter contract must match BouncyCastle
     * (whose PKCS12 SPI inherits the java.security.KeyStoreSpi base). For each
     * parameter shape on a key entry and a trusted-cert entry, Jostle and BC
     * must throw the same exception type -- or both succeed.
     */
    @Test
    public void getEntryProtectionParameterMatchesBouncyCastle()
        throws Exception
    {
        char[] password = "agree-getentry".toCharArray();
        KeyPair keyPair = newRsaKeyPair(BouncyCastleProvider.PROVIDER_NAME);
        X509Certificate keyCert = selfSignedCertificate(keyPair,
                "CN=Agreement getEntry key", BigInteger.valueOf(101));
        KeyPair trustedPair = newRsaKeyPair(BouncyCastleProvider.PROVIDER_NAME);
        X509Certificate trustedCert = selfSignedCertificate(trustedPair,
                "CN=Agreement getEntry trusted", BigInteger.valueOf(102));

        KeyStore jostle = populatedStore(JostleProvider.PROVIDER_NAME,
                keyPair, keyCert, password, trustedCert);
        KeyStore bc = populatedStore(BouncyCastleProvider.PROVIDER_NAME,
                keyPair, keyCert, password, trustedCert);

        KeyStore.ProtectionParameter pwd = new KeyStore.PasswordProtection(password);
        KeyStore.ProtectionParameter cbh =
                new KeyStore.CallbackHandlerProtection(callbacks -> { });

        assertSameOutcome("getEntry(key, null)", jostle, bc,
                ks -> ks.getEntry("key", null));
        assertSameOutcome("getEntry(key, password)", jostle, bc,
                ks -> ks.getEntry("key", pwd));
        assertSameOutcome("getEntry(key, callbackHandler)", jostle, bc,
                ks -> ks.getEntry("key", cbh));
        assertSameOutcome("getEntry(trusted, null)", jostle, bc,
                ks -> ks.getEntry("trusted", null));
        assertSameOutcome("getEntry(trusted, password)", jostle, bc,
                ks -> ks.getEntry("trusted", pwd));
        assertSameOutcome("getEntry(trusted, callbackHandler)", jostle, bc,
                ks -> ks.getEntry("trusted", cbh));
    }

    /**
     * The engineSetEntry protection-parameter contract must match BouncyCastle:
     * only a PasswordProtection (or null where the entry permits it) is
     * accepted; other parameter types are rejected with the same exception type.
     */
    @Test
    public void setEntryProtectionParameterMatchesBouncyCastle()
        throws Exception
    {
        char[] password = "agree-setentry".toCharArray();
        KeyPair keyPair = newRsaKeyPair(BouncyCastleProvider.PROVIDER_NAME);
        X509Certificate keyCert = selfSignedCertificate(keyPair,
                "CN=Agreement setEntry key", BigInteger.valueOf(103));
        KeyPair trustedPair = newRsaKeyPair(BouncyCastleProvider.PROVIDER_NAME);
        X509Certificate trustedCert = selfSignedCertificate(trustedPair,
                "CN=Agreement setEntry trusted", BigInteger.valueOf(104));

        KeyStore jostle = emptyStore(JostleProvider.PROVIDER_NAME);
        KeyStore bc = emptyStore(BouncyCastleProvider.PROVIDER_NAME);

        KeyStore.Entry keyEntry = new KeyStore.PrivateKeyEntry(
                keyPair.getPrivate(), new Certificate[] {keyCert});
        KeyStore.Entry certEntry = new KeyStore.TrustedCertificateEntry(trustedCert);
        KeyStore.ProtectionParameter pwd = new KeyStore.PasswordProtection(password);
        KeyStore.ProtectionParameter cbh =
                new KeyStore.CallbackHandlerProtection(callbacks -> { });

        assertSameOutcome("setEntry(key, password)", jostle, bc,
                ks -> ks.setEntry("k-pwd", keyEntry, pwd));
        assertSameOutcome("setEntry(key, callbackHandler)", jostle, bc,
                ks -> ks.setEntry("k-cbh", keyEntry, cbh));
        assertSameOutcome("setEntry(key, null)", jostle, bc,
                ks -> ks.setEntry("k-null", keyEntry, null));
        assertSameOutcome("setEntry(trusted, callbackHandler)", jostle, bc,
                ks -> ks.setEntry("c-cbh", certEntry, cbh));
        assertSameOutcome("setEntry(trusted, null)", jostle, bc,
                ks -> ks.setEntry("c-null", certEntry, null));
    }

    private static KeyStore emptyStore(String provider)
        throws Exception
    {
        KeyStore keyStore = KeyStore.getInstance("PKCS12", provider);
        keyStore.load(null, null);
        return keyStore;
    }

    private static KeyStore populatedStore(String provider, KeyPair keyPair,
                                           X509Certificate keyCert, char[] password,
                                           X509Certificate trustedCert)
        throws Exception
    {
        KeyStore keyStore = emptyStore(provider);
        keyStore.setKeyEntry("key", keyPair.getPrivate(), password,
                new Certificate[] {keyCert});
        keyStore.setCertificateEntry("trusted", trustedCert);
        return keyStore;
    }

    private interface KsOp
    {
        void run(KeyStore keyStore)
            throws Exception;
    }

    private static Class<? extends Throwable> outcome(KeyStore keyStore, KsOp op)
    {
        try
        {
            op.run(keyStore);
            return null;
        }
        catch (Throwable t)
        {
            return t.getClass();
        }
    }

    private static void assertSameOutcome(String label, KeyStore jostle, KeyStore bc,
                                          KsOp op)
    {
        Class<? extends Throwable> bcOutcome = outcome(bc, op);
        Class<? extends Throwable> jostleOutcome = outcome(jostle, op);
        Assertions.assertEquals(bcOutcome, jostleOutcome,
                label + ": BouncyCastle => " + bcOutcome
                        + " but Jostle => " + jostleOutcome);
    }

    // -----------------------------------------------------------------
    // Secret-key entries (PKCS#12 secretBag): JSL against BouncyCastle and SunJCE, both forms
    // -----------------------------------------------------------------

    private static final char[] SK_PASSWORD = "secret store".toCharArray();
    private static final String BC_ALLOW_SUN = "org.bouncycastle.pkcs12.allow_sun_secret_keys";

    /** The JDK's own PKCS12 key store: provider SUN from JDK 9, SunJSSE on JDK 8. */
    private static KeyStore sunKeyStore()
        throws Exception
    {
        for (String name : new String[]{"SUN", "SunJSSE"})
        {
            java.security.Provider p = Security.getProvider(name);
            if (p != null && p.getService("KeyStore", "PKCS12") != null)
            {
                KeyStore ks = KeyStore.getInstance("PKCS12", p);
                return ks;
            }
        }
        throw new IllegalStateException("no JDK PKCS12 key store");
    }

    private static boolean jdk8()
    {
        return System.getProperty("java.specification.version").startsWith("1.");
    }

    /**
     * BouncyCastle's writer types JSL can read: BouncyCastle's plain "PKCS12" encrypts its safe with
     * pbeWithSHAAnd40BitRC2-CBC, which OpenSSL 3's default provider does not implement.
     */
    private static final String[] BC_READABLE_TYPES = {"PKCS12-3DES-3DES", "PKCS12-AES256-AES128"};

    /**
     * The JDK's PKCS12 key store refuses some secret keys at set on older JDKs, measured: DESede, the HmacSHA3
     * family and RC2 on JDK 8; DESede and RC2 on JDK 11; RC2 on JDK 17; none from JDK 21. The keys it stores on
     * this JDK are the ones interop is checked with; a refusal outside that set, or any refusal from JDK 21, fails.
     */
    private static final java.util.Set<String> SUN_HISTORICAL_GAPS = new java.util.HashSet<String>(
            java.util.Arrays.asList("DESede", "HmacSHA3-224", "HmacSHA3-256", "HmacSHA3-384", "HmacSHA3-512",
                    "RC2"));

    private static int jdkFeature()
    {
        String v = System.getProperty("java.specification.version");
        return v.startsWith("1.") ? Integer.parseInt(v.substring(2)) : Integer.parseInt(v);
    }

    private static javax.crypto.SecretKey[] sunStorable(javax.crypto.SecretKey[] keys)
        throws Exception
    {
        java.util.List<javax.crypto.SecretKey> out = new java.util.ArrayList<javax.crypto.SecretKey>();
        for (javax.crypto.SecretKey key : keys)
        {
            KeyStore probe = sunKeyStore();
            probe.load(null, null);
            try
            {
                probe.setEntry("p", new KeyStore.SecretKeyEntry(key), new KeyStore.PasswordProtection(SK_PASSWORD));
                out.add(key);
            }
            catch (java.security.KeyStoreException e)
            {
                Assertions.assertTrue(jdkFeature() < 21 && SUN_HISTORICAL_GAPS.contains(key.getAlgorithm()),
                        "SunJCE refused " + key.getAlgorithm() + " on JDK " + jdkFeature() + ": " + e);
                Assertions.assertTrue(e.getMessage().startsWith("Key protection algorithm not found"), e.getMessage());
            }
        }
        return out.toArray(new javax.crypto.SecretKey[0]);
    }

    private static javax.crypto.SecretKey secret(String algorithm, int len)
    {
        byte[] k = new byte[len];
        new java.security.SecureRandom().nextBytes(k);
        return new javax.crypto.spec.SecretKeySpec(k, algorithm);
    }

    private static byte[] storeSecrets(KeyStore ks, javax.crypto.SecretKey[] keys,
                                       org.openssl.jostle.jcajce.PKCS12LoadStoreParameter.SecretKeyBagForm form)
        throws Exception
    {
        ks.load(null, null);
        for (int i = 0; i < keys.length; i++)
        {
            ks.setEntry("k" + i, new KeyStore.SecretKeyEntry(keys[i]), new KeyStore.PasswordProtection(SK_PASSWORD));
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        if (form == null)
        {
            ks.store(out, SK_PASSWORD);
        }
        else
        {
            ks.store(new org.openssl.jostle.jcajce.PKCS12LoadStoreParameter(out,
                    new KeyStore.PasswordProtection(SK_PASSWORD), form));
        }
        return out.toByteArray();
    }

    private static javax.crypto.SecretKey[] supportedKeys()
    {
        Object[][] algs = PKCS12SecretKeyTest.SUPPORTED;
        javax.crypto.SecretKey[] keys = new javax.crypto.SecretKey[algs.length];
        for (int i = 0; i < algs.length; i++)
        {
            keys[i] = secret((String) algs[i][0], (Integer) algs[i][1]);
        }
        return keys;
    }

    private static void assertReads(KeyStore reader, byte[] p12, javax.crypto.SecretKey[] keys, String label)
        throws Exception
    {
        reader.load(new ByteArrayInputStream(p12), SK_PASSWORD);
        for (int i = 0; i < keys.length; i++)
        {
            java.security.Key got = reader.getKey("k" + i, SK_PASSWORD);
            String what = label + " " + keys[i].getAlgorithm() + "/" + keys[i].getEncoded().length;
            Assertions.assertNotNull(got, what);
            Assertions.assertArrayEquals(keys[i].getEncoded(), got.getEncoded(), what);
            Assertions.assertTrue(keys[i].getAlgorithm().equalsIgnoreCase(got.getAlgorithm()),
                    what + " read as " + got.getAlgorithm());
        }
    }

    /**
     * SunJCE names a secret key through the providers registered in the JVM, so ARIA and Camellia can come back
     * under their OID. The name JSL's file reads as is therefore compared with the name SunJCE's own file reads as
     * in the same JVM, and the bytes with the key. Where SunJCE names its own key by OID, it writes an OID of its
     * own (JDK 8 names ARIA by id-aria256-ofb), so JSL's key must then come back under an OID too.
     */
    private static void assertSunReadsLikeItsOwn(byte[] p12, javax.crypto.SecretKey[] keys, String label)
        throws Exception
    {
        KeyStore own = sunKeyStore();
        own.load(new ByteArrayInputStream(storeSecrets(sunKeyStore(), keys, null)), SK_PASSWORD);
        KeyStore read = sunKeyStore();
        read.load(new ByteArrayInputStream(p12), SK_PASSWORD);
        for (int i = 0; i < keys.length; i++)
        {
            java.security.Key got = read.getKey("k" + i, SK_PASSWORD);
            String what = label + " " + keys[i].getAlgorithm() + "/" + keys[i].getEncoded().length;
            Assertions.assertNotNull(got, what);
            Assertions.assertArrayEquals(keys[i].getEncoded(), got.getEncoded(), what);
            String ownName = own.getKey("k" + i, SK_PASSWORD).getAlgorithm();
            if (Character.isDigit(ownName.charAt(0)))
            {
                Assertions.assertTrue(Character.isDigit(got.getAlgorithm().charAt(0)), what + " " + got.getAlgorithm());
            }
            else
            {
                Assertions.assertEquals(ownName, got.getAlgorithm(), what);
            }
        }
    }

    @Test
    public void secretKeys_jslDefaultFormBouncyCastleReads()
        throws Exception
    {
        javax.crypto.SecretKey[] keys = supportedKeys();
        byte[] p12 = storeSecrets(KeyStore.getInstance("PKCS12", JostleProvider.PROVIDER_NAME), keys, null);
        assertReads(KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME), p12, keys, "JSL->BC");
    }

    @Test
    public void secretKeys_bouncyCastleWritesJslReads()
        throws Exception
    {
        javax.crypto.SecretKey[] keys = supportedKeys();
        for (String type : BC_READABLE_TYPES)
        {
            byte[] p12 = storeSecrets(KeyStore.getInstance(type, BouncyCastleProvider.PROVIDER_NAME), keys, null);
            assertReads(KeyStore.getInstance("PKCS12", JostleProvider.PROVIDER_NAME), p12, keys,
                    "BC " + type + "->JSL");
        }
    }

    @Test
    public void secretKeys_sunWritesJslReads()
        throws Exception
    {
        javax.crypto.SecretKey[] keys = sunStorable(supportedKeys());
        byte[] p12 = storeSecrets(sunKeyStore(), keys, null);
        assertReads(KeyStore.getInstance("PKCS12", JostleProvider.PROVIDER_NAME), p12, keys, "SUN->JSL");
    }

    @Test
    public void secretKeys_jslSunFormSunReads()
        throws Exception
    {
        javax.crypto.SecretKey[] keys = sunStorable(supportedKeys());
        byte[] jslFile = storeSecrets(KeyStore.getInstance("PKCS12", JostleProvider.PROVIDER_NAME), keys,
                org.openssl.jostle.jcajce.PKCS12LoadStoreParameter.SecretKeyBagForm.SUNJCE);
        assertSunReadsLikeItsOwn(jslFile, keys, "JSL(SUNJCE)->SUN");
    }

    /**
     * A file read in one form and written by JSL in the other reaches that form's reader: SunJCE's file stored by
     * default reads in BouncyCastle, and BouncyCastle's file stored in the SunJCE form reads in SunJCE.
     */
    @Test
    public void secretKeys_crossFormRewriteReachesTheOtherReader()
        throws Exception
    {
        javax.crypto.SecretKey[] keys = sunStorable(supportedKeys());
        KeyStore jsl = KeyStore.getInstance("PKCS12", JostleProvider.PROVIDER_NAME);
        jsl.load(new ByteArrayInputStream(storeSecrets(sunKeyStore(), keys, null)), SK_PASSWORD);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        jsl.store(out, SK_PASSWORD);
        assertReads(KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME), out.toByteArray(), keys,
                "SUN->JSL->BC");

        jsl = KeyStore.getInstance("PKCS12", JostleProvider.PROVIDER_NAME);
        jsl.load(new ByteArrayInputStream(storeSecrets(
                KeyStore.getInstance(BC_READABLE_TYPES[0], BouncyCastleProvider.PROVIDER_NAME), keys, null)),
                SK_PASSWORD);
        out = new ByteArrayOutputStream();
        jsl.store(new org.openssl.jostle.jcajce.PKCS12LoadStoreParameter(out,
                new KeyStore.PasswordProtection(SK_PASSWORD),
                org.openssl.jostle.jcajce.PKCS12LoadStoreParameter.SecretKeyBagForm.SUNJCE));
        assertSunReadsLikeItsOwn(out.toByteArray(), keys, "BC->JSL(SUNJCE)->SUN");
    }

    /**
     * Divergence, pinned in both halves: SunJCE cannot read the RFC 7292 form, whether BouncyCastle or JSL wrote
     * it; the store loads and getKey refuses. BouncyCastle's own file is the control.
     */
    @Test
    public void secretKeys_divergence_sunCannotReadTheRfcForm()
        throws Exception
    {
        javax.crypto.SecretKey[] keys = {secret("AES", 16)};
        byte[][] files = {
                storeSecrets(KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME), keys, null),
                storeSecrets(KeyStore.getInstance("PKCS12", JostleProvider.PROVIDER_NAME), keys, null)};
        for (byte[] p12 : files)
        {
            KeyStore sun = sunKeyStore();
            sun.load(new ByteArrayInputStream(p12), SK_PASSWORD);
            Assertions.assertThrows(java.security.UnrecoverableKeyException.class,
                    () -> sun.getKey("k0", SK_PASSWORD));
        }
    }

    /**
     * Divergence, pinned in both halves: BouncyCastle reads the SunJCE form only with its opt-in property set.
     * Without it the load is refused naming the secretBag type; with it the key is read. The property is global
     * state, so it is restored and the restoration asserted.
     */
    @Test
    public void secretKeys_divergence_bouncyCastleReadsSunFormOnlyWhenAllowed()
        throws Exception
    {
        javax.crypto.SecretKey[] keys = {secret("HmacSHA256", 32)};
        byte[] p12 = storeSecrets(KeyStore.getInstance("PKCS12", JostleProvider.PROVIDER_NAME), keys,
                org.openssl.jostle.jcajce.PKCS12LoadStoreParameter.SecretKeyBagForm.SUNJCE);
        String before = System.getProperty(BC_ALLOW_SUN);
        try
        {
            System.clearProperty(BC_ALLOW_SUN);
            KeyStore refused = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
            java.io.IOException e = Assertions.assertThrows(java.io.IOException.class,
                    () -> refused.load(new ByteArrayInputStream(p12), SK_PASSWORD));
            Assertions.assertEquals("unrecognised PKCS12 secretBag algorithm: 1.2.840.113549.1.12.10.1.2",
                    e.getMessage());

            System.setProperty(BC_ALLOW_SUN, "true");
            KeyStore allowed = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
            allowed.load(new ByteArrayInputStream(p12), SK_PASSWORD);
            Assertions.assertArrayEquals(keys[0].getEncoded(), allowed.getKey("k0", SK_PASSWORD).getEncoded());
        }
        finally
        {
            if (before == null)
            {
                System.clearProperty(BC_ALLOW_SUN);
            }
            else
            {
                System.setProperty(BC_ALLOW_SUN, before);
            }
        }
        Assertions.assertEquals(before, System.getProperty(BC_ALLOW_SUN), "the property must be restored");
    }

    /**
     * Divergence rows: SunJCE also stores Blowfish, DES and RC2 keys, which have no RFC 7292 OID BouncyCastle
     * writes, so JSL refuses them; SunJCE drops a chain given with a secret key, as JSL does (the control), where
     * BouncyCastle keeps it in memory.
     */
    @Test
    public void secretKeys_divergence_extrasAndChains()
        throws Exception
    {
        for (Object[] x : new Object[][]{{"Blowfish", 16}, {"DES", 8}, {"RC2", 16}})
        {
            javax.crypto.SecretKey key = secret((String) x[0], (Integer) x[1]);
            if (sunStorable(new javax.crypto.SecretKey[]{key}).length == 1)
            {
                KeyStore sun = sunKeyStore();
                sun.load(null, null);
                sun.setKeyEntry("s", key, SK_PASSWORD, null);
                Assertions.assertTrue(sun.isKeyEntry("s"), "SunJCE stores " + x[0]);
            }
            KeyStore jsl = KeyStore.getInstance("PKCS12", JostleProvider.PROVIDER_NAME);
            jsl.load(null, null);
            Assertions.assertThrows(java.security.KeyStoreException.class,
                    () -> jsl.setKeyEntry("s", key, SK_PASSWORD, null), "JSL refuses " + x[0]);
        }

        KeyPair pair = newRsaKeyPair(BouncyCastleProvider.PROVIDER_NAME);
        Certificate[] chain = {selfSignedCertificate(pair, "CN=secret chain", BigInteger.ONE)};
        javax.crypto.SecretKey key = secret("AES", 16);
        KeyStore bc = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
        bc.load(null, null);
        bc.setKeyEntry("s", key, SK_PASSWORD, chain);
        Assertions.assertEquals(1, bc.getCertificateChain("s").length, "BouncyCastle keeps the chain in memory");
        KeyStore sun = sunKeyStore();
        sun.load(null, null);
        sun.setKeyEntry("s", key, SK_PASSWORD, chain);
        Assertions.assertNull(sun.getCertificateChain("s"), "SunJCE holds no chain for a secret key");
        KeyStore jsl = KeyStore.getInstance("PKCS12", JostleProvider.PROVIDER_NAME);
        jsl.load(null, null);
        jsl.setKeyEntry("s", key, SK_PASSWORD, chain);
        Assertions.assertNull(jsl.getCertificateChain("s"), "JSL holds no chain for a secret key");
    }

    /**
     * Password rules, pinned against both peers. BouncyCastle returns a secret key whatever password is given, in
     * memory and after an RFC 7292 load; JSL agrees after that load (the bag carries no protection) and refuses a
     * wrong password in memory (a divergence). SunJCE refuses a wrong password, in memory and after a load of its
     * own form, as JSL does after a SunJCE-form load.
     */
    @Test
    public void secretKeys_passwordRulesAgainstBothPeers()
        throws Exception
    {
        char[] wrong = "wrong".toCharArray();
        javax.crypto.SecretKey[] keys = {secret("AES", 32)};

        KeyStore bc = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
        byte[] bcFile = storeSecrets(bc, keys, null);
        Assertions.assertNotNull(bc.getKey("k0", wrong), "BouncyCastle in memory ignores the password");
        KeyStore jslMemory = KeyStore.getInstance("PKCS12", JostleProvider.PROVIDER_NAME);
        byte[] jslRfc = storeSecrets(jslMemory, keys, null);
        Assertions.assertThrows(java.security.UnrecoverableKeyException.class,
                () -> jslMemory.getKey("k0", wrong), "JSL in memory checks the password");

        KeyStore bcLoaded = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
        bcLoaded.load(new ByteArrayInputStream(bcFile), SK_PASSWORD);
        Assertions.assertNotNull(bcLoaded.getKey("k0", wrong));
        KeyStore jslLoaded = KeyStore.getInstance("PKCS12", JostleProvider.PROVIDER_NAME);
        jslLoaded.load(new ByteArrayInputStream(jslRfc), SK_PASSWORD);
        Assertions.assertArrayEquals(keys[0].getEncoded(), jslLoaded.getKey("k0", wrong).getEncoded());

        KeyStore sun = sunKeyStore();
        byte[] sunFile = storeSecrets(sun, keys, null);
        Assertions.assertThrows(java.security.UnrecoverableKeyException.class, () -> sun.getKey("k0", wrong));
        KeyStore sunLoaded = sunKeyStore();
        sunLoaded.load(new ByteArrayInputStream(sunFile), SK_PASSWORD);
        Assertions.assertThrows(java.security.UnrecoverableKeyException.class, () -> sunLoaded.getKey("k0", wrong));
        KeyStore jslSunLoaded = KeyStore.getInstance("PKCS12", JostleProvider.PROVIDER_NAME);
        jslSunLoaded.load(new ByteArrayInputStream(sunFile), SK_PASSWORD);
        Assertions.assertThrows(java.security.UnrecoverableKeyException.class,
                () -> jslSunLoaded.getKey("k0", wrong));
    }

    /**
     * A foreign LoadStoreParameter type. At load BouncyCastle refuses it with IllegalArgumentException and keeps
     * its entries (the control) and JSL does the same; SunJCE empties the store (a divergence). At store
     * BouncyCastle and JSL refuse with IllegalArgumentException and SunJCE with UnsupportedOperationException.
     */
    @Test
    public void foreignLoadStoreParameter_againstBothPeers()
        throws Exception
    {
        KeyStore.LoadStoreParameter foreign = () -> new KeyStore.PasswordProtection(SK_PASSWORD);
        javax.crypto.SecretKey[] keys = {secret("AES", 16)};
        for (String provider : new String[]{BouncyCastleProvider.PROVIDER_NAME, JostleProvider.PROVIDER_NAME})
        {
            KeyStore ks = KeyStore.getInstance("PKCS12", provider);
            storeSecrets(ks, keys, null);
            Assertions.assertThrows(IllegalArgumentException.class, () -> ks.load(foreign), provider);
            Assertions.assertEquals(1, ks.size(), provider + " keeps its entries");
            Assertions.assertThrows(IllegalArgumentException.class, () -> ks.store(foreign), provider);
        }
        KeyStore sun = sunKeyStore();
        storeSecrets(sun, keys, null);
        if (jdk8())
        {
            Assertions.assertThrows(UnsupportedOperationException.class, () -> sun.load(foreign));
            Assertions.assertEquals(1, sun.size(), "JDK 8 SunJSSE refuses the parameter");
        }
        else
        {
            sun.load(foreign);
            Assertions.assertEquals(0, sun.size(), "SunJCE empties the store");
        }
        KeyStore sunStore = sunKeyStore();
        sunStore.load(null, null);
        Assertions.assertThrows(UnsupportedOperationException.class, () -> sunStore.store(foreign));
    }
}
