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

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.provider.ks.KSServiceNI;
import org.openssl.jostle.jcajce.provider.ks.KSServiceSPI;
import org.openssl.jostle.jcajce.spec.MLDSAParameterSpec;
import org.openssl.jostle.jcajce.spec.MLKEMParameterSpec;
import org.openssl.jostle.jcajce.spec.SLHDSAParameterSpec;
import org.openssl.jostle.util.Arrays;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Stream;

public class KSServiceTest
{
    @BeforeAll
    public static void beforeAll()
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

    private static Stream<KeyCase> supportedPrivateKeyCases()
    {
        return Stream.of(
                new KeyCase("RSA", 2048, "RSA"),
                new KeyCase("EC", new ECGenParameterSpec("P-256"), "EC"),
                new KeyCase("ED25519", "Ed25519"),
                new KeyCase("ED448", "Ed448"),
                new KeyCase("X25519", "X25519"),
                new KeyCase("X448", "X448"),
                new KeyCase("DSA", 1024, "DSA"),
                new KeyCase("DH", 2048, "DH"),
                new KeyCase("MLDSA", MLDSAParameterSpec.ml_dsa_44, "ML-DSA-44"),
                new KeyCase("MLDSA", MLDSAParameterSpec.ml_dsa_65, "ML-DSA-65"),
                new KeyCase("MLDSA", MLDSAParameterSpec.ml_dsa_87, "ML-DSA-87"),
                new KeyCase("MLKEM", MLKEMParameterSpec.ml_kem_512, "ML-KEM-512"),
                new KeyCase("MLKEM", MLKEMParameterSpec.ml_kem_768, "ML-KEM-768"),
                new KeyCase("MLKEM", MLKEMParameterSpec.ml_kem_1024, "ML-KEM-1024"),
                new KeyCase("SLHDSA", SLHDSAParameterSpec.slh_dsa_sha2_128f, "SLH-DSA-SHA2-128F"),
                new KeyCase("SLHDSA", SLHDSAParameterSpec.slh_dsa_sha2_128s, "SLH-DSA-SHA2-128S"),
                new KeyCase("SLHDSA", SLHDSAParameterSpec.slh_dsa_sha2_192f, "SLH-DSA-SHA2-192F"),
                new KeyCase("SLHDSA", SLHDSAParameterSpec.slh_dsa_sha2_192s, "SLH-DSA-SHA2-192S"),
                new KeyCase("SLHDSA", SLHDSAParameterSpec.slh_dsa_sha2_256f, "SLH-DSA-SHA2-256F"),
                new KeyCase("SLHDSA", SLHDSAParameterSpec.slh_dsa_sha2_256s, "SLH-DSA-SHA2-256S"),
                new KeyCase("SLHDSA", SLHDSAParameterSpec.slh_dsa_shake_128f, "SLH-DSA-SHAKE-128F"),
                new KeyCase("SLHDSA", SLHDSAParameterSpec.slh_dsa_shake_128s, "SLH-DSA-SHAKE-128S"),
                new KeyCase("SLHDSA", SLHDSAParameterSpec.slh_dsa_shake_192f, "SLH-DSA-SHAKE-192F"),
                new KeyCase("SLHDSA", SLHDSAParameterSpec.slh_dsa_shake_192s, "SLH-DSA-SHAKE-192S"),
                new KeyCase("SLHDSA", SLHDSAParameterSpec.slh_dsa_shake_256f, "SLH-DSA-SHAKE-256F"),
                new KeyCase("SLHDSA", SLHDSAParameterSpec.slh_dsa_shake_256s, "SLH-DSA-SHAKE-256S"));
    }

    @ParameterizedTest
    @MethodSource("supportedPrivateKeyCases")
    public void privateKeyRoundTrip(KeyCase keyCase)
        throws Exception
    {
        KeyStore keyStore = KeyStore.getInstance("PKCS12", JostleProvider.PROVIDER_NAME);
        keyStore.load(null, null);

        KeyPairGenerator keyPairGenerator =
                KeyPairGenerator.getInstance(keyCase.algorithm, JostleProvider.PROVIDER_NAME);
        keyCase.initialize(keyPairGenerator);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        keyStore.setKeyEntry("signing", keyPair.getPrivate().getEncoded(), null);

        Assertions.assertTrue(keyStore.isKeyEntry("signing"));
        Assertions.assertFalse(keyStore.isKeyEntry("missing"));

        Key key = keyStore.getKey("signing", null);
        Assertions.assertNotNull(key);
        Assertions.assertEquals(keyCase.expectedKeyAlgorithm, key.getAlgorithm());
        Assertions.assertEquals("PKCS#8", key.getFormat());
        Assertions.assertTrue(Arrays.areEqual(keyPair.getPrivate().getEncoded(), key.getEncoded()));
    }

    @Test
    public void privateKeyEntryRetainsCertificateChain()
        throws Exception
    {
        KeyStore keyStore = KeyStore.getInstance("PKCS12", JostleProvider.PROVIDER_NAME);
        keyStore.load(null, null);

        KeyPair keyPair = generateRsaKeyPair();
        X509Certificate certificate = selfSignedCertificate(keyPair,
                "CN=Jostle KeyStore Certificate Chain Test", BigInteger.ONE);
        Certificate[] chain = new Certificate[] {certificate};

        keyStore.setKeyEntry("signing", keyPair.getPrivate(), null, chain);

        assertCertificateChain(keyStore, "signing", certificate);
        Assertions.assertNull(keyStore.getCertificate("missing"));
        Assertions.assertNull(keyStore.getCertificateChain("missing"));
    }

    @Test
    public void encodedPrivateKeyEntryRetainsCertificateChain()
        throws Exception
    {
        KeyStore keyStore = KeyStore.getInstance("PKCS12", JostleProvider.PROVIDER_NAME);
        keyStore.load(null, null);

        KeyPair keyPair = generateRsaKeyPair();
        X509Certificate certificate = selfSignedCertificate(keyPair,
                "CN=Jostle Encoded KeyStore Certificate Chain Test",
                BigInteger.valueOf(2));

        keyStore.setKeyEntry("encoded", keyPair.getPrivate().getEncoded(),
                new Certificate[] {certificate});

        assertCertificateChain(keyStore, "encoded", certificate);
    }

    @Test
    public void storeLoadRetainsPrivateKeyAndCertificateChain()
        throws Exception
    {
        char[] password = "changeit".toCharArray();
        KeyPair keyPair = generateRsaKeyPair();
        X509Certificate certificate = selfSignedCertificate(keyPair,
                "CN=Jostle Persisted KeyStore Certificate Chain Test",
                BigInteger.valueOf(3));

        KeyStore keyStore = KeyStore.getInstance("PKCS12", JostleProvider.PROVIDER_NAME);
        keyStore.load(null, null);
        keyStore.setKeyEntry("persisted", keyPair.getPrivate(), null,
                new Certificate[] {certificate});

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        keyStore.store(out, password);

        byte[] encoded = out.toByteArray();
        Assertions.assertTrue(encoded.length > 0);

        KeyStore loaded = KeyStore.getInstance("PKCS12", JostleProvider.PROVIDER_NAME);
        loaded.load(new ByteArrayInputStream(encoded), password);

        Assertions.assertTrue(loaded.isKeyEntry("persisted"));
        Key loadedKey = loaded.getKey("persisted", password);
        Assertions.assertNotNull(loadedKey);
        Assertions.assertEquals("RSA", loadedKey.getAlgorithm());
        Assertions.assertArrayEquals(keyPair.getPrivate().getEncoded(),
                loadedKey.getEncoded());
        assertCertificateChain(loaded, "persisted", certificate);
    }

    @Test
    public void privateKeyPasswordIsEnforced()
        throws Exception
    {
        char[] password = "entrypass".toCharArray();
        char[] storePassword = "storepass".toCharArray();
        char[] wrongPassword = "wrongpass".toCharArray();
        KeyPair keyPair = generateRsaKeyPair();
        X509Certificate certificate = selfSignedCertificate(keyPair,
                "CN=Jostle Key Password Test", BigInteger.valueOf(18));

        KeyStore keyStore = KeyStore.getInstance("PKCS12",
                JostleProvider.PROVIDER_NAME);
        keyStore.load(null, null);
        keyStore.setKeyEntry("protected", keyPair.getPrivate(), password,
                new Certificate[] {certificate});

        Assertions.assertArrayEquals(keyPair.getPrivate().getEncoded(),
                keyStore.getKey("protected", password).getEncoded());
        Assertions.assertThrows(UnrecoverableKeyException.class,
                () -> keyStore.getKey("protected", wrongPassword));

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        keyStore.store(out, storePassword);

        KeyStore loaded = KeyStore.getInstance("PKCS12",
                JostleProvider.PROVIDER_NAME);
        loaded.load(new ByteArrayInputStream(out.toByteArray()), storePassword);

        Assertions.assertArrayEquals(keyPair.getPrivate().getEncoded(),
                loaded.getKey("protected", storePassword).getEncoded());
        Assertions.assertThrows(UnrecoverableKeyException.class,
                () -> loaded.getKey("protected", password));
        Assertions.assertThrows(UnrecoverableKeyException.class,
                () -> loaded.getKey("protected", wrongPassword));
    }

    @Test
    public void emptyStoreLoadRoundTripWorks()
        throws Exception
    {
        char[] password = "changeit".toCharArray();
        KeyStore keyStore = KeyStore.getInstance("PKCS12",
                JostleProvider.PROVIDER_NAME);
        keyStore.load(null, null);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        keyStore.store(out, password);

        Assertions.assertTrue(out.size() > 0);

        KeyStore loaded = KeyStore.getInstance("PKCS12",
                JostleProvider.PROVIDER_NAME);
        loaded.load(new ByteArrayInputStream(out.toByteArray()), password);

        Assertions.assertEquals(0, loaded.size());
        Assertions.assertFalse(loaded.aliases().hasMoreElements());
    }

    @Test
    public void failedLoadPreservesExistingEntries()
        throws Exception
    {
        char[] password = "changeit".toCharArray();
        KeyPair keyPair = generateRsaKeyPair();
        X509Certificate certificate = selfSignedCertificate(keyPair,
                "CN=Jostle Failed Load Preservation Test",
                BigInteger.valueOf(17));

        KeyStore keyStore = KeyStore.getInstance("PKCS12",
                JostleProvider.PROVIDER_NAME);
        keyStore.load(null, null);
        keyStore.setKeyEntry("stable", keyPair.getPrivate(), password,
                new Certificate[] {certificate});

        Assertions.assertThrows(IOException.class,
                () -> keyStore.load(
                        new ByteArrayInputStream(new byte[] {1, 2, 3}),
                        password));

        Assertions.assertEquals(1, keyStore.size());
        Assertions.assertTrue(keyStore.isKeyEntry("stable"));
        Assertions.assertArrayEquals(keyPair.getPrivate().getEncoded(),
                keyStore.getKey("stable", password).getEncoded());
        assertCertificateChain(keyStore, "stable", certificate);
    }

    @Test
    public void emptyInputLoadFailsAndPreservesExistingEntries()
        throws Exception
    {
        char[] password = "changeit".toCharArray();
        KeyPair keyPair = generateRsaKeyPair();
        X509Certificate certificate = selfSignedCertificate(keyPair,
                "CN=Jostle Empty Input Load Preservation Test",
                BigInteger.valueOf(19));

        KeyStore keyStore = KeyStore.getInstance("PKCS12",
                JostleProvider.PROVIDER_NAME);
        keyStore.load(null, null);
        keyStore.setKeyEntry("stable", keyPair.getPrivate(), password,
                new Certificate[] {certificate});

        Assertions.assertThrows(IOException.class,
                () -> keyStore.load(new ByteArrayInputStream(new byte[0]),
                        password));

        Assertions.assertEquals(1, keyStore.size());
        Assertions.assertTrue(keyStore.isKeyEntry("stable"));
        Assertions.assertArrayEquals(keyPair.getPrivate().getEncoded(),
                keyStore.getKey("stable", password).getEncoded());
        assertCertificateChain(keyStore, "stable", certificate);
    }

    @Test
    public void rejectedPrivateKeyFormatDoesNotLeaveEncodedBytes()
        throws Exception
    {
        KeyPair keyPair = generateRsaKeyPair();
        byte[] encoded = keyPair.getPrivate().getEncoded();
        boolean[] getEncodedCalled = new boolean[1];
        PrivateKey key = new PrivateKey()
        {
            @Override
            public String getAlgorithm()
            {
                return "RSA";
            }

            @Override
            public String getFormat()
            {
                return "RAW";
            }

            @Override
            public byte[] getEncoded()
            {
                getEncodedCalled[0] = true;
                return encoded;
            }
        };

        KeyStore keyStore = KeyStore.getInstance("PKCS12",
                JostleProvider.PROVIDER_NAME);
        keyStore.load(null, null);

        Assertions.assertThrows(KeyStoreException.class,
                () -> keyStore.setKeyEntry("rejected", key, null,
                        new Certificate[] {selfSignedCertificate(keyPair,
                                "CN=Jostle Rejected Key Format Test",
                                BigInteger.valueOf(20))}));
        Assertions.assertFalse(getEncodedCalled[0]);
        Assertions.assertArrayEquals(keyPair.getPrivate().getEncoded(), encoded);
    }

    @Test
    public void entryMetadataAndCertificateEntriesWork()
        throws Exception
    {
        KeyStore keyStore = KeyStore.getInstance("PKCS12", JostleProvider.PROVIDER_NAME);
        keyStore.load(null, null);

        KeyPair keyPair = generateRsaKeyPair();
        X509Certificate keyCertificate = selfSignedCertificate(keyPair,
                "CN=Jostle Key Entry Metadata Test", BigInteger.valueOf(6));
        KeyPair trustedPair = generateRsaKeyPair();
        X509Certificate trustedCertificate = selfSignedCertificate(trustedPair,
                "CN=Jostle Trusted Certificate Metadata Test", BigInteger.valueOf(7));

        keyStore.setKeyEntry("key", keyPair.getPrivate(), null,
                new Certificate[] {keyCertificate});
        keyStore.setCertificateEntry("trusted", trustedCertificate);

        Assertions.assertEquals(2, keyStore.size());
        Assertions.assertTrue(keyStore.containsAlias("key"));
        Assertions.assertTrue(keyStore.containsAlias("trusted"));
        Assertions.assertFalse(keyStore.containsAlias("missing"));
        Assertions.assertEquals(aliasSet("key", "trusted"), aliases(keyStore));

        Assertions.assertTrue(keyStore.isKeyEntry("key"));
        Assertions.assertFalse(keyStore.isCertificateEntry("key"));
        Assertions.assertFalse(keyStore.isKeyEntry("trusted"));
        Assertions.assertTrue(keyStore.isCertificateEntry("trusted"));

        Assertions.assertNotNull(keyStore.getCreationDate("key"));
        Assertions.assertNotNull(keyStore.getCreationDate("trusted"));
        Assertions.assertNull(keyStore.getCreationDate("missing"));

        Assertions.assertEquals("key", keyStore.getCertificateAlias(keyCertificate));
        Assertions.assertEquals("trusted",
                keyStore.getCertificateAlias(trustedCertificate));
        Assertions.assertArrayEquals(trustedCertificate.getEncoded(),
                keyStore.getCertificate("trusted").getEncoded());

        Assertions.assertThrows(KeyStoreException.class,
                () -> keyStore.setCertificateEntry("key", trustedCertificate));

        keyStore.deleteEntry("trusted");
        Assertions.assertEquals(1, keyStore.size());
        Assertions.assertFalse(keyStore.containsAlias("trusted"));
        Assertions.assertNull(keyStore.getCertificate("trusted"));
    }

    @Test
    public void storeLoadRetainsMultipleEntryTypes()
        throws Exception
    {
        char[] password = "changeit".toCharArray();
        KeyStore keyStore = KeyStore.getInstance("PKCS12", JostleProvider.PROVIDER_NAME);
        keyStore.load(null, null);

        KeyPair keyPair = generateRsaKeyPair();
        X509Certificate keyCertificate = selfSignedCertificate(keyPair,
                "CN=Jostle Multi Entry Key Test", BigInteger.valueOf(8));
        KeyPair trustedPair = generateRsaKeyPair();
        X509Certificate trustedCertificate = selfSignedCertificate(trustedPair,
                "CN=Jostle Multi Entry Trusted Test", BigInteger.valueOf(9));

        keyStore.setKeyEntry("key", keyPair.getPrivate(), password,
                new Certificate[] {keyCertificate});
        keyStore.setCertificateEntry("trusted", trustedCertificate);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        keyStore.store(out, password);

        KeyStore loaded = KeyStore.getInstance("PKCS12", JostleProvider.PROVIDER_NAME);
        loaded.load(new ByteArrayInputStream(out.toByteArray()), password);

        Assertions.assertEquals(aliasSet("key", "trusted"), aliases(loaded));
        Assertions.assertTrue(loaded.isKeyEntry("key"));
        Assertions.assertTrue(loaded.isCertificateEntry("trusted"));
        Assertions.assertArrayEquals(keyPair.getPrivate().getEncoded(),
                loaded.getKey("key", password).getEncoded());
        assertCertificateChain(loaded, "key", keyCertificate);
        Assertions.assertArrayEquals(trustedCertificate.getEncoded(),
                loaded.getCertificate("trusted").getEncoded());
    }

    @Test
    public void nativeStoreLoadRetainsMultipleEntryTypes()
        throws Exception
    {
        byte[] password = "changeit".getBytes(StandardCharsets.UTF_8);
        KeyPair keyPair = generateRsaKeyPair();
        X509Certificate keyCertificate = selfSignedCertificate(keyPair,
                "CN=Jostle Native Multi Entry Key Test", BigInteger.valueOf(15));
        KeyPair trustedPair = generateRsaKeyPair();
        X509Certificate trustedCertificate = selfSignedCertificate(trustedPair,
                "CN=Jostle Native Multi Entry Trusted Test",
                BigInteger.valueOf(16));

        KSServiceNI serviceNI = NISelector.KSServiceNI;
        long source = 0L;
        long loaded = 0L;
        try
        {
            source = serviceNI.allocateKeyStore("PKCS12");
            serviceNI.setKey(source, "key", keyPair.getPrivate().getEncoded(),
                    password);
            serviceNI.setCertificateChain(source, "key",
                    encodeCertificateChain(keyCertificate));
            serviceNI.setCertificateEntry(source, "trusted",
                    trustedCertificate.getEncoded());

            // profile: AES-256-CBC keys, AES-128-CBC certs (PBES2), HMAC-SHA256 MAC
            byte[] encoded = serviceNI.store(source, password,
                    3, 2, 1, 2, 2048, 2048);
            Assertions.assertNotNull(encoded);
            Assertions.assertTrue(encoded.length > 0);

            loaded = serviceNI.allocateKeyStore("PKCS12");
            serviceNI.load(loaded, encoded, password);

            Assertions.assertEquals(2, serviceNI.size(loaded));
            Assertions.assertEquals(aliasSet("key", "trusted"),
                    decodeNativeAliases(serviceNI.getAliases(loaded)));
            Assertions.assertTrue(serviceNI.isKeyEntry(loaded, "key"));
            Assertions.assertTrue(serviceNI.isCertificateEntry(loaded,
                    "trusted"));
            Assertions.assertArrayEquals(keyPair.getPrivate().getEncoded(),
                    serviceNI.getKey(loaded, "key", password));
            final long loadedRef = loaded;
            Assertions.assertThrows(KeyStoreException.class,
                    () -> serviceNI.getKey(loadedRef, "key",
                            "wrongpass".getBytes(StandardCharsets.UTF_8)));
            Assertions.assertArrayEquals(encodeCertificateChain(keyCertificate),
                    serviceNI.getCertificateChain(loaded, "key"));
            Assertions.assertArrayEquals(
                    encodeCertificateChain(trustedCertificate),
                    serviceNI.getCertificateChain(loaded, "trusted"));
        }
        finally
        {
            if (source != 0L)
            {
                serviceNI.dispose(source);
            }
            if (loaded != 0L)
            {
                serviceNI.dispose(loaded);
            }
        }
    }

    @Test
    public void nativeEmptyPersistenceAndEmptyChainDoNotCreateAliases()
        throws Exception
    {
        byte[] password = "changeit".getBytes(StandardCharsets.UTF_8);
        KSServiceNI serviceNI = NISelector.KSServiceNI;
        long source = 0L;
        long loaded = 0L;
        try
        {
            source = serviceNI.allocateKeyStore("PKCS12");

            serviceNI.setCertificateChain(source, "empty-chain", null);
            Assertions.assertEquals(0, serviceNI.size(source));
            Assertions.assertFalse(serviceNI.containsAlias(source,
                    "empty-chain"));
            final long sourceRef = source;
            Assertions.assertThrows(KeyStoreException.class,
                    () -> serviceNI.setCertificateEntry(sourceRef, "empty-cert",
                            null));
            Assertions.assertFalse(serviceNI.containsAlias(source,
                    "empty-cert"));

            // profile: AES-256-CBC keys, AES-128-CBC certs (PBES2), HMAC-SHA256 MAC
            byte[] encoded = serviceNI.store(source, password,
                    3, 2, 1, 2, 2048, 2048);
            Assertions.assertNotNull(encoded);
            Assertions.assertTrue(encoded.length > 0);

            loaded = serviceNI.allocateKeyStore("PKCS12");
            serviceNI.load(loaded, encoded, password);

            Assertions.assertEquals(0, serviceNI.size(loaded));
            Assertions.assertEquals(aliasSet(),
                    decodeNativeAliases(serviceNI.getAliases(loaded)));
        }
        finally
        {
            if (source != 0L)
            {
                serviceNI.dispose(source);
            }
            if (loaded != 0L)
            {
                serviceNI.dispose(loaded);
            }
        }
    }

    @Test
    public void entryConvenienceMethodsWork()
        throws Exception
    {
        char[] password = "entrypass".toCharArray();
        KeyStore.PasswordProtection protection =
                new KeyStore.PasswordProtection(password);
        KeyStore keyStore = KeyStore.getInstance("PKCS12",
                JostleProvider.PROVIDER_NAME);
        keyStore.load(null, null);

        KeyPair keyPair = generateRsaKeyPair();
        X509Certificate keyCertificate = selfSignedCertificate(keyPair,
                "CN=Jostle PrivateKeyEntry Test", BigInteger.valueOf(10));
        KeyStore.PrivateKeyEntry privateKeyEntry =
                new KeyStore.PrivateKeyEntry(keyPair.getPrivate(),
                        new Certificate[] {keyCertificate});

        keyStore.setEntry("entry-key", privateKeyEntry, protection);

        Assertions.assertTrue(keyStore.entryInstanceOf("entry-key",
                KeyStore.PrivateKeyEntry.class));
        Assertions.assertFalse(keyStore.entryInstanceOf("entry-key",
                KeyStore.TrustedCertificateEntry.class));
        KeyStore.Entry retrieved = keyStore.getEntry("entry-key", protection);
        Assertions.assertTrue(retrieved instanceof KeyStore.PrivateKeyEntry);
        KeyStore.PrivateKeyEntry retrievedKeyEntry =
                (KeyStore.PrivateKeyEntry)retrieved;
        Assertions.assertArrayEquals(keyPair.getPrivate().getEncoded(),
                retrievedKeyEntry.getPrivateKey().getEncoded());
        Assertions.assertArrayEquals(keyCertificate.getEncoded(),
                retrievedKeyEntry.getCertificate().getEncoded());

        KeyPair trustedPair = generateRsaKeyPair();
        X509Certificate trustedCertificate = selfSignedCertificate(trustedPair,
                "CN=Jostle TrustedCertificateEntry Test", BigInteger.valueOf(11));
        keyStore.setEntry("entry-cert",
                new KeyStore.TrustedCertificateEntry(trustedCertificate), null);

        Assertions.assertTrue(keyStore.entryInstanceOf("entry-cert",
                KeyStore.TrustedCertificateEntry.class));
        Assertions.assertFalse(keyStore.entryInstanceOf("entry-cert",
                KeyStore.PrivateKeyEntry.class));
        KeyStore.Entry trustedEntry = keyStore.getEntry("entry-cert", null);
        Assertions.assertTrue(trustedEntry
                instanceof KeyStore.TrustedCertificateEntry);
        Assertions.assertArrayEquals(trustedCertificate.getEncoded(),
                ((KeyStore.TrustedCertificateEntry)trustedEntry)
                        .getTrustedCertificate().getEncoded());

        Assertions.assertTrue(new KSServiceSPI()
                .engineGetAttributes("missing").isEmpty());
    }

    @Test
    public void streamLoadStoreParameterRoundTripWorks()
        throws Exception
    {
        char[] password = "changeit".toCharArray();
        KeyStore.PasswordProtection protection =
                new KeyStore.PasswordProtection(password);
        KeyPair keyPair = generateRsaKeyPair();
        X509Certificate certificate = selfSignedCertificate(keyPair,
                "CN=Jostle Stream LoadStoreParameter Test",
                BigInteger.valueOf(12));

        KeyStore keyStore = KeyStore.getInstance("PKCS12",
                JostleProvider.PROVIDER_NAME);
        keyStore.load(new KSServiceSPI.StreamLoadStoreParameter(
                (ByteArrayInputStream)null, protection));
        keyStore.setKeyEntry("stream", keyPair.getPrivate(), password,
                new Certificate[] {certificate});

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        keyStore.store(new KSServiceSPI.StreamLoadStoreParameter(out,
                protection));

        KeyStore loaded = KeyStore.getInstance("PKCS12",
                JostleProvider.PROVIDER_NAME);
        loaded.load(new KSServiceSPI.StreamLoadStoreParameter(
                new ByteArrayInputStream(out.toByteArray()), protection));

        Assertions.assertTrue(loaded.isKeyEntry("stream"));
        Assertions.assertArrayEquals(keyPair.getPrivate().getEncoded(),
                loaded.getKey("stream", password).getEncoded());
        assertCertificateChain(loaded, "stream", certificate);
    }

    @Test
    public void engineProbeRecognizesPkcs12()
        throws Exception
    {
        char[] password = "changeit".toCharArray();
        KeyPair keyPair = generateRsaKeyPair();
        X509Certificate certificate = selfSignedCertificate(keyPair,
                "CN=Jostle Probe Test", BigInteger.valueOf(13));
        KeyStore keyStore = KeyStore.getInstance("PKCS12",
                JostleProvider.PROVIDER_NAME);
        keyStore.load(null, null);
        keyStore.setKeyEntry("probe", keyPair.getPrivate(), password,
                new Certificate[] {certificate});

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        keyStore.store(out, password);

        KSServiceSPI spi = new KSServiceSPI();
        Assertions.assertTrue(spi.engineProbe(
                new ByteArrayInputStream(out.toByteArray())));
        Assertions.assertFalse(spi.engineProbe(
                new ByteArrayInputStream(new byte[] {0x01, 0x02, 0x03})));
    }

    @Test
    public void unknownAliasReturnsNullKey()
        throws Exception
    {
        KeyStore keyStore = KeyStore.getInstance("PKCS12", JostleProvider.PROVIDER_NAME);
        keyStore.load(null, null);

        Assertions.assertNull(keyStore.getKey("missing", null));
    }

    @Test
    public void directSpiRejectsNullInputs()
        throws Exception
    {
        KSServiceSPI spi = new KSServiceSPI();

        Assertions.assertThrows(NullPointerException.class,
                () -> spi.engineGetKey(null, null));
        Assertions.assertThrows(NullPointerException.class,
                () -> spi.engineGetCertificateChain(null));
        Assertions.assertThrows(NullPointerException.class,
                () -> spi.engineGetCreationDate(null));
        Assertions.assertThrows(KeyStoreException.class,
                () -> spi.engineSetKeyEntry(null, new byte[] {1}, null));
        Assertions.assertThrows(KeyStoreException.class,
                () -> spi.engineSetKeyEntry("key", (byte[])null, null));
        Assertions.assertThrows(KeyStoreException.class,
                () -> spi.engineSetKeyEntry(null, (Key)null, null, null));
        Assertions.assertThrows(KeyStoreException.class,
                () -> spi.engineSetCertificateEntry(null, null));
        Assertions.assertThrows(KeyStoreException.class,
                () -> spi.engineSetCertificateEntry("cert", null));
        Assertions.assertThrows(KeyStoreException.class,
                () -> spi.engineDeleteEntry(null));
        Assertions.assertThrows(NullPointerException.class,
                () -> spi.engineContainsAlias(null));
        Assertions.assertThrows(NullPointerException.class,
                () -> spi.engineIsKeyEntry(null));
        Assertions.assertThrows(NullPointerException.class,
                () -> spi.engineIsCertificateEntry(null));
        Assertions.assertThrows(NullPointerException.class,
                () -> spi.engineGetAttributes(null));
        Assertions.assertThrows(KeyStoreException.class,
                () -> spi.engineSetEntry(null, null, null));
        Assertions.assertThrows(KeyStoreException.class,
                () -> spi.engineSetEntry("entry", null, null));
        Assertions.assertThrows(NullPointerException.class,
                () -> spi.engineEntryInstanceOf("entry", null));
    }

    private static KeyPair generateRsaKeyPair()
        throws Exception
    {
        KeyPairGenerator keyPairGenerator =
                KeyPairGenerator.getInstance("RSA", JostleProvider.PROVIDER_NAME);
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    private static X509Certificate selfSignedCertificate(KeyPair keyPair,
                                                        String distinguishedName,
                                                        BigInteger serial)
        throws Exception
    {
        return selfSignedCertificate(keyPair, distinguishedName, serial,
                BouncyCastleProvider.PROVIDER_NAME);
    }

    private static X509Certificate selfSignedCertificate(KeyPair keyPair,
                                                        String distinguishedName,
                                                        BigInteger serial,
                                                        String signerProvider)
        throws Exception
    {
        X500Name name = new X500Name(distinguishedName);
        Date notBefore = new Date(System.currentTimeMillis() - 3600_000L);
        Date notAfter = new Date(System.currentTimeMillis() + 3600_000L);
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                name, serial, notBefore, notAfter, name, keyPair.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(signerProvider).build(keyPair.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }

    private static void assertCertificateChain(KeyStore keyStore, String alias,
                                               X509Certificate certificate)
        throws Exception
    {
        Certificate retrievedCertificate = keyStore.getCertificate(alias);
        Assertions.assertNotNull(retrievedCertificate);
        Assertions.assertArrayEquals(certificate.getEncoded(),
                retrievedCertificate.getEncoded());

        Certificate[] retrievedChain = keyStore.getCertificateChain(alias);
        Assertions.assertNotNull(retrievedChain);
        Assertions.assertEquals(1, retrievedChain.length);
        Assertions.assertArrayEquals(certificate.getEncoded(),
                retrievedChain[0].getEncoded());
    }

    private static Set<String> aliases(KeyStore keyStore)
        throws Exception
    {
        Set<String> aliases = new HashSet<String>();
        Enumeration<String> enumeration = keyStore.aliases();
        while (enumeration.hasMoreElements())
        {
            aliases.add(enumeration.nextElement());
        }
        return aliases;
    }

    private static Set<String> aliasSet(String... aliases)
    {
        Set<String> aliasSet = new HashSet<String>();
        for (String alias : aliases)
        {
            aliasSet.add(alias);
        }
        return aliasSet;
    }

    private static byte[] encodeCertificateChain(Certificate... certificates)
        throws Exception
    {
        // Concatenated DER, matching the native cert-chain marshalling.
        ByteArrayOutputStream encoded = new ByteArrayOutputStream();
        for (Certificate certificate : certificates)
        {
            byte[] der = certificate.getEncoded();
            encoded.write(der, 0, der.length);
        }
        return encoded.toByteArray();
    }

    private static Set<String> decodeNativeAliases(byte[] encoded)
    {
        Set<String> aliases = new HashSet<String>();
        if (encoded == null || encoded.length < 4)
        {
            return aliases;
        }

        int offset = 0;
        int count = readInt(encoded, offset);
        offset += 4;
        for (int i = 0; i < count; i++)
        {
            int length = readInt(encoded, offset);
            offset += 4;
            aliases.add(new String(encoded, offset, length,
                    StandardCharsets.UTF_8));
            offset += length;
        }
        return aliases;
    }

    private static int readInt(byte[] input, int offset)
    {
        return (input[offset] & 0xff) << 24
                | (input[offset + 1] & 0xff) << 16
                | (input[offset + 2] & 0xff) << 8
                | (input[offset + 3] & 0xff);
    }

    private static final class KeyCase
    {
        private final String algorithm;
        private final Integer size;
        private final AlgorithmParameterSpec spec;
        private final String expectedKeyAlgorithm;

        private KeyCase(String algorithm, String expectedKeyAlgorithm)
        {
            this.algorithm = algorithm;
            this.size = null;
            this.spec = null;
            this.expectedKeyAlgorithm = expectedKeyAlgorithm;
        }

        private KeyCase(String algorithm, int size, String expectedKeyAlgorithm)
        {
            this.algorithm = algorithm;
            this.size = size;
            this.spec = null;
            this.expectedKeyAlgorithm = expectedKeyAlgorithm;
        }

        private KeyCase(String algorithm, AlgorithmParameterSpec spec,
                        String expectedKeyAlgorithm)
        {
            this.algorithm = algorithm;
            this.size = null;
            this.spec = spec;
            this.expectedKeyAlgorithm = expectedKeyAlgorithm;
        }

        private void initialize(KeyPairGenerator generator)
            throws Exception
        {
            if (size != null)
            {
                generator.initialize(size);
            }
            else if (spec != null)
            {
                generator.initialize(spec);
            }
        }

        @Override
        public String toString()
        {
            return expectedKeyAlgorithm;
        }
    }
}
