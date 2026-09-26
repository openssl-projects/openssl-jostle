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
package jostle.examples.jsl;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.BCFKSLoadStoreParameter;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

/**
 * Key stores: PKCS#12 and its variants, and BCFKS, BouncyCastle's FIPS key store format, which JSL reads and
 * writes itself. Each example stores entries, writes the store, and loads it into a fresh instance.
 */
public class KeyStoreExamplesTest
        extends JslExamples
{
    /**
     * A private key with its certificate chain, the commonest key store entry, in PKCS#12 and BCFKS. The key is
     * read from a PKCS#8 PEM file through JSL's `KeyFactory`, and the certificate through its
     * `CertificateFactory`.
     */
    @Test
    public void privateKeyEntry()
            throws Exception
    {
        char[] password = "change it".toCharArray();
        String pem = new Scanner(getClass().getResourceAsStream("/jostle/examples/keystore/example-key.pem"),
                "US-ASCII").useDelimiter("\\A").next();
        byte[] pkcs8 = Base64.getMimeDecoder().decode(pem.replaceAll("-----[A-Z ]+-----", ""));
        PrivateKey key = KeyFactory.getInstance("RSA", "JSL").generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
        Certificate cert = CertificateFactory.getInstance("X.509", "JSL").generateCertificate(
                getClass().getResourceAsStream("/jostle/examples/keystore/example-cert.pem"));
        for (String type : new String[]{"PKCS12", "BCFKS"})
        {
            KeyStore ks = KeyStore.getInstance(type, "JSL");
            ks.load(null, null);
            ks.setKeyEntry("me", key, password, new Certificate[]{cert});
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            ks.store(out, password);

            KeyStore loaded = KeyStore.getInstance(type, "JSL");
            loaded.load(new ByteArrayInputStream(out.toByteArray()), password);
            Assertions.assertArrayEquals(key.getEncoded(), loaded.getKey("me", password).getEncoded(), type);
            Assertions.assertEquals(cert, loaded.getCertificateChain("me")[0], type);
        }
    }

    /**
     * A PKCS#12 trust store: trusted-certificate entries, written with an integrity password and read back.
     */
    @Test
    public void pkcs12TrustStore()
            throws Exception
    {
        char[] password = "change it".toCharArray();
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "JSL");
        Certificate root = cf.generateCertificate(
                getClass().getResourceAsStream("/jostle/examples/pkits/TrustAnchorRootCertificate.crt"));
        Certificate ca = cf.generateCertificate(
                getClass().getResourceAsStream("/jostle/examples/pkits/GoodCACert.crt"));

        KeyStore ks = KeyStore.getInstance("PKCS12", "JSL");
        ks.load(null, null);
        ks.setCertificateEntry("root", root);
        ks.setCertificateEntry("good ca", ca);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ks.store(out, password);

        KeyStore loaded = KeyStore.getInstance("PKCS12", "JSL");
        loaded.load(new ByteArrayInputStream(out.toByteArray()), password);
        Assertions.assertEquals(root, loaded.getCertificate("root"));
        Assertions.assertTrue(loaded.isCertificateEntry("good ca"));
    }

    /**
     * The PKCS#12 variants fix the protection used when writing: legacy Triple-DES, AES-256 with an AES-128 MAC
     * key derivation, or a PBMAC1 integrity MAC. A plain `PKCS12` store reads any of them.
     */
    @Test
    public void pkcs12Variants()
            throws Exception
    {
        String[] names = {"PKCS12-3DES-3DES", "PKCS12-AES256-AES128", "PKCS12-PBMAC1"};
        char[] password = "change it".toCharArray();
        Certificate root = CertificateFactory.getInstance("X.509", "JSL").generateCertificate(
                getClass().getResourceAsStream("/jostle/examples/pkits/TrustAnchorRootCertificate.crt"));
        for (String name : names)
        {
            KeyStore ks = KeyStore.getInstance(name, "JSL");
            ks.load(null, null);
            ks.setCertificateEntry("root", root);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            ks.store(out, password);

            KeyStore loaded = KeyStore.getInstance("PKCS12", "JSL");
            loaded.load(new ByteArrayInputStream(out.toByteArray()), password);
            Assertions.assertEquals(root, loaded.getCertificate("root"), name);
        }
    }

    /**
     * BCFKS written with explicit store protection through `BCFKSLoadStoreParameter`: the store encryption,
     * the integrity MAC and the password-based KDF settings. Loading takes the same class.
     */
    @Test
    public void bcfksWithStoreParameters()
            throws Exception
    {
        char[] password = "change it".toCharArray();
        KeyStore ks = KeyStore.getInstance("BCFKS", "JSL");
        ks.load(null, null);
        ks.setEntry("k", new KeyStore.SecretKeyEntry(new SecretKeySpec(new byte[32], "AES")),
                new KeyStore.PasswordProtection(password));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ks.store(new BCFKSLoadStoreParameter.Builder(out, password)
                .withStoreEncryptionAlgorithm(BCFKSLoadStoreParameter.EncryptionAlgorithm.AES256_KWP)
                .withStoreMacAlgorithm(BCFKSLoadStoreParameter.MacAlgorithm.HmacSHA3_512)
                .withStorePBKDFConfig(new BCFKSLoadStoreParameter.PBKDF2Config.Builder()
                        .withIterationCount(100000).build())
                .build());

        KeyStore loaded = KeyStore.getInstance("BCFKS", "JSL");
        loaded.load(new BCFKSLoadStoreParameter.Builder(new ByteArrayInputStream(out.toByteArray()), password)
                .build());
        Assertions.assertEquals(32, loaded.getKey("k", password).getEncoded().length);
    }

    /**
     * Store a key derived from a password (here PBKDF2) as a BCFKS secret-key entry, and read it back.
     */
    @Test
    public void bcfksPasswordDerivedKeyEntry()
            throws Exception
    {
        char[] storePassword = "change it".toCharArray();
        SecretKey derived = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256", "JSL").generateSecret(
                new PBEKeySpec("user password".toCharArray(), "salt value".getBytes(StandardCharsets.US_ASCII),
                        10000, 256));
        SecretKeySpec key = new SecretKeySpec(derived.getEncoded(), "AES");

        KeyStore ks = KeyStore.getInstance("BCFKS", "JSL");
        ks.load(null, null);
        ks.setEntry("derived", new KeyStore.SecretKeyEntry(key), new KeyStore.PasswordProtection(storePassword));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ks.store(out, storePassword);

        KeyStore loaded = KeyStore.getInstance("BCFKS", "JSL");
        loaded.load(new ByteArrayInputStream(out.toByteArray()), storePassword);
        Assertions.assertArrayEquals(key.getEncoded(), loaded.getKey("derived", storePassword).getEncoded());
    }
}
