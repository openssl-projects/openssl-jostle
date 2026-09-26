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
package jostle.examples.fips;

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
 * Key stores in the FIPS module: BCFKS only. PKCS#12's key derivation is served by OpenSSL's default provider,
 * not the FIPS module, so JSLFIPS registers no PKCS#12 store. Each example stores entries, writes the store, and
 * loads it into a fresh instance.
 */
public class FipsKeyStoreExamplesTest
        extends FipsExamples
{
    /**
     * A private key with its certificate chain, the commonest key store entry. The key is
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
        PrivateKey key = KeyFactory.getInstance("RSA", "JSLFIPS").generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
        Certificate cert = CertificateFactory.getInstance("X.509", "JSLFIPS").generateCertificate(
                getClass().getResourceAsStream("/jostle/examples/keystore/example-cert.pem"));
        KeyStore ks = KeyStore.getInstance("BCFKS", "JSLFIPS");
        ks.load(null, null);
        ks.setKeyEntry("me", key, password, new Certificate[]{cert});
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ks.store(out, password);

        KeyStore loaded = KeyStore.getInstance("BCFKS", "JSLFIPS");
        loaded.load(new ByteArrayInputStream(out.toByteArray()), password);
        Assertions.assertArrayEquals(key.getEncoded(), loaded.getKey("me", password).getEncoded());
        Assertions.assertEquals(cert, loaded.getCertificateChain("me")[0]);
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
        KeyStore ks = KeyStore.getInstance("BCFKS", "JSLFIPS");
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

        KeyStore loaded = KeyStore.getInstance("BCFKS", "JSLFIPS");
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
        SecretKey derived = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256", "JSLFIPS").generateSecret(
                new PBEKeySpec("user password".toCharArray(), "a sixteen-byte salt".getBytes(StandardCharsets.US_ASCII),
                        10000, 256));
        SecretKeySpec key = new SecretKeySpec(derived.getEncoded(), "AES");

        KeyStore ks = KeyStore.getInstance("BCFKS", "JSLFIPS");
        ks.load(null, null);
        ks.setEntry("derived", new KeyStore.SecretKeyEntry(key), new KeyStore.PasswordProtection(storePassword));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ks.store(out, storePassword);

        KeyStore loaded = KeyStore.getInstance("BCFKS", "JSLFIPS");
        loaded.load(new ByteArrayInputStream(out.toByteArray()), storePassword);
        Assertions.assertArrayEquals(key.getEncoded(), loaded.getKey("derived", storePassword).getEncoded());
    }
}
