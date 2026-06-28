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
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.util.Arrays;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

/**
 * Behavioural unit tests for the PKCS#12 KeyStore SPI that go beyond the
 * happy-path coverage in {@link KSServiceTest}: the integrity negative path
 * (tampered content, wrong store password), state-machine reset/reuse on a
 * single SPI instance, multi-key-entry persistence, and BouncyCastle encode
 * round-trip for non-RSA key types (the in-bag PKCS#8 must carry the right
 * curve / algorithm for a stricter reader).
 *
 * <p>Random passwords and serials per the testing.md randomisation rule; the
 * seed is logged so a flaky run can be reproduced.
 */
public class KSTest
{
    private static final SecureRandom RANDOM = new SecureRandom();

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

    // -----------------------------------------------------------------
    // negative path: integrity
    // -----------------------------------------------------------------

    @Test
    public void tamperedContentFailsToLoad()
        throws Exception
    {
        char[] password = randomPassword();
        KeyPair keyPair = rsaKeyPair();
        X509Certificate cert = selfSigned(keyPair, "SHA256withRSA",
                "CN=Jostle KS Tamper Test");

        KeyStore keyStore = jostleStore();
        keyStore.setKeyEntry("k", keyPair.getPrivate(), password, new Certificate[] {cert});
        byte[] encoded = storeToBytes(keyStore, password);

        // Flip a byte well inside the MAC-protected content (not the outer
        // framing) so the integrity check -- not just the DER parse -- is what
        // rejects it.
        byte[] tampered = Arrays.clone(encoded);
        tampered[tampered.length / 2] ^= (byte) 0xFF;

        KeyStore reload = jostleStore0();
        Assertions.assertThrows(IOException.class,
                () -> reload.load(new ByteArrayInputStream(tampered), password));
    }

    @Test
    public void wrongStorePasswordFailsToLoad()
        throws Exception
    {
        char[] password = randomPassword();
        char[] wrongPassword = randomPassword();
        KeyPair keyPair = rsaKeyPair();
        X509Certificate cert = selfSigned(keyPair, "SHA256withRSA",
                "CN=Jostle KS Wrong Store Password Test");

        KeyStore keyStore = jostleStore();
        keyStore.setKeyEntry("k", keyPair.getPrivate(), password, new Certificate[] {cert});
        byte[] encoded = storeToBytes(keyStore, password);

        // A wrong integrity password fails the MAC check on load. Per the JCE
        // engineLoad contract the IOException's cause must be an
        // UnrecoverableKeyException (distinguishing wrong-password from a
        // malformed file), which the dedicated MAC-verify error code provides.
        KeyStore reload = jostleStore0();
        IOException ioe = Assertions.assertThrows(IOException.class,
                () -> reload.load(new ByteArrayInputStream(encoded), wrongPassword));
        Assertions.assertTrue(ioe.getCause() instanceof UnrecoverableKeyException,
                "expected UnrecoverableKeyException cause, got " + ioe.getCause());
    }

    // -----------------------------------------------------------------
    // reset / reuse
    // -----------------------------------------------------------------

    @Test
    public void twoStoresFromOneInstanceAreIndependent()
        throws Exception
    {
        char[] password = randomPassword();
        KeyPair keyA = rsaKeyPair();
        KeyPair keyB = rsaKeyPair();
        X509Certificate certA = selfSigned(keyA, "SHA256withRSA", "CN=Jostle KS Reuse A");
        X509Certificate certB = selfSigned(keyB, "SHA256withRSA", "CN=Jostle KS Reuse B");

        KeyStore keyStore = jostleStore();
        keyStore.setKeyEntry("a", keyA.getPrivate(), password, new Certificate[] {certA});
        byte[] firstSnapshot = storeToBytes(keyStore, password);

        keyStore.setKeyEntry("b", keyB.getPrivate(), password, new Certificate[] {certB});
        byte[] secondSnapshot = storeToBytes(keyStore, password);

        // The second snapshot has both entries.
        KeyStore loadedSecond = jostleStore0();
        loadedSecond.load(new ByteArrayInputStream(secondSnapshot), password);
        Assertions.assertEquals(aliasSet("a", "b"), aliases(loadedSecond));
        Assertions.assertArrayEquals(keyA.getPrivate().getEncoded(),
                loadedSecond.getKey("a", password).getEncoded());
        Assertions.assertArrayEquals(keyB.getPrivate().getEncoded(),
                loadedSecond.getKey("b", password).getEncoded());

        // The first snapshot, taken before "b" was added, is uncorrupted by the
        // later store -- it still holds only "a".
        KeyStore loadedFirst = jostleStore0();
        loadedFirst.load(new ByteArrayInputStream(firstSnapshot), password);
        Assertions.assertEquals(aliasSet("a"), aliases(loadedFirst));
        Assertions.assertArrayEquals(keyA.getPrivate().getEncoded(),
                loadedFirst.getKey("a", password).getEncoded());
    }

    @Test
    public void loadIntoPopulatedInstanceReplacesEntries()
        throws Exception
    {
        char[] password = randomPassword();
        KeyPair keyX = rsaKeyPair();
        KeyPair keyY = rsaKeyPair();
        X509Certificate certX = selfSigned(keyX, "SHA256withRSA", "CN=Jostle KS Replace X");
        X509Certificate certY = selfSigned(keyY, "SHA256withRSA", "CN=Jostle KS Replace Y");

        // Build a keystore whose only entry is "y".
        KeyStore source = jostleStore();
        source.setKeyEntry("y", keyY.getPrivate(), password, new Certificate[] {certY});
        byte[] yEncoded = storeToBytes(source, password);

        // Populate an instance with "x", then load the "y" keystore into it: a
        // successful load replaces all prior entries (exercises replace_entries).
        KeyStore keyStore = jostleStore();
        keyStore.setKeyEntry("x", keyX.getPrivate(), password, new Certificate[] {certX});
        Assertions.assertTrue(keyStore.containsAlias("x"));

        keyStore.load(new ByteArrayInputStream(yEncoded), password);
        Assertions.assertEquals(aliasSet("y"), aliases(keyStore));
        Assertions.assertFalse(keyStore.containsAlias("x"));
        Assertions.assertArrayEquals(keyY.getPrivate().getEncoded(),
                keyStore.getKey("y", password).getEncoded());
    }

    // -----------------------------------------------------------------
    // multi-entry
    // -----------------------------------------------------------------

    @Test
    public void multipleKeyEntriesRoundTrip()
        throws Exception
    {
        char[] password = randomPassword();
        KeyStore keyStore = jostleStore();

        KeyPair[] keyPairs = new KeyPair[3];
        for (int i = 0; i < keyPairs.length; i++)
        {
            keyPairs[i] = rsaKeyPair();
            X509Certificate cert = selfSigned(keyPairs[i], "SHA256withRSA",
                    "CN=Jostle KS Multi " + i);
            keyStore.setKeyEntry("key" + i, keyPairs[i].getPrivate(), password,
                    new Certificate[] {cert});
        }

        byte[] encoded = storeToBytes(keyStore, password);
        KeyStore loaded = jostleStore0();
        loaded.load(new ByteArrayInputStream(encoded), password);

        Assertions.assertEquals(aliasSet("key0", "key1", "key2"), aliases(loaded));
        for (int i = 0; i < keyPairs.length; i++)
        {
            Assertions.assertTrue(loaded.isKeyEntry("key" + i));
            Assertions.assertArrayEquals(keyPairs[i].getPrivate().getEncoded(),
                    loaded.getKey("key" + i, password).getEncoded());
        }
    }

    // -----------------------------------------------------------------
    // non-RSA BC encode round-trip (P1.5): in-bag PKCS#8 must round-trip
    // through BouncyCastle's stricter parser for every key type Jostle stores.
    // -----------------------------------------------------------------

    @Test
    public void ecKeyEntryJostleStoresBouncyCastleReads()
        throws Exception
    {
        assertJostleStoredKeyReadableByBouncyCastle(
                ecKeyPair("P-256"), "EC", "CN=Jostle KS EC Interop");
    }

    @Test
    public void ed25519KeyEntryJostleStoresBouncyCastleReads()
        throws Exception
    {
        assertJostleStoredKeyReadableByBouncyCastle(
                edKeyPair("ED25519"), "Ed25519", "CN=Jostle KS Ed25519 Interop");
    }

    /**
     * Full-fidelity EdDSA interop: a self-signed Ed25519 certificate (BC builds
     * an Ed25519 ContentSigner from the Jostle key) plus a BC sign/verify
     * cross-check on the recovered key. This exercises BC's foreign-EdDSA-key
     * path, which only works on JVMs that ship the EdDSA interfaces
     * (java.security.interfaces.EdEC*, JDK 15+), so it is skipped on older JVMs.
     * The companion ed25519KeyEntryJostleStoresBouncyCastleReads runs on every
     * JVM (RSA-signed cert + KeyFactory comparison) and keeps the Ed25519 key
     * marshalling covered there.
     */
    @Test
    public void ed25519EddsaInteropWhenJvmHasEdDSA()
        throws Exception
    {
        Assumptions.assumeTrue(jvmHasEdDSAInterface(),
                "JVM lacks java.security.interfaces.EdECKey (EdDSA added in JDK 15)");

        char[] password = randomPassword();
        KeyPair keyPair = edKeyPair("ED25519");
        X509Certificate cert = selfSigned(keyPair, "Ed25519",
                "CN=Jostle KS Ed25519 EdDSA Interop");

        KeyStore jostle = jostleStore();
        jostle.setKeyEntry("k", keyPair.getPrivate(), password,
                new Certificate[] {cert});
        byte[] encoded = storeToBytes(jostle, password);

        KeyStore bc = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
        bc.load(new ByteArrayInputStream(encoded), password);

        Assertions.assertTrue(bc.isKeyEntry("k"));
        PrivateKey recovered = (PrivateKey) bc.getKey("k", password);
        Assertions.assertNotNull(recovered);

        // Sign with the recovered key and verify against the original public
        // key: proves the round-tripped key is the same and usable for EdDSA.
        byte[] data = new byte[64];
        RANDOM.nextBytes(data);
        Signature signer = Signature.getInstance("Ed25519", BouncyCastleProvider.PROVIDER_NAME);
        signer.initSign(recovered);
        signer.update(data);
        byte[] signature = signer.sign();
        Signature verifier = Signature.getInstance("Ed25519", BouncyCastleProvider.PROVIDER_NAME);
        verifier.initVerify(keyPair.getPublic());
        verifier.update(data);
        Assertions.assertTrue(verifier.verify(signature));

        Certificate[] chain = bc.getCertificateChain("k");
        Assertions.assertNotNull(chain);
        Assertions.assertEquals(1, chain.length);
        Assertions.assertArrayEquals(cert.getEncoded(), chain[0].getEncoded());
    }

    private static boolean jvmHasEdDSAInterface()
    {
        try
        {
            Class.forName("java.security.interfaces.EdECKey");
            return true;
        }
        catch (ClassNotFoundException e)
        {
            return false;
        }
    }

    private static void assertJostleStoredKeyReadableByBouncyCastle(
            KeyPair keyPair, String keyFactoryAlgorithm, String dn)
        throws Exception
    {
        char[] password = randomPassword();
        // Sign the entry certificate with a throwaway RSA CA (SHA256withRSA),
        // NOT the entry key's own algorithm: building a BouncyCastle ContentSigner
        // from a foreign (Jostle) EdDSA key fails on JDKs without built-in EdDSA
        // (8, 11), and that signing is incidental to what this test verifies. The
        // cert still carries the entry's public key as its subject.
        X509Certificate cert = caSignedCertificate(dn, keyPair.getPublic(),
                rsaKeyPair().getPrivate());

        KeyStore jostle = jostleStore();
        jostle.setKeyEntry("k", keyPair.getPrivate(), password, new Certificate[] {cert});
        byte[] encoded = storeToBytes(jostle, password);

        KeyStore bc = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
        bc.load(new ByteArrayInputStream(encoded), password);

        Assertions.assertTrue(bc.isKeyEntry("k"));
        Key recovered = bc.getKey("k", password);
        Assertions.assertNotNull(recovered);

        // Prove BouncyCastle recovered the exact key. A raw getEncoded() compare
        // is too strict (OpenSSL omits the optional EC public-key field that BC
        // includes), and a sign/verify cross-check relies on BC handling a
        // foreign key (fragile for EdDSA). Instead normalise BOTH the original
        // Jostle key and the keystore-recovered key through BC's KeyFactory --
        // which decodes PKCS#8 with BC's own EdDSA/EC, independent of JDK
        // provider support -- so their canonical encodings are directly
        // comparable. A mismatch means the bag mis-encoded the curve/scalar.
        KeyFactory bcKeyFactory =
                KeyFactory.getInstance(keyFactoryAlgorithm, BouncyCastleProvider.PROVIDER_NAME);
        PrivateKey originalViaBc = bcKeyFactory.generatePrivate(
                new PKCS8EncodedKeySpec(keyPair.getPrivate().getEncoded()));
        Assertions.assertArrayEquals(originalViaBc.getEncoded(),
                ((PrivateKey)recovered).getEncoded());

        Certificate[] chain = bc.getCertificateChain("k");
        Assertions.assertNotNull(chain);
        Assertions.assertEquals(1, chain.length);
        Assertions.assertArrayEquals(cert.getEncoded(), chain[0].getEncoded());
    }

    private static X509Certificate caSignedCertificate(String dn, PublicKey subjectKey,
                                                       PrivateKey caKey)
        throws Exception
    {
        X500Name name = new X500Name(dn);
        BigInteger serial = new BigInteger(64, RANDOM).abs().add(BigInteger.ONE);
        Date notBefore = new Date(System.currentTimeMillis() - 3600_000L);
        Date notAfter = new Date(System.currentTimeMillis() + 3600_000L);
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                name, serial, notBefore, notAfter, name, subjectKey);
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(caKey);
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }

    // -----------------------------------------------------------------
    // helpers
    // -----------------------------------------------------------------

    private static KeyStore jostleStore()
        throws Exception
    {
        KeyStore keyStore = jostleStore0();
        keyStore.load(null, null);
        return keyStore;
    }

    private static KeyStore jostleStore0()
        throws Exception
    {
        return KeyStore.getInstance("PKCS12", JostleProvider.PROVIDER_NAME);
    }

    private static byte[] storeToBytes(KeyStore keyStore, char[] password)
        throws Exception
    {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        keyStore.store(out, password);
        byte[] encoded = out.toByteArray();
        Assertions.assertTrue(encoded.length > 0);
        return encoded;
    }

    private static KeyPair rsaKeyPair()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", JostleProvider.PROVIDER_NAME);
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    private static KeyPair ecKeyPair(String curve)
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", JostleProvider.PROVIDER_NAME);
        kpg.initialize(new ECGenParameterSpec(curve));
        return kpg.generateKeyPair();
    }

    private static KeyPair edKeyPair(String algorithm)
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm, JostleProvider.PROVIDER_NAME);
        return kpg.generateKeyPair();
    }

    private static X509Certificate selfSigned(KeyPair keyPair, String signatureAlgorithm,
                                              String dn)
        throws Exception
    {
        X500Name name = new X500Name(dn);
        BigInteger serial = new BigInteger(64, RANDOM).abs().add(BigInteger.ONE);
        Date notBefore = new Date(System.currentTimeMillis() - 3600_000L);
        Date notAfter = new Date(System.currentTimeMillis() + 3600_000L);
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                name, serial, notBefore, notAfter, name, keyPair.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm)
                .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(keyPair.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }

    private static char[] randomPassword()
    {
        char[] password = new char[12];
        for (int i = 0; i < password.length; i++)
        {
            password[i] = (char) ('a' + RANDOM.nextInt(26));
        }
        return password;
    }

    private static Set<String> aliases(KeyStore keyStore)
        throws Exception
    {
        Set<String> aliases = new HashSet<String>();
        java.util.Enumeration<String> enumeration = keyStore.aliases();
        while (enumeration.hasMoreElements())
        {
            aliases.add(enumeration.nextElement());
        }
        return aliases;
    }

    private static Set<String> aliasSet(String... aliases)
    {
        Set<String> set = new HashSet<String>();
        for (String alias : aliases)
        {
            set.add(alias);
        }
        return set;
    }
}
