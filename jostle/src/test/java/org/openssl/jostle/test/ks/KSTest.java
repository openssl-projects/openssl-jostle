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
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.util.Arrays;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
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
    private static final long SEED = new SecureRandom().nextLong();
    private static final SecureRandom RANDOM = new SecureRandom(longToBytes(SEED));

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
        System.out.println("KSTest random seed: " + SEED);
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
                ecKeyPair("P-256"), "SHA256withECDSA", "CN=Jostle KS EC Interop");
    }

    @Test
    public void ed25519KeyEntryJostleStoresBouncyCastleReads()
        throws Exception
    {
        assertJostleStoredKeyReadableByBouncyCastle(
                edKeyPair("ED25519"), "Ed25519", "CN=Jostle KS Ed25519 Interop");
    }

    private static void assertJostleStoredKeyReadableByBouncyCastle(
            KeyPair keyPair, String signatureAlgorithm, String dn)
        throws Exception
    {
        char[] password = randomPassword();
        X509Certificate cert = selfSigned(keyPair, signatureAlgorithm, dn);

        KeyStore jostle = jostleStore();
        jostle.setKeyEntry("k", keyPair.getPrivate(), password, new Certificate[] {cert});
        byte[] encoded = storeToBytes(jostle, password);

        KeyStore bc = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
        bc.load(new ByteArrayInputStream(encoded), password);

        Assertions.assertTrue(bc.isKeyEntry("k"));
        Key recovered = bc.getKey("k", password);
        Assertions.assertNotNull(recovered);

        // Prove BouncyCastle recovered the SAME private key, robustly: sign with
        // the recovered key and verify against the original public key. A byte
        // comparison of getEncoded() is too strict here -- both encodings are
        // valid PKCS#8 for the same key, but OpenSSL omits the optional EC
        // public-key field (RFC 5915) that BouncyCastle includes, so the bytes
        // legitimately differ even though the key value is identical. The
        // sign/verify pairing fails iff the curve/scalar were mis-encoded.
        byte[] data = new byte[64];
        RANDOM.nextBytes(data);
        Signature signer = Signature.getInstance(signatureAlgorithm, BouncyCastleProvider.PROVIDER_NAME);
        signer.initSign((PrivateKey) recovered);
        signer.update(data);
        byte[] signature = signer.sign();
        Signature verifier = Signature.getInstance(signatureAlgorithm, BouncyCastleProvider.PROVIDER_NAME);
        verifier.initVerify(keyPair.getPublic());
        verifier.update(data);
        Assertions.assertTrue(verifier.verify(signature));

        Certificate[] chain = bc.getCertificateChain("k");
        Assertions.assertNotNull(chain);
        Assertions.assertEquals(1, chain.length);
        Assertions.assertArrayEquals(cert.getEncoded(), chain[0].getEncoded());
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

    private static byte[] longToBytes(long value)
    {
        byte[] bytes = new byte[8];
        for (int i = 7; i >= 0; i--)
        {
            bytes[i] = (byte) (value & 0xff);
            value >>= 8;
        }
        return bytes;
    }
}
