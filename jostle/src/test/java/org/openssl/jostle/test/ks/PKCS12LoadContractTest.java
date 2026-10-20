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
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.provider.ks.KSServiceNI;
import org.openssl.jostle.test.TestUtil;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;

/**
 * What a PKCS#12 load and store refuse on their own, with no reference to
 * compare against: the input ceiling, a store algorithm this build cannot run,
 * and the null password told apart from the empty one on the bridge.
 */
public class PKCS12LoadContractTest
{
    private static final String CEILING = "org.openssl.jostle.pkcs12.max_store_bytes";
    private static final char[] PW = "changeit".toCharArray();

    private final KSServiceNI ni = NISelector.KSServiceNI;

    @BeforeAll
    public static void before()
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

    @AfterEach
    public void clearCeiling()
    {
        System.clearProperty(CEILING);
    }

    private static byte[] aStore(char[] password) throws Exception
    {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC", "SunEC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = g.generateKeyPair();
        X500Name n = new X500Name("CN=Load Contract");
        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(new JcaX509v3CertificateBuilder(
                n, BigInteger.ONE, new Date(System.currentTimeMillis() - 3600_000L),
                new Date(System.currentTimeMillis() + 3600_000L), n, kp.getPublic())
                .build(new JcaContentSignerBuilder("SHA256withECDSA")
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(kp.getPrivate())));
        KeyStore ks = KeyStore.getInstance("PKCS12", JostleProvider.PROVIDER_NAME);
        ks.load(null, null);
        ks.setKeyEntry("key", kp.getPrivate(), password, new Certificate[]{cert});
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ks.store(out, password);
        return out.toByteArray();
    }

    private static KeyStore load(byte[] file, char[] password) throws Exception
    {
        KeyStore ks = KeyStore.getInstance("PKCS12", JostleProvider.PROVIDER_NAME);
        ks.load(new ByteArrayInputStream(file), password);
        return ks;
    }

    // ------------------------------------------------------------- ceiling

    /**
     * The ceiling bounds the stream before any parse, with the property lowered
     * to the store's own length: that length loads, one byte less is refused.
     */
    @Test
    public void theCeilingRefusesOneByteOverAndAcceptsTheExactLength() throws Exception
    {
        byte[] file = aStore(PW);

        System.setProperty(CEILING, Integer.toString(file.length));
        Assertions.assertTrue(load(file, PW).isKeyEntry("key"), "the exact length loads");

        System.setProperty(CEILING, Integer.toString(file.length - 1));
        IOException e = Assertions.assertThrows(IOException.class, () -> load(file, PW));
        Assertions.assertEquals("key store input exceeds the configured ceiling; raise " + CEILING, e.getMessage());
        Assertions.assertNotNull(e.getCause());
        Assertions.assertEquals("CeilingExceededException", e.getCause().getClass().getSimpleName());
        Assertions.assertEquals(e.getMessage(), e.getCause().getMessage());
    }

    /** A ceiling that is not an integer is refused, not defaulted. */
    @Test
    public void aCeilingThatIsNotAnIntegerIsRefused() throws Exception
    {
        byte[] file = aStore(PW);
        System.setProperty(CEILING, "sixty-four megabytes");
        IOException e = Assertions.assertThrows(IOException.class, () -> load(file, PW));
        Assertions.assertEquals(CEILING + " is not an integer", e.getMessage());
        Assertions.assertTrue(e.getCause() instanceof NumberFormatException);
    }

    // --------------------------------------------------- unsupported store

    /**
     * The AES-GCM key protection selectors: OpenSSL's PBES2 runs no AEAD
     * cipher, so the store is refused naming the cipher, not as a malformed
     * request. Asked at the NI because no registered type selects GCM.
     */
    @Test
    public void aGcmStoreIsAnUnsupportedAlgorithmNamedByItsOid() throws Exception
    {
        long ref = ni.allocateKeyStore("PKCS12");
        try
        {
            ni.load(ref, aStore(PW), new String(PW).getBytes(StandardCharsets.UTF_8));
            for (int keyPbe : new int[]{4, 5})
            {
                IOException e = Assertions.assertThrows(IOException.class, () -> ni.store(ref,
                        "changeit".getBytes(StandardCharsets.UTF_8), keyPbe, 2, 1, 2, 2048, 2048,
                        KSServiceNI.SECRET_FORM_RFC7292, TestUtil.RNDSrc));
                Assertions.assertTrue(e.getCause() instanceof NoSuchAlgorithmException, String.valueOf(e.getCause()));
                String oid = keyPbe == 4 ? "2.16.840.1.101.3.4.1.6" : "2.16.840.1.101.3.4.1.46";
                Assertions.assertTrue(e.getMessage().contains(oid), e.getMessage());
            }
        }
        finally
        {
            ni.dispose(ref);
        }
    }

    // ------------------------------------------- null and empty passwords

    /**
     * A null password and an empty one are two loads on both bridges: the
     * empty one is a password, so the keys decrypt at load; the null one checks
     * no MAC and keeps the keys encrypted until asked with their password.
     */
    @Test
    public void aNullAndAnEmptyPasswordAreDifferentLoadsOnTheBridge() throws Exception
    {
        byte[] file = aStore(new char[0]);
        long ref = ni.allocateKeyStore("PKCS12");
        try
        {
            ni.load(ref, file, new byte[0]);
            Assertions.assertNotNull(ni.getKey(ref, "key", new byte[0]), "empty: decrypted at load");

            byte[] other = aStore(PW);
            ni.load(ref, other, null);
            Assertions.assertTrue(ni.isKeyEntry(ref, "key"), "null: the key entry is listed");
            Assertions.assertNotNull(ni.getKey(ref, "key", new String(PW).getBytes(StandardCharsets.UTF_8)),
                    "null: decrypted at getKey with its password");
            IOException wrongMac = Assertions.assertThrows(IOException.class,
                    () -> ni.load(ref, other, new byte[0]), "empty is a password, and the wrong one");
            Assertions.assertEquals("PKCS12 keystore integrity check failed", wrongMac.getMessage());
        }
        finally
        {
            ni.dispose(ref);
        }
    }
}
