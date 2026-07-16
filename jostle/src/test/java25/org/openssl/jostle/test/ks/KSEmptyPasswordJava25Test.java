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
import java.util.Base64;
import java.util.Date;

/**
 * Empty-password PKCS#12 handling. PKCS#12 seeds the MAC/KDF differently for a
 * NULL password and a zero-length one; Jostle collapses an empty caller
 * password to the NULL form on store, and on load retries the "" form when the
 * NULL form fails (mirroring OpenSSL's own PKCS12_parse). Without that retry a
 * keystore whose MAC was built with the explicit empty-string form -- which the
 * {@code openssl pkcs12 -export -passout pass:} CLI produces -- would fail
 * Jostle's MAC check.
 *
 * <p>Lives in the java25 source set because the OpenSSL-produced fixture is
 * embedded as a text block, and because the KS suite only runs under the
 * unitTest25 tasks anyway.
 */
public class KSEmptyPasswordJava25Test
{
    // An RSA key + self-signed cert exported by the OpenSSL 3.6.2 CLI with an
    // EXPLICIT EMPTY password (the "" form, not NULL):
    //   openssl req -x509 -newkey rsa:2048 -keyout k.pem -out c.pem -nodes -subj /CN=...
    //   openssl pkcs12 -export -inkey k.pem -in c.pem -name emptypwdkey \
    //           -out empty.p12 -passout pass:
    // MAC sha256/2048, key + cert PBES2/PBKDF2/AES-256-CBC. Regenerating with a
    // fresh key yields a different but equally-valid blob; the test only cares
    // that it is a well-formed "" -form keystore Jostle must read.
    private static final String OPENSSL_EMPTY_PASSWORD_P12 = """
            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
            t8iJTlyItDqRHwOSGuACAggA            """;

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

    /**
     * The load-side "" retry: an OpenSSL-produced keystore whose MAC and content
     * use the empty-string form must load under a zero-length password. Jostle's
     * first attempt (NULL form) fails the MAC, the "" retry succeeds, and the
     * chosen form then decrypts the safe and shrouded key. Exercises the exact
     * code path added for the empty-password interop fix.
     */
    @Test
    public void jostleReadsOpenSslEmptyStringPasswordKeystore()
        throws Exception
    {
        byte[] p12 = Base64.getMimeDecoder().decode(OPENSSL_EMPTY_PASSWORD_P12);

        KeyStore ks = KeyStore.getInstance("PKCS12", JostleProvider.PROVIDER_NAME);
        ks.load(new ByteArrayInputStream(p12), new char[0]);

        Assertions.assertTrue(ks.containsAlias("emptypwdkey"), "alias present");
        Assertions.assertTrue(ks.isKeyEntry("emptypwdkey"), "is a key entry");

        PrivateKey key = (PrivateKey) ks.getKey("emptypwdkey", new char[0]);
        Assertions.assertNotNull(key, "private key recovered under empty password");

        Certificate[] chain = ks.getCertificateChain("emptypwdkey");
        Assertions.assertNotNull(chain, "certificate chain recovered");
        Assertions.assertEquals(1, chain.length);
        Assertions.assertTrue(chain[0] instanceof X509Certificate);
    }

    /**
     * Regression guard for the load-side changes (trailing-data check, unpack
     * hard-fail, "" retry): Jostle's own empty-password keystore must still
     * round-trip, key + chain intact.
     */
    @Test
    public void jostleEmptyPasswordSelfRoundTrip()
        throws Exception
    {
        char[] empty = new char[0];
        KeyPair keyPair = rsaKeyPair();
        X509Certificate cert = selfSigned(keyPair, "CN=Jostle Empty Pwd Self");

        KeyStore store = KeyStore.getInstance("PKCS12", JostleProvider.PROVIDER_NAME);
        store.load(null, null);
        store.setKeyEntry("k", keyPair.getPrivate(), empty, new Certificate[] {cert});
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        store.store(out, empty);

        KeyStore reload = KeyStore.getInstance("PKCS12", JostleProvider.PROVIDER_NAME);
        reload.load(new ByteArrayInputStream(out.toByteArray()), empty);
        Assertions.assertTrue(reload.isKeyEntry("k"));
        PrivateKey recovered = (PrivateKey) reload.getKey("k", empty);
        Assertions.assertNotNull(recovered);
        Assertions.assertArrayEquals(keyPair.getPrivate().getEncoded(),
                recovered.getEncoded());
        Certificate[] chain = reload.getCertificateChain("k");
        Assertions.assertNotNull(chain);
        Assertions.assertEquals(1, chain.length);
        Assertions.assertArrayEquals(cert.getEncoded(), chain[0].getEncoded());
    }

    private static KeyPair rsaKeyPair()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", JostleProvider.PROVIDER_NAME);
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    private static X509Certificate selfSigned(KeyPair keyPair, String dn)
        throws Exception
    {
        X500Name name = new X500Name(dn);
        Date notBefore = new Date(System.currentTimeMillis() - 3600_000L);
        Date notAfter = new Date(System.currentTimeMillis() + 3600_000L);
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                name, BigInteger.valueOf(1L), notBefore, notAfter, name, keyPair.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(keyPair.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }
}
