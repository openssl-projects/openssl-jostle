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

package org.openssl.jostle.test.cert;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v2CRLBuilder;
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
import java.security.Security;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;

/**
 * PEM input to the X.509 {@code CertificateFactory} — certificates and CRLs,
 * singular and plural, and the negative paths RFC 7468 and the JDK/BC
 * behaviour define.
 */
public class X509PemInputTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final String SUN = "SUN";
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    @BeforeAll
    static void before()
    {
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private static X509Certificate selfSignedCert(String cn, KeyPair kp) throws Exception
    {
        X500Name dn = new X500Name("CN=" + cn);
        Date notBefore = new Date(System.currentTimeMillis() - 3600_000L);
        Date notAfter = new Date(System.currentTimeMillis() + 3600_000L * 24 * 30);
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                dn, BigInteger.valueOf(1), notBefore, notAfter, dn, kp.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        builder.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign | KeyUsage.digitalSignature));
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(JSL).build(kp.getPrivate());
        return new JcaX509CertificateConverter().setProvider(JSL).getCertificate(builder.build(signer));
    }

    private static X509CRL selfSignedCrl(X509Certificate issuer, KeyPair kp) throws Exception
    {
        Date notBefore = new Date(System.currentTimeMillis() - 3600_000L);
        Date notAfter = new Date(System.currentTimeMillis() + 3600_000L * 24 * 30);
        JcaX509v2CRLBuilder crlBuilder = new JcaX509v2CRLBuilder(issuer, notBefore);
        crlBuilder.setNextUpdate(notAfter);
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(JSL).build(kp.getPrivate());
        return new JcaX509CRLConverter().setProvider(JSL).getCRL(crlBuilder.build(signer));
    }

    private static String pem(String label, byte[] der)
    {
        String body = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(der);
        return "-----BEGIN " + label + "-----\n" + body + "\n-----END " + label + "-----\n";
    }

    private static byte[] utf8(String s)
    {
        return s.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    }

    // ----- positive: singular round-trip -----

    @Test
    public void pemCertificateDecodesToTheSameCertificateAsDer() throws Exception
    {
        KeyPair kp = KeyPairGenerator.getInstance("RSA", JSL).generateKeyPair();
        X509Certificate cert = selfSignedCert("Jostle PEM Cert Test", kp);
        byte[] der = cert.getEncoded();

        CertificateFactory cf = CertificateFactory.getInstance("X.509", JSL);
        X509Certificate fromDer = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der));
        X509Certificate fromPem = (X509Certificate) cf.generateCertificate(
                new ByteArrayInputStream(utf8(pem("CERTIFICATE", der))));

        Assertions.assertArrayEquals(der, fromPem.getEncoded());
        Assertions.assertEquals(fromDer, fromPem);
    }

    @Test
    public void pemCrlDecodesToTheSameCrlAsDer() throws Exception
    {
        KeyPair kp = KeyPairGenerator.getInstance("RSA", JSL).generateKeyPair();
        X509Certificate issuer = selfSignedCert("Jostle PEM CRL Test CA", kp);
        X509CRL crl = selfSignedCrl(issuer, kp);
        byte[] der = crl.getEncoded();

        CertificateFactory cf = CertificateFactory.getInstance("X.509", JSL);
        X509CRL fromDer = (X509CRL) cf.generateCRL(new ByteArrayInputStream(der));
        X509CRL fromPem = (X509CRL) cf.generateCRL(new ByteArrayInputStream(utf8(pem("X509 CRL", der))));

        Assertions.assertArrayEquals(der, fromPem.getEncoded());
        Assertions.assertEquals(fromDer, fromPem);
    }

    /** RFC 7468's older label, still measured-accepted by both references. */
    @Test
    public void pemCertificateAcceptsTheOldX509CertificateLabel() throws Exception
    {
        KeyPair kp = KeyPairGenerator.getInstance("RSA", JSL).generateKeyPair();
        X509Certificate cert = selfSignedCert("Jostle PEM Old Label Test", kp);
        byte[] der = cert.getEncoded();

        CertificateFactory cf = CertificateFactory.getInstance("X.509", JSL);
        X509Certificate fromPem = (X509Certificate) cf.generateCertificate(
                new ByteArrayInputStream(utf8(pem("X509 CERTIFICATE", der))));
        Assertions.assertArrayEquals(der, fromPem.getEncoded());
    }

    /** Measured: a PEM block followed by trailing bytes leaves them unread. */
    @Test
    public void pemCertificateLeavesTrailingBytesUnread() throws Exception
    {
        KeyPair kp = KeyPairGenerator.getInstance("RSA", JSL).generateKeyPair();
        X509Certificate cert = selfSignedCert("Jostle PEM Trailing Test", kp);
        byte[] der = cert.getEncoded();

        ByteArrayInputStream in = new ByteArrayInputStream(
                utf8(pem("CERTIFICATE", der) + "trailing9"));
        CertificateFactory.getInstance("X.509", JSL).generateCertificate(in);
        Assertions.assertEquals(9, in.available());
    }

    /** SUN and BC both tolerate a blank line before the BEGIN line. */
    @Test
    public void blankLineBeforeBeginIsTolerated() throws Exception
    {
        KeyPair kp = KeyPairGenerator.getInstance("RSA", JSL).generateKeyPair();
        X509Certificate cert = selfSignedCert("Jostle PEM Blank Preamble Test", kp);
        byte[] der = cert.getEncoded();
        assertParsesLikeSun(utf8("\n" + pem("CERTIFICATE", der)), der);
    }

    /** SUN and BC both tolerate prose before the BEGIN line (e.g. an "openssl x509 -text" dump). */
    @Test
    public void textPreambleBeforeBeginIsTolerated() throws Exception
    {
        KeyPair kp = KeyPairGenerator.getInstance("RSA", JSL).generateKeyPair();
        X509Certificate cert = selfSignedCert("Jostle PEM Text Preamble Test", kp);
        byte[] der = cert.getEncoded();
        String preamble = "Certificate:\n    Data:\n        Version: 3 (0x2)\n"
                + "        Serial Number: 1 (0x1)\n";
        assertParsesLikeSun(utf8(preamble + pem("CERTIFICATE", der)), der);
    }

    /** A bundle with comment lines between two blocks still yields both certificates. */
    @Test
    public void commentLinesBetweenBundledBlocksAreTolerated() throws Exception
    {
        KeyPair kp1 = KeyPairGenerator.getInstance("RSA", JSL).generateKeyPair();
        KeyPair kp2 = KeyPairGenerator.getInstance("RSA", JSL).generateKeyPair();
        X509Certificate c1 = selfSignedCert("Jostle PEM Comment Bundle One", kp1);
        X509Certificate c2 = selfSignedCert("Jostle PEM Comment Bundle Two", kp2);

        byte[] bundle = utf8(pem("CERTIFICATE", c1.getEncoded())
                + "# a comment between two PEM blocks\n"
                + pem("CERTIFICATE", c2.getEncoded()));

        Collection<? extends Certificate> ours = CertificateFactory.getInstance("X.509", JSL)
                .generateCertificates(new ByteArrayInputStream(bundle));
        Collection<? extends Certificate> sun = CertificateFactory.getInstance("X.509", SUN)
                .generateCertificates(new ByteArrayInputStream(bundle));
        Assertions.assertEquals(sun.size(), ours.size());
        Assertions.assertEquals(2, ours.size());
        Assertions.assertTrue(ours.stream().anyMatch(c -> c.equals(c1)));
        Assertions.assertTrue(ours.stream().anyMatch(c -> c.equals(c2)));
    }

    /**
     * Text with no PEM block anywhere: both singular and plural refuse, on
     * both providers. Measured (this JDK 25/Zulu install): {@code SUN}'s
     * {@code engineGenerateCertificates} does not loop the same
     * {@code readOneBlock} the singular form uses — it reaches
     * {@code X509Factory.parseX509orPKCS7Cert}, which throws
     * {@code CertificateException("No certificate data found")} for
     * unreadable input rather than returning an empty collection. An empty
     * collection is reserved for a genuinely EMPTY stream (0 bytes), which is
     * a different input and not this cell.
     */
    @Test
    public void noBlockAtAllRefusesBothSingularAndPlural()
    {
        byte[] noBlock = utf8("just some text\nwith no PEM block in it at all\n");

        for (String provider : new String[]{JSL, SUN})
        {
            Assertions.assertThrows(CertificateException.class, () ->
                    CertificateFactory.getInstance("X.509", provider)
                            .generateCertificate(new ByteArrayInputStream(noBlock)));
            Assertions.assertThrows(CertificateException.class, () ->
                    CertificateFactory.getInstance("X.509", provider)
                            .generateCertificates(new ByteArrayInputStream(noBlock)));
        }
    }

    private static void assertParsesLikeSun(byte[] input, byte[] expectedDer) throws Exception
    {
        X509Certificate ours = (X509Certificate) CertificateFactory.getInstance("X.509", JSL)
                .generateCertificate(new ByteArrayInputStream(input));
        X509Certificate sun = (X509Certificate) CertificateFactory.getInstance("X.509", SUN)
                .generateCertificate(new ByteArrayInputStream(input));
        Assertions.assertArrayEquals(expectedDer, ours.getEncoded());
        Assertions.assertArrayEquals(sun.getEncoded(), ours.getEncoded());
    }

    // ----- positive: plural, bundles and mixed DER/PEM -----

    @Test
    public void pemBundleForGenerateCertificatesReturnsBoth() throws Exception
    {
        KeyPair kp1 = KeyPairGenerator.getInstance("RSA", JSL).generateKeyPair();
        KeyPair kp2 = KeyPairGenerator.getInstance("RSA", JSL).generateKeyPair();
        X509Certificate c1 = selfSignedCert("Jostle PEM Bundle One", kp1);
        X509Certificate c2 = selfSignedCert("Jostle PEM Bundle Two", kp2);

        ByteArrayOutputStream bundle = new ByteArrayOutputStream();
        bundle.write(utf8(pem("CERTIFICATE", c1.getEncoded())));
        bundle.write(utf8(pem("CERTIFICATE", c2.getEncoded())));

        Collection<? extends Certificate> certs = CertificateFactory.getInstance("X.509", JSL)
                .generateCertificates(new ByteArrayInputStream(bundle.toByteArray()));
        Assertions.assertEquals(2, certs.size());
        Assertions.assertTrue(certs.stream().anyMatch(c -> c.equals(c1)));
        Assertions.assertTrue(certs.stream().anyMatch(c -> c.equals(c2)));
    }

    /**
     * A DER certificate immediately followed by a PEM one, and the reverse
     * order, both accepted — matched against SUN, since {@code readOne}
     * treats each unit independently regardless of what came before it.
     */
    @Test
    public void mixedDerThenPemAndPemThenDerBothParseLikeSun() throws Exception
    {
        KeyPair kp1 = KeyPairGenerator.getInstance("RSA", JSL).generateKeyPair();
        KeyPair kp2 = KeyPairGenerator.getInstance("RSA", JSL).generateKeyPair();
        X509Certificate c1 = selfSignedCert("Jostle Mixed DER First", kp1);
        X509Certificate c2 = selfSignedCert("Jostle Mixed PEM Second", kp2);

        ByteArrayOutputStream derThenPem = new ByteArrayOutputStream();
        derThenPem.write(c1.getEncoded());
        derThenPem.write(utf8(pem("CERTIFICATE", c2.getEncoded())));

        ByteArrayOutputStream pemThenDer = new ByteArrayOutputStream();
        pemThenDer.write(utf8(pem("CERTIFICATE", c1.getEncoded())));
        pemThenDer.write(c2.getEncoded());

        for (byte[] stream : new byte[][]{derThenPem.toByteArray(), pemThenDer.toByteArray()})
        {
            Collection<? extends Certificate> ours = CertificateFactory.getInstance("X.509", JSL)
                    .generateCertificates(new ByteArrayInputStream(stream));
            Collection<? extends Certificate> sun = CertificateFactory.getInstance("X.509", SUN)
                    .generateCertificates(new ByteArrayInputStream(stream));
            Assertions.assertEquals(sun.size(), ours.size());
            Assertions.assertEquals(2, ours.size());
        }
    }

    // ----- negative: exception TYPE parity with SUN and BC, our own text -----

    @Test
    public void garbageBetweenMarkersIsRefusedTyped()
    {
        byte[] bad = utf8("-----BEGIN CERTIFICATE-----\nnot base64 at all!!\n-----END CERTIFICATE-----\n");
        assertAllThreeRefuseTyped(bad);
    }

    @Test
    public void missingEndMarkerIsRefusedTyped() throws Exception
    {
        KeyPair kp = KeyPairGenerator.getInstance("RSA", JSL).generateKeyPair();
        X509Certificate cert = selfSignedCert("Jostle PEM No Footer Test", kp);
        String body = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(cert.getEncoded());
        byte[] noFooter = utf8("-----BEGIN CERTIFICATE-----\n" + body + "\n");
        assertAllThreeRefuseTyped(noFooter);
    }

    @Test
    public void mismatchedBeginAndEndLabelsIsRefusedTyped() throws Exception
    {
        KeyPair kp = KeyPairGenerator.getInstance("RSA", JSL).generateKeyPair();
        X509Certificate cert = selfSignedCert("Jostle PEM Mismatch Test", kp);
        String body = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(cert.getEncoded());
        byte[] mismatched = utf8(
                "-----BEGIN CERTIFICATE-----\n" + body + "\n-----END X509 CRL-----\n");
        Assertions.assertThrows(CertificateException.class, () ->
                CertificateFactory.getInstance("X.509", JSL)
                        .generateCertificate(new ByteArrayInputStream(mismatched)));
    }

    /**
     * A CRL, PEM-wrapped as though it were a certificate. Measured: neither
     * SUN nor BC check the PEM label against the call site — the DER decodes
     * (it is well-formed ASN.1) and is refused only because it is not a
     * Certificate structure, exactly as a CRL fed to {@code generateCertificate}
     * as raw DER is refused (see {@link X509CertificateFactoryTest}).
     */
    @Test
    public void aCrlPemWrappedAsACertificateIsRefusedByStructureNotByLabel() throws Exception
    {
        KeyPair kp = KeyPairGenerator.getInstance("RSA", JSL).generateKeyPair();
        X509Certificate issuer = selfSignedCert("Jostle PEM Wrong Type Test CA", kp);
        X509CRL crl = selfSignedCrl(issuer, kp);
        byte[] wrongLabelPem = utf8(pem("CERTIFICATE", crl.getEncoded()));

        for (String provider : new String[]{JSL, SUN, BC})
        {
            Assertions.assertThrows(CertificateException.class, () ->
                    CertificateFactory.getInstance("X.509", provider)
                            .generateCertificate(new ByteArrayInputStream(wrongLabelPem)));
        }
    }

    /**
     * A PEM body whose decoded length would exceed the certificate ceiling is
     * refused before the whole thing is buffered, not merely after — the
     * bound checked in {@code readPem} is on the base64 TEXT read so far, so
     * this must not hang or allocate the full oversized body first.
     */
    @Test
    public void oversizedPemBodyIsRefusedTyped()
    {
        int ceiling = org.openssl.jostle.jcajce.provider.cert.X509NI.maxCertificateBytes();
        char[] filler = new char[2 * ceiling + 4096];
        java.util.Arrays.fill(filler, 'A');
        byte[] oversized = utf8("-----BEGIN CERTIFICATE-----\n" + new String(filler) + "\n-----END CERTIFICATE-----\n");
        Assertions.assertThrows(CertificateException.class, () ->
                CertificateFactory.getInstance("X.509", JSL)
                        .generateCertificate(new ByteArrayInputStream(oversized)));
    }

    private static void assertAllThreeRefuseTyped(byte[] input)
    {
        for (String provider : new String[]{JSL, SUN, BC})
        {
            Assertions.assertThrows(CertificateException.class, () ->
                    CertificateFactory.getInstance("X.509", provider)
                            .generateCertificate(new ByteArrayInputStream(input)));
        }
    }
}
