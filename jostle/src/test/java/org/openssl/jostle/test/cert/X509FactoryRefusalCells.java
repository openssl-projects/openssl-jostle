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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.function.Executable;
import org.openssl.jostle.jcajce.provider.cert.X509NI;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;

/**
 * The CertificateFactory's refusals, driven through the JCA surface of one
 * provider: every refusal is the JCA's checked type, the size ceiling bounds
 * the whole encoding, and a PEM body carries exactly one object.
 * <p>
 * Each cell moves a system property and restores it in a finally.
 */
public final class X509FactoryRefusalCells
{
    private static final String CERT_PROP = X509NI.MAX_CERT_BYTES_PROPERTY;
    private static final String CONTAINER_PROP = X509NI.MAX_CONTAINER_BYTES_PROPERTY;
    private static final String MEMBERS_PROP = X509NI.MAX_MEMBERS_PROPERTY;
    private static final String CEILING_TEXT = "exceeds the configured ceiling";

    private final String provider;

    public X509FactoryRefusalCells(String provider)
    {
        this.provider = provider;
    }

    private CertificateFactory cf()
        throws Exception
    {
        return CertificateFactory.getInstance("X.509", provider);
    }

    private static InputStream in(byte[] b)
    {
        return new ByteArrayInputStream(b);
    }

    private interface Body
    {
        void run()
            throws Exception;
    }

    private static void withProperty(String name, String value, Body body)
        throws Exception
    {
        String restore = System.getProperty(name);
        System.setProperty(name, value);
        try
        {
            body.run();
        }
        finally
        {
            if (restore == null)
            {
                System.clearProperty(name);
            }
            else
            {
                System.setProperty(name, restore);
            }
        }
    }

    private static void certRefusal(String what, String text, Executable call)
    {
        CertificateException e = Assertions.assertThrows(CertificateException.class, call, what);
        Assertions.assertTrue(e.getMessage().contains(text), what + ": " + e.getMessage());
    }

    private static void crlRefusal(String what, String text, Executable call)
    {
        CRLException e = Assertions.assertThrows(CRLException.class, call, what);
        Assertions.assertTrue(e.getMessage().contains(text), what + ": " + e.getMessage());
    }

    private static byte[] prose(int atLeast)
    {
        StringBuilder sb = new StringBuilder();
        while (sb.length() < atLeast)
        {
            sb.append("a line of prose that is not a PEM header at all\n");
        }
        return X509Fixtures.ascii(sb.toString());
    }

    private static byte[] base64Body(int atLeast)
    {
        StringBuilder sb = new StringBuilder("-----BEGIN CERTIFICATE-----\n");
        while (sb.length() < atLeast)
        {
            sb.append("QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB\n");
        }
        sb.append("-----END CERTIFICATE-----\n");
        return X509Fixtures.ascii(sb.toString());
    }

    /**
     * The four over-ceiling inputs: a DER header naming more than the ceiling,
     * a 0xFFFFFFFF length, a PEM preamble over the text bound and a PEM body over
     * it. With a ceiling of 1000 the text bound is 2 * 1000 + 1024 characters.
     */
    private static byte[][] overCeiling()
    {
        return new byte[][]{
                {0x30, (byte) 0x82, 0x07, (byte) 0xD0},
                {0x30, (byte) 0x84, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF},
                X509Fixtures.concat(prose(3100), X509Fixtures.ascii("-----BEGIN CERTIFICATE-----\n")),
                base64Body(3100)};
    }

    /** Every over-ceiling input is the JCA's checked type on every generate path. */
    public void ceilingRefusalsAreCheckedOnEveryPath()
        throws Exception
    {
        CertificateFactory cf = cf();
        byte[] good = X509Fixtures.certificate(null, null, null);
        withProperty(CERT_PROP, "1000", () -> withProperty(CONTAINER_PROP, "1000", () ->
        {
            for (byte[] input : overCeiling())
            {
                certRefusal("generateCertificate", CEILING_TEXT, () -> cf.generateCertificate(in(input)));
                certRefusal("generateCertificates", CEILING_TEXT, () -> cf.generateCertificates(in(input)));
                certRefusal("generateCertificates after one certificate", CEILING_TEXT,
                        () -> cf.generateCertificates(in(X509Fixtures.concat(good, input))));
                crlRefusal("generateCRL", CEILING_TEXT, () -> cf.generateCRL(in(input)));
                crlRefusal("generateCRLs", CEILING_TEXT, () -> cf.generateCRLs(in(input)));
                certRefusal("generateCertPath PkiPath", CEILING_TEXT,
                        () -> cf.generateCertPath(in(input), "PkiPath"));
                certRefusal("generateCertPath PKCS7", CEILING_TEXT,
                        () -> cf.generateCertPath(in(input), "PKCS7"));
            }
        }));
    }

    /** An empty stream is refused before any decode, on both encodings. */
    public void certPathFromAnEmptyStreamIsEmptyInput()
        throws Exception
    {
        CertificateFactory cf = cf();
        certRefusal("PkiPath", "Empty input", () -> cf.generateCertPath(in(new byte[0]), "PkiPath"));
        certRefusal("PKCS7", "Empty input", () -> cf.generateCertPath(in(new byte[0]), "PKCS7"));
    }

    /** A ceiling property that is not a number is refused typed, naming the property. */
    public void nonNumericCeilingPropertyIsRefusedNamingIt()
        throws Exception
    {
        CertificateFactory cf = cf();
        byte[] cert = X509Fixtures.certificate(null, null, null);
        byte[] crl = X509Fixtures.crl(null);
        X509Certificate parsed = (X509Certificate) cf.generateCertificate(in(cert));
        withProperty(CERT_PROP, "abc", () ->
        {
            certRefusal("generateCertificate", CERT_PROP, () -> cf.generateCertificate(in(cert)));
            certRefusal("generateCertificates", CERT_PROP, () -> cf.generateCertificates(in(cert)));
        });
        withProperty(CONTAINER_PROP, "abc", () ->
        {
            crlRefusal("generateCRL", CONTAINER_PROP, () -> cf.generateCRL(in(crl)));
            crlRefusal("generateCRLs", CONTAINER_PROP, () -> cf.generateCRLs(in(crl)));
            certRefusal("generateCertPath", CONTAINER_PROP, () -> cf.generateCertPath(in(cert), "PkiPath"));
        });
        withProperty(MEMBERS_PROP, "abc", () ->
        {
            certRefusal("generateCertificates", MEMBERS_PROP, () -> cf.generateCertificates(in(cert)));
            crlRefusal("generateCRLs", MEMBERS_PROP, () -> cf.generateCRLs(in(crl)));
            certRefusal("generateCertPath list", MEMBERS_PROP,
                    () -> cf.generateCertPath(Collections.singletonList(parsed)));
            certRefusal("generateCertPath stream", MEMBERS_PROP, () -> cf.generateCertPath(in(cert), "PkiPath"));
        });
    }

    /**
     * The ceiling counts the whole encoding, header included, so the factory
     * refuses at exactly the length the native bridge bounds: one below is the
     * factory's own refusal, never the bridge's.
     */
    public void ceilingBoundsTheWholeEncoding()
        throws Exception
    {
        CertificateFactory cf = cf();
        byte[] cert = X509Fixtures.certificate(null, null, null);
        byte[] crl = X509Fixtures.crl(null);
        withProperty(CERT_PROP, String.valueOf(cert.length), () ->
        {
            Assertions.assertArrayEquals(cert, cf.generateCertificate(in(cert)).getEncoded());
            Assertions.assertArrayEquals(cert, cf.generateCertificate(
                    in(X509Fixtures.ascii(X509Fixtures.pem("CERTIFICATE", cert)))).getEncoded());
        });
        withProperty(CERT_PROP, String.valueOf(cert.length - 1), () ->
        {
            for (byte[] input : new byte[][]{cert, X509Fixtures.ascii(X509Fixtures.pem("CERTIFICATE", cert))})
            {
                CertificateException e = Assertions.assertThrows(CertificateException.class,
                        () -> cf.generateCertificate(in(input)));
                Assertions.assertFalse(e instanceof CertificateParsingException,
                        "the bridge's ceiling was reached: " + e.getMessage());
                Assertions.assertEquals("object exceeds the configured ceiling; raise " + CERT_PROP, e.getMessage());
            }
        });
        withProperty(CONTAINER_PROP, String.valueOf(crl.length), () ->
                Assertions.assertArrayEquals(crl, ((java.security.cert.X509CRL) cf.generateCRL(in(crl))).getEncoded()));
        withProperty(CONTAINER_PROP, String.valueOf(crl.length - 1), () ->
        {
            CRLException e = Assertions.assertThrows(CRLException.class, () -> cf.generateCRL(in(crl)));
            Assertions.assertEquals("object exceeds the configured ceiling; raise " + CONTAINER_PROP, e.getMessage());
        });
    }

    /** A PEM body carries exactly one object; DER input still reads one and leaves the rest. */
    public void pemBodyWithMoreThanOneObjectIsRefused()
        throws Exception
    {
        CertificateFactory cf = cf();
        byte[] cert = X509Fixtures.certificate(null, null, null);
        byte[] crl = X509Fixtures.crl(null);
        byte[][] certBodies = {X509Fixtures.concat(cert, new byte[]{0}), X509Fixtures.concat(cert, cert)};
        for (byte[] body : certBodies)
        {
            byte[] pem = X509Fixtures.ascii(X509Fixtures.pem("CERTIFICATE", body));
            certRefusal("generateCertificate", "trailing data after the certificate",
                    () -> cf.generateCertificate(in(pem)));
            certRefusal("generateCertificates", "trailing data after the certificate",
                    () -> cf.generateCertificates(in(pem)));
        }
        byte[][] crlBodies = {X509Fixtures.concat(crl, new byte[]{0}), X509Fixtures.concat(crl, crl)};
        for (byte[] body : crlBodies)
        {
            byte[] pem = X509Fixtures.ascii(X509Fixtures.pem("X509 CRL", body));
            crlRefusal("generateCRL", "trailing data after the CRL", () -> cf.generateCRL(in(pem)));
            crlRefusal("generateCRLs", "trailing data after the CRL", () -> cf.generateCRLs(in(pem)));
        }

        InputStream der = in(X509Fixtures.concat(cert, new byte[]{7}));
        Certificate one = cf.generateCertificate(der);
        Assertions.assertArrayEquals(cert, one.getEncoded());
        Assertions.assertEquals(1, der.available(), "a DER read takes one object and leaves the rest");
        Assertions.assertEquals(7, der.read());
    }

    /** An OID whose text exceeds the parser's bound is a parse refusal; one character less parses. */
    public void overlongOidTextIsAParseRefusal()
        throws Exception
    {
        CertificateFactory cf = cf();
        String fits = X509Fixtures.oidOfLength(127);
        String over = X509Fixtures.oidOfLength(128);

        Assertions.assertEquals(Collections.singleton(fits), ((X509Certificate) cf.generateCertificate(
                in(X509Fixtures.certificate(fits, null, null)))).getNonCriticalExtensionOIDs());
        Assertions.assertEquals(fits, ((X509Certificate) cf.generateCertificate(
                in(X509Fixtures.certificate(null, fits, null)))).getSigAlgOID());
        Assertions.assertEquals(fits, ((java.security.cert.X509CRL) cf.generateCRL(
                in(X509Fixtures.crl(fits)))).getSigAlgOID());
        Assertions.assertNotNull(cf.generateCertificate(in(X509Fixtures.certificate(null, null, fits))));

        for (byte[] input : Arrays.asList(X509Fixtures.certificate(over, null, null),
                X509Fixtures.certificate(null, over, null), X509Fixtures.certificate(null, null, over)))
        {
            Assertions.assertThrows(CertificateParsingException.class, () -> cf.generateCertificate(in(input)));
        }
        crlRefusal("CRL signature OID", "did not decode", () -> cf.generateCRL(in(X509Fixtures.crl(over))));
    }
}
