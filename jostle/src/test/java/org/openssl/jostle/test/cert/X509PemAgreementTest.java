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

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import java.io.ByteArrayInputStream;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Base64;
import java.util.Collection;

/**
 * PEM input to the X.509 {@code CertificateFactory}, ours against SUN and
 * BouncyCastle on the same bytes. The own-provider assertions on these inputs
 * are in {@link X509PemInputTest}.
 */
public class X509PemAgreementTest
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

    private static CertificateFactory cf(String provider) throws Exception
    {
        return CertificateFactory.getInstance("X.509", provider);
    }

    private static byte[] pem(String label, byte[] der)
    {
        return X509Fixtures.ascii(X509Fixtures.pem(label, der));
    }

    /** A blank line, and prose, before the BEGIN line: both parse to the same encoding as SUN's. */
    @Test
    public void textBeforeTheBeginLineParsesAsSunParsesIt() throws Exception
    {
        byte[] der = X509Fixtures.certificate(null, null, null);
        String preamble = "Certificate:\n    Data:\n        Version: 3 (0x2)\n";
        for (byte[] input : new byte[][]{
                X509Fixtures.concat(X509Fixtures.ascii("\n"), pem("CERTIFICATE", der)),
                X509Fixtures.concat(X509Fixtures.ascii(preamble), pem("CERTIFICATE", der))})
        {
            byte[] ours = cf(JSL).generateCertificate(new ByteArrayInputStream(input)).getEncoded();
            byte[] sun = cf(SUN).generateCertificate(new ByteArrayInputStream(input)).getEncoded();
            Assertions.assertArrayEquals(der, ours);
            Assertions.assertArrayEquals(sun, ours);
        }
    }

    /** A bundle with a comment line between two blocks, and DER and PEM mixed: SUN's count. */
    @Test
    public void bundlesYieldTheSameCountAsSun() throws Exception
    {
        byte[] c1 = X509Fixtures.certificate(null, null, null);
        byte[] c2 = X509Fixtures.certificate(null, null, null);
        byte[][] streams = {
                X509Fixtures.concat(pem("CERTIFICATE", c1),
                        X509Fixtures.concat(X509Fixtures.ascii("# a comment between two PEM blocks\n"),
                                pem("CERTIFICATE", c2))),
                X509Fixtures.concat(c1, pem("CERTIFICATE", c2)),
                X509Fixtures.concat(pem("CERTIFICATE", c1), c2)};
        for (byte[] stream : streams)
        {
            Collection<? extends Certificate> ours = cf(JSL).generateCertificates(new ByteArrayInputStream(stream));
            Collection<? extends Certificate> sun = cf(SUN).generateCertificates(new ByteArrayInputStream(stream));
            Assertions.assertEquals(sun.size(), ours.size());
            Assertions.assertEquals(2, ours.size());
        }
    }

    /**
     * Text with no PEM block anywhere: singular and plural both refuse on SUN
     * as here. Measured on JDK 25: SUN's plural reaches
     * {@code X509Factory.parseX509orPKCS7Cert}, which throws "No certificate
     * data found" rather than returning an empty collection.
     */
    @Test
    public void textWithNoBlockIsRefusedAsSunRefusesIt()
    {
        byte[] noBlock = X509Fixtures.ascii("just some text\nwith no PEM block in it at all\n");
        for (String provider : new String[]{JSL, SUN})
        {
            Assertions.assertThrows(CertificateException.class,
                    () -> cf(provider).generateCertificate(new ByteArrayInputStream(noBlock)), provider);
            Assertions.assertThrows(CertificateException.class,
                    () -> cf(provider).generateCertificates(new ByteArrayInputStream(noBlock)), provider);
        }
    }

    /**
     * Garbage between the markers, a missing footer, and a CRL wrapped as a
     * certificate: refused with CertificateException by all three. Neither
     * reference checks the label against the call site, so the CRL is refused
     * by its structure.
     */
    @Test
    public void malformedBlocksAreRefusedTypedByAllThree() throws Exception
    {
        byte[] der = X509Fixtures.certificate(null, null, null);
        String body = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(der);
        byte[][] inputs = {
                X509Fixtures.ascii("-----BEGIN CERTIFICATE-----\nnot base64 at all!!\n-----END CERTIFICATE-----\n"),
                X509Fixtures.ascii("-----BEGIN CERTIFICATE-----\n" + body + "\n"),
                pem("CERTIFICATE", X509Fixtures.crl(null))};
        for (byte[] input : inputs)
        {
            for (String provider : new String[]{JSL, SUN, BC})
            {
                Assertions.assertThrows(CertificateException.class,
                        () -> cf(provider).generateCertificate(new ByteArrayInputStream(input)), provider);
            }
        }
    }
}
