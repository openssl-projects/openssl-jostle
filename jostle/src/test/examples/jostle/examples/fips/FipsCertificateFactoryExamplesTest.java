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

import java.security.ProviderException;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.Collection;

/**
 * X.509 certificates, CRLs and certificate paths, parsed by JSLFIPS; a certificate's signature is verified in
 * the module. JSLFIPS registers no CertPathValidator or CertPathBuilder. The inputs are NIST PKITS test certificates
 * shipped with the examples under `jostle/examples/pkits`.
 */
public class FipsCertificateFactoryExamplesTest
        extends FipsExamples
{
    /**
     * Parse a DER certificate and check its signature with the issuer's public key.
     */
    @Test
    public void parseAndVerifyADerCertificate()
            throws Exception
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "JSLFIPS");
        X509Certificate root = (X509Certificate) cf.generateCertificate(
                getClass().getResourceAsStream("/jostle/examples/pkits/TrustAnchorRootCertificate.crt"));
        X509Certificate ca = (X509Certificate) cf.generateCertificate(
                getClass().getResourceAsStream("/jostle/examples/pkits/GoodCACert.crt"));
        Assertions.assertEquals(root.getSubjectX500Principal(), ca.getIssuerX500Principal());
        ca.verify(root.getPublicKey());
        Assertions.assertTrue(ca.getBasicConstraints() >= 0, "a CA certificate");
    }

    /**
     * Read several PEM certificates from one stream.
     */
    @Test
    public void readAPemBundle()
            throws Exception
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "JSLFIPS");
        Collection<? extends Certificate> certs = cf.generateCertificates(
                getClass().getResourceAsStream("/jostle/examples/pkits/GoodCAChain.pem"));
        Assertions.assertEquals(2, certs.size());
    }

    /**
     * Parse a CRL, verify it against its issuer, and ask whether a certificate is on it.
     */
    @Test
    public void checkACrl()
            throws Exception
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "JSLFIPS");
        X509Certificate ca = (X509Certificate) cf.generateCertificate(
                getClass().getResourceAsStream("/jostle/examples/pkits/GoodCACert.crt"));
        X509CRL crl = (X509CRL) cf.generateCRL(getClass().getResourceAsStream("/jostle/examples/pkits/GoodCACRL.crl"));
        crl.verify(ca.getPublicKey());
        Certificate revoked = cf.generateCertificate(
                getClass().getResourceAsStream("/jostle/examples/pkits/InvalidRevokedEETest3EE.crt"));
        Certificate good = cf.generateCertificate(
                getClass().getResourceAsStream("/jostle/examples/pkits/ValidCertificatePathTest1EE.crt"));
        Assertions.assertTrue(crl.isRevoked(revoked));
        Assertions.assertFalse(crl.isRevoked(good));
    }

    /**
     * A certificate path, end entity first, encoded as PkiPath and parsed back.
     */
    @Test
    public void encodeACertPath()
            throws Exception
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "JSLFIPS");
        Certificate ee = cf.generateCertificate(
                getClass().getResourceAsStream("/jostle/examples/pkits/ValidCertificatePathTest1EE.crt"));
        Certificate ca = cf.generateCertificate(
                getClass().getResourceAsStream("/jostle/examples/pkits/GoodCACert.crt"));
        CertPath path = cf.generateCertPath(Arrays.asList(ee, ca));
        byte[] encoded = path.getEncoded("PkiPath");
        CertPath back = cf.generateCertPath(new ByteArrayInputStream(encoded), "PkiPath");
        Assertions.assertEquals(path.getCertificates(), back.getCertificates());
    }

    /**
     * `getEncoded()` returns DER, not the bytes read. Here the input is a valid BER encoding of the same
     * certificate (its outer length in a longer form than DER allows); hash `getEncoded()`, not the input, when
     * fingerprinting. BouncyCastle does the same; the JDK keeps the input bytes.
     */
    @Test
    public void berInputIsReencodedAsDer()
            throws Exception
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "JSLFIPS");
        byte[] der = cf.generateCertificate(
                getClass().getResourceAsStream("/jostle/examples/pkits/GoodCACert.crt")).getEncoded();
        Assertions.assertEquals((byte) 0x82, der[1], "a two-byte DER length");
        byte[] ber = new byte[der.length + 1];
        ber[0] = 0x30;
        ber[1] = (byte) 0x83;
        System.arraycopy(der, 2, ber, 3, der.length - 2);
        X509Certificate fromBer = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(ber));
        Assertions.assertArrayEquals(der, fromBer.getEncoded());
    }

    /**
     * A DSA certificate may leave its key's parameters out and inherit them from the issuer (RFC 3279). It
     * parses, but its key cannot be built from the certificate alone: `getPublicKey()` throws
     * `ProviderException`.
     */
    @Test
    public void dsaCertificateInheritingParameters()
            throws Exception
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "JSLFIPS");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(
                getClass().getResourceAsStream("/jostle/examples/pkits/ValidDSAParameterInheritanceTest5EE.crt"));
        Assertions.assertNotNull(cert.getSubjectX500Principal());
        Assertions.assertThrows(ProviderException.class, cert::getPublicKey);
    }
}
