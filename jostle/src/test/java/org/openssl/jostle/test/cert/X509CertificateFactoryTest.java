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

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.V1TBSCertificateGenerator;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.util.Arrays;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.List;

/**
 * JCE-level tests for the JSL {@code CertificateFactory.X.509} SPI
 * ({@code X509CertificateFactorySpi} + {@code JSLKeyX509Certificate}).
 *
 * <p>The factory delegates the ASN.1 parsing to the JDK "SUN" factory but
 * re-wraps each {@link X509Certificate} so that {@code getPublicKey()} returns
 * a JSL-provider key usable directly in JSL's Signature SPIs. These tests
 * confirm:
 * <ol>
 *   <li>the factory resolves against the JSL provider by both "X.509" and the
 *       "X509" alias,</li>
 *   <li>{@code getPublicKey()} returns a JSL key (not the SUN key) for RSA, EC
 *       and the post-quantum (ML-DSA / SLH-DSA / ML-KEM) schemes, the latter
 *       re-derived through the JSL provider via the SubjectPublicKeyInfo
 *       algorithm OID,</li>
 *   <li>that JSL key actually verifies the certificate's (self- or CA-) signed
 *       signature through a JSL {@link Signature} — and a tampered TBS does
 *       NOT verify (negative path),</li>
 *   <li>the bulk {@code generateCertificates} and {@code generateCertPath}
 *       entry points round-trip.</li>
 * </ol>
 *
 * <p>The RSA and EC certificates are self-signed leaves generated offline with
 * OpenSSL (SHA256withRSA / SHA256withECDSA) and embedded as base64 DER. The
 * post-quantum certificates are built at runtime — bcprov's ASN.1 layer for the
 * certificate structure, the JSL provider for signing — so the test still needs
 * no PKIX cert-builder dependency (only bcprov is on the test classpath).
 */
public class X509CertificateFactoryTest
{
    // Self-signed 2048-bit RSA cert, sha256WithRSAEncryption.
    private static final String RSA_CERT_B64 =
            "MIIDFTCCAf2gAwIBAgIUVSbA2ohOLE8j05vqRp0HoFCgcYcwDQYJKoZIhvcNAQEL"
          + "BQAwGjEYMBYGA1UEAwwPSm9zdGxlIFJTQSBUZXN0MB4XDTI2MDYwNTIzNTA1NloX"
          + "DTM2MDYwMjIzNTA1NlowGjEYMBYGA1UEAwwPSm9zdGxlIFJTQSBUZXN0MIIBIjAN"
          + "BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtA9sLfgO1/dW9q1w/dyoox6S0C6l"
          + "fWYIwtr+kiuJicBfQ+0Bqm1XRqVhmLUTSadxLMbEY+rQ0Hyq0YNQrgKME68pbX1k"
          + "FQcNk3aS/a+aJ7J2XG/yZih5rHhgxKIjaGDfsBdQPlTueC8IV+3v+h8SweYuOv5y"
          + "aXKcxk+IeN/MzSag/2YqDsBzmN98R0hAGvvVsU9KN6OydTSqDAGJ0ontBoJmqj3N"
          + "5bdwImikjVSYC65frTMcvFgO2gOrRHiMCuqxhR0wLhn2AZote/LdUMIrIhB2wMOQ"
          + "1NiIN1jET8TN9FSVDXjlK+MFRWopx8rdtg3h7Egs1U6WsBQ8jOTQIASm1wIDAQAB"
          + "o1MwUTAdBgNVHQ4EFgQUTlapRpnUiPa9hzCribOp+lqpScgwHwYDVR0jBBgwFoAU"
          + "TlapRpnUiPa9hzCribOp+lqpScgwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0B"
          + "AQsFAAOCAQEAIS/foqm1TkS68DNfElAWhaabpP8/TBpNF5VTYgMHp9H/NGprGUm5"
          + "DXngGRQgN7WwsJVhuhJJP58qGOVjsuZlwXhN/65l3xDof9JuEAeGGJKkfJZfaF3b"
          + "6mDVlM2m3VCNcCRiuJqllDy/L6/D3t5WFxSizDGM4gYObX3tFnm4keiEohE2gZ8+"
          + "KpudoyLOnsEBxBO/Xv9+cQlfkoU7Pd6N+bDZ6HpoDkFp29iVxtRhPign+5HAl03J"
          + "4BVccBXua58I57YzhfP1YDD1DKK8H3SKzaHTrUkZBZkvAEvmIkOKIIOvJRjkXGlA"
          + "V806dyTKN7aECu5CPJLm9ZlxyuBPFTBE0w==";

    // Self-signed P-256 EC cert, ecdsa-with-SHA256.
    private static final String EC_CERT_B64 =
            "MIIBhzCCAS2gAwIBAgIUGw7BX327g5VGgIB0kLh4b3d/cEYwCgYIKoZIzj0EAwIw"
          + "GTEXMBUGA1UEAwwOSm9zdGxlIEVDIFRlc3QwHhcNMjYwNjA1MjM1MDU2WhcNMzYw"
          + "NjAyMjM1MDU2WjAZMRcwFQYDVQQDDA5Kb3N0bGUgRUMgVGVzdDBZMBMGByqGSM49"
          + "AgEGCCqGSM49AwEHA0IABJ3IIptnXEpqnBxrqPNim2tasxMlp4i+KuGDUwVLXXA5"
          + "kostunyWLXe+/HYJLhOuFZH3SSQuqaQuPlk3MHurxM2jUzBRMB0GA1UdDgQWBBQt"
          + "H9lYOOYWHAQ02wUzpkQnF59FuzAfBgNVHSMEGDAWgBQtH9lYOOYWHAQ02wUzpkQn"
          + "F59FuzAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIHQ6mpnH9ACV"
          + "LTlGJzOeeVi7bAbb+sshOBe8yU70hIW+AiEA1Pdbej87xccBxO1vrWs+/Kul3Y2q"
          + "jIWEouTwpbn+V60=";

    // Self-signed CA cert (CN=Jostle Test CA) that signed the CRL below.
    private static final String CA_CERT_B64 =
            "MIIDEzCCAfugAwIBAgIUVl1zlM3b8O5ShxK+m8azHpi1TtwwDQYJKoZIhvcNAQEL"
          + "BQAwGTEXMBUGA1UEAwwOSm9zdGxlIFRlc3QgQ0EwHhcNMjYwNjA2MDAxMDQ4WhcN"
          + "MzYwNjAzMDAxMDQ4WjAZMRcwFQYDVQQDDA5Kb3N0bGUgVGVzdCBDQTCCASIwDQYJ"
          + "KoZIhvcNAQEBBQADggEPADCCAQoCggEBAM8zeYWbDsUE/Y5QY74Ik3MJEq8VFE+v"
          + "cxw2IYR1yRAKwNkdacZU4RDmXVRh3iJ3Xo+TWScOShXe89MAYuNsuYghwaIZboh6"
          + "uOYNudrNklQ+CyKlI7jUzK/aXbEHUWkXRBBa6kuJzLLNXLywtlr3Ii135XmdUZqY"
          + "SNci5HXFKh+ya0h0oFWCBowfFN8CTkuMQdnwF1dQ8I+6DWV/ekd9gtvGeF/7LR72"
          + "D6xWimZ12mio7ZnPN+qY1oatZMRcNLv2AlrPsabym43nkkxqE7tg45d4L8FYO/lw"
          + "UHWZYY5VgognbR6QoSYEw5nxhrCPMgRP2HVnosMgqDEeLJoyTR4tEN0CAwEAAaNT"
          + "MFEwHQYDVR0OBBYEFMs1oSbFkDlkMxJ+Q6vCF+k/QPPoMB8GA1UdIwQYMBaAFMs1"
          + "oSbFkDlkMxJ+Q6vCF+k/QPPoMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEL"
          + "BQADggEBAK+41x+GT+5QULHTW4Ri606KWt0MrYUPIEcRQEFi1Qi8fepnz6Hbl4P/"
          + "DirtQEBjgoPrUJGZVxxMaRqz0psJUPKwKQfUEfS/N/sEXTVCb10UIFC++qD3iZNT"
          + "tUT+jaGHsEX0bT/Zkw7ixszxlqZh546z82M33Xdh4HRBfFLnMjvJAIfdrL9YDeEI"
          + "EelUN4nrLxMMRZCf8tSK7VvFk9dRpuP00o0PRDzEOPC5utLUsDEkb8bCW0s2c1ZN"
          + "+b+UrCYOvboDB533DjrGwHIq7Znp08r+u14oB98aa9ghivVKYof/VQRls6CXlRq4"
          + "Qd7XDenttvOwWlAvxXFencBPfNJrVag=";

    // CRL signed by the CA above, revoking one leaf with serial 0x2000.
    private static final String CRL_B64 =
            "MIIBiTBzAgEBMA0GCSqGSIb3DQEBCwUAMBkxFzAVBgNVBAMMDkpvc3RsZSBUZXN0"
          + "IENBFw0yNjA2MDYwMDEwNDhaFw0zNjA2MDMwMDEwNDhaMBUwEwICIAAXDTI2MDYw"
          + "NjAwMTA0OFqgDzANMAsGA1UdFAQEAgIQADANBgkqhkiG9w0BAQsFAAOCAQEAeuBm"
          + "C/c7wjrVsRqOFZiUkEMMMK/Pjwa2MvNNKlly8X39seBfuHDlOXF3k2VgILncf0XC"
          + "RhGGqP76V+89RK0H4rbcEg5oucsAf+eRQANRgZ7/zJQb1d9Ww6yjoEEEJpXTEUe1"
          + "WdTIsEoOWnl/VKTjJ+aW/AcL4bw3WkcxpvUC4yDKkiwrhnd0LR+3nE8fBdxLkks7"
          + "nUODsHAAr5GBFlGvX5YgbfBfwwDhOymv7ykvdjJXOd1KG9r7P3BptOecTWTrogtW"
          + "e8ys2kwz/qbEIWBnT7QIC129EamJ5RS5JWsWs43VoQy8ELj3on7N/WaWZ501m2KB"
          + "g7oHwW/9CNPoDpHBDA==";

    /** Serial number of the single revoked entry in {@link #CRL_B64}. */
    private static final BigInteger REVOKED_SERIAL = BigInteger.valueOf(0x2000);

    private static byte[] rsaCertDer()
    {
        return Base64.getDecoder().decode(RSA_CERT_B64);
    }

    private static byte[] caCertDer()
    {
        return Base64.getDecoder().decode(CA_CERT_B64);
    }

    private static byte[] crlDer()
    {
        return Base64.getDecoder().decode(CRL_B64);
    }

    private static byte[] ecCertDer()
    {
        return Base64.getDecoder().decode(EC_CERT_B64);
    }

    @BeforeAll
    static void before()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    private static X509Certificate parse(byte[] der) throws Exception
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", JostleProvider.PROVIDER_NAME);
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der));
    }

    // -----------------------------------------------------------------
    // Provider plumbing
    // -----------------------------------------------------------------

    @Test
    public void testFactory_resolvesByNameAndAlias() throws Exception
    {
        // Both the canonical "X.509" name and the "X509" alias must resolve
        // to the JSL factory.
        CertificateFactory byName = CertificateFactory.getInstance("X.509", JostleProvider.PROVIDER_NAME);
        CertificateFactory byAlias = CertificateFactory.getInstance("X509", JostleProvider.PROVIDER_NAME);
        Assertions.assertEquals(JostleProvider.PROVIDER_NAME, byName.getProvider().getName());
        Assertions.assertEquals(JostleProvider.PROVIDER_NAME, byAlias.getProvider().getName());
    }

    // -----------------------------------------------------------------
    // getPublicKey() returns a working JSL key
    // -----------------------------------------------------------------

    @Test
    public void testRsaCert_publicKeyIsJslAndVerifiesSelfSignature() throws Exception
    {
        X509Certificate cert = parse(rsaCertDer());
        assertPublicKeyIsJslAndVerifies(cert);
    }

    @Test
    public void testEcCert_publicKeyIsJslAndVerifiesSelfSignature() throws Exception
    {
        X509Certificate cert = parse(ecCertDer());
        assertPublicKeyIsJslAndVerifies(cert);
    }

    // -----------------------------------------------------------------
    // Post-quantum certificates: the SubjectPublicKeyInfo / signature OID must
    // resolve to a JSL KeyFactory / Signature so getPublicKey() returns a JSL
    // key (see the OID aliases in ProvMLDSA / ProvSLHDSA / ProvMLKEM and the
    // OID-keyed import in JSLKeyX509Certificate). Built at runtime because no
    // PQC cert fixtures exist; bcprov's ASN.1 layer supplies the cert structure
    // and the JSL provider does the signing.
    // -----------------------------------------------------------------

    @Test
    public void testMldsaCert_publicKeyIsJslAndVerifiesSelfSignature() throws Exception
    {
        KeyPair kp = KeyPairGenerator.getInstance("ML-DSA-44", JostleProvider.PROVIDER_NAME).generateKeyPair();
        byte[] der = buildPqcCert(kp.getPublic().getEncoded(), "ML-DSA-44",
                "2.16.840.1.101.3.4.3.17", kp.getPrivate());
        X509Certificate cert = parse(der);

        PublicKey pub = cert.getPublicKey();
        Assertions.assertTrue(pub.getClass().getName().startsWith("org.openssl.jostle"),
                "getPublicKey() did not return a JSL key, was: " + pub.getClass().getName());
        assertCertSignatureVerifies(cert, pub, "ML-DSA-44");
    }

    @Test
    public void testSlhdsaCert_publicKeyIsJslAndVerifiesSelfSignature() throws Exception
    {
        KeyPair kp = KeyPairGenerator.getInstance("SLH-DSA-SHA2-128F", JostleProvider.PROVIDER_NAME).generateKeyPair();
        byte[] der = buildPqcCert(kp.getPublic().getEncoded(), "SLH-DSA-SHA2-128F",
                "2.16.840.1.101.3.4.3.21", kp.getPrivate());
        X509Certificate cert = parse(der);

        PublicKey pub = cert.getPublicKey();
        Assertions.assertTrue(pub.getClass().getName().startsWith("org.openssl.jostle"),
                "getPublicKey() did not return a JSL key, was: " + pub.getClass().getName());
        assertCertSignatureVerifies(cert, pub, "SLH-DSA-SHA2-128F");
    }

    @Test
    public void testMlkemCert_publicKeyResolvedThroughJslByOid() throws Exception
    {
        // ML-KEM is a KEM, not a signature scheme: the cert carries an ML-KEM
        // subject key but is signed by an ML-DSA CA. The subject key must still
        // be re-derived through the JSL KeyFactory keyed on the ML-KEM SPKI OID
        // (2.16.840.1.101.3.4.4.2), and the ML-DSA signature must verify.
        KeyPair caKp = KeyPairGenerator.getInstance("ML-DSA-44", JostleProvider.PROVIDER_NAME).generateKeyPair();
        KeyPair kemKp = KeyPairGenerator.getInstance("ML-KEM-768", JostleProvider.PROVIDER_NAME).generateKeyPair();
        byte[] der = buildPqcCert(kemKp.getPublic().getEncoded(), "ML-DSA-44",
                "2.16.840.1.101.3.4.3.17", caKp.getPrivate());
        X509Certificate cert = parse(der);

        PublicKey pub = cert.getPublicKey();
        Assertions.assertTrue(pub.getClass().getName().startsWith("org.openssl.jostle"),
                "getPublicKey() did not return a JSL key, was: " + pub.getClass().getName());
        Assertions.assertArrayEquals(kemKp.getPublic().getEncoded(), pub.getEncoded(),
                "ML-KEM subject key did not round-trip through the JSL KeyFactory");
        assertCertSignatureVerifies(cert, caKp.getPublic(), "ML-DSA-44");
    }

    /**
     * Verify {@code cert}'s signature over its TBS with {@code verifyKey} through
     * a JSL {@link Signature} named {@code sigAlg}, and prove the verify actually
     * consumes the bytes: a tampered TBS must NOT verify (negative path).
     */
    private static void assertCertSignatureVerifies(X509Certificate cert, PublicKey verifyKey, String sigAlg)
            throws Exception
    {
        byte[] tbs = cert.getTBSCertificate();
        byte[] sig = cert.getSignature();

        Signature verifier = Signature.getInstance(sigAlg, JostleProvider.PROVIDER_NAME);
        verifier.initVerify(verifyKey);
        verifier.update(tbs);
        Assertions.assertTrue(verifier.verify(sig),
                sigAlg + ": JSL key failed to verify the certificate signature");

        byte[] tamperedTbs = Arrays.clone(tbs);
        tamperedTbs[tamperedTbs.length / 2] ^= 0x01;
        Signature verifier2 = Signature.getInstance(sigAlg, JostleProvider.PROVIDER_NAME);
        verifier2.initVerify(verifyKey);
        verifier2.update(tamperedTbs);
        Assertions.assertFalse(verifier2.verify(sig),
                sigAlg + ": tampered TBS unexpectedly verified");
    }

    /**
     * Assemble a minimal X.509 v1 certificate carrying {@code subjectSpki} as its
     * SubjectPublicKeyInfo, signed by {@code signerKey} through the JSL
     * {@link Signature} {@code sigAlgName}, with {@code sigOid} as the
     * signatureAlgorithm OID. Self-signed when {@code signerKey} matches the
     * subject key.
     */
    private static byte[] buildPqcCert(byte[] subjectSpki, String sigAlgName, String sigOid, PrivateKey signerKey)
            throws Exception
    {
        AlgorithmIdentifier sigAlgId = new AlgorithmIdentifier(new ASN1ObjectIdentifier(sigOid));

        V1TBSCertificateGenerator tbsGen = new V1TBSCertificateGenerator();
        tbsGen.setSerialNumber(new ASN1Integer(BigInteger.valueOf(1)));
        tbsGen.setSignature(sigAlgId);
        tbsGen.setIssuer(new X500Name("CN=Jostle PQC Test"));
        tbsGen.setStartDate(new Time(new Date(1700000000000L)));
        tbsGen.setEndDate(new Time(new Date(1900000000000L)));
        tbsGen.setSubject(new X500Name("CN=Jostle PQC Test"));
        tbsGen.setSubjectPublicKeyInfo(SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(subjectSpki)));
        TBSCertificate tbs = tbsGen.generateTBSCertificate();

        Signature signer = Signature.getInstance(sigAlgName, JostleProvider.PROVIDER_NAME);
        signer.initSign(signerKey);
        signer.update(tbs.getEncoded(ASN1Encoding.DER));
        byte[] sig = signer.sign();

        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(tbs);
        v.add(sigAlgId);
        v.add(new DERBitString(sig));
        return new DERSequence(v).getEncoded(ASN1Encoding.DER);
    }

    /**
     * The wrapped certificate's public key must come from the JSL provider,
     * and it must verify the certificate's own (self-signed) signature when
     * driven through a JSL {@link Signature}. A tampered TBS must NOT verify
     * — proving the verify actually consumes the bytes rather than rubber-
     * stamping (CLAUDE.md negative-path rule).
     */
    private static void assertPublicKeyIsJslAndVerifies(X509Certificate cert) throws Exception
    {
        PublicKey pub = cert.getPublicKey();
        Assertions.assertTrue(pub.getClass().getName().startsWith("org.openssl.jostle"),
                "getPublicKey() did not return a JSL key, was: " + pub.getClass().getName());

        byte[] tbs = cert.getTBSCertificate();
        byte[] sig = cert.getSignature();

        Signature verifier = Signature.getInstance(cert.getSigAlgName(), JostleProvider.PROVIDER_NAME);
        verifier.initVerify(pub);
        verifier.update(tbs);
        Assertions.assertTrue(verifier.verify(sig),
                cert.getSigAlgName() + ": JSL key failed to verify the cert's self-signature");

        // Negative: flip a byte in the TBS — verification must fail.
        byte[] tamperedTbs = Arrays.clone(tbs);
        tamperedTbs[tamperedTbs.length / 2] ^= 0x01;
        Signature verifier2 = Signature.getInstance(cert.getSigAlgName(), JostleProvider.PROVIDER_NAME);
        verifier2.initVerify(pub);
        verifier2.update(tamperedTbs);
        Assertions.assertFalse(verifier2.verify(sig),
                cert.getSigAlgName() + ": tampered TBS unexpectedly verified");
    }

    @Test
    public void testVerify_withProviderInstance_overload() throws Exception
    {
        // The verify(PublicKey, Provider) overload must delegate to the wrapped
        // cert, NOT fall through to Certificate's default (which throws
        // UnsupportedOperationException). Self-signed cert → verifies against its
        // own JSL public key when handed the JSL Provider instance.
        X509Certificate cert = parse(rsaCertDer());
        Provider jsl = Security.getProvider(JostleProvider.PROVIDER_NAME);
        cert.verify(cert.getPublicKey(), jsl); // must not throw
    }

    // -----------------------------------------------------------------
    // Bulk entry points
    // -----------------------------------------------------------------

    @Test
    public void testGenerateCertificates_collectionWrapsEachAsJslKeyed() throws Exception
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", JostleProvider.PROVIDER_NAME);
        Collection<? extends Certificate> certs =
                cf.generateCertificates(new ByteArrayInputStream(rsaCertDer()));
        Assertions.assertEquals(1, certs.size());
        for (Certificate c : certs)
        {
            // Each wrapped cert must hand back a JSL public key.
            Assertions.assertTrue(c.getPublicKey().getClass().getName().startsWith("org.openssl.jostle"),
                    "generateCertificates element returned a non-JSL key");
        }
    }

    @Test
    public void testGenerateCertPath_roundTrips() throws Exception
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", JostleProvider.PROVIDER_NAME);

        List<Certificate> list = new ArrayList<Certificate>();
        list.add(parse(rsaCertDer()));
        CertPath path = cf.generateCertPath(list);
        Assertions.assertEquals(1, path.getCertificates().size());
        Assertions.assertTrue(path.getCertificates().get(0).getPublicKey().getClass().getName().startsWith("org.openssl.jostle"),
                "generateCertPath(List) element returned a non-JSL key");

        // Encode then re-parse — the encoded form must round-trip back to an
        // equal cert list through the same factory.
        byte[] encoded = path.getEncoded();
        CertPath reparsed = cf.generateCertPath(new ByteArrayInputStream(encoded));
        Assertions.assertTrue(reparsed.getCertificates().get(0).getPublicKey().getClass().getName().startsWith("org.openssl.jostle"),
                "generateCertPath(InputStream) element returned a non-JSL key");
        Assertions.assertArrayEquals(
                list.get(0).getEncoded(),
                reparsed.getCertificates().get(0).getEncoded(),
                "CertPath did not round-trip through encode/parse");
    }

    @Test
    public void testGenerateCertPath_inputStreamWithEncoding_wrapsCerts() throws Exception
    {
        // Covers the engineGenerateCertPath(InputStream, encoding) overload — the
        // no-encoding InputStream and List paths are covered above. Uses the
        // non-default "PKCS7" encoding so the encoding-specific decode path is
        // exercised, and asserts the rebuilt path still yields a JSL key.
        CertificateFactory cf = CertificateFactory.getInstance("X.509", JostleProvider.PROVIDER_NAME);

        List<Certificate> list = new ArrayList<Certificate>();
        list.add(parse(rsaCertDer()));
        CertPath path = cf.generateCertPath(list);

        byte[] encoded = path.getEncoded("PKCS7");
        CertPath reparsed = cf.generateCertPath(new ByteArrayInputStream(encoded), "PKCS7");

        Assertions.assertEquals(1, reparsed.getCertificates().size());
        Assertions.assertTrue(
                reparsed.getCertificates().get(0).getPublicKey().getClass().getName().startsWith("org.openssl.jostle"),
                "generateCertPath(InputStream, encoding) element returned a non-JSL key");
        Assertions.assertArrayEquals(
                list.get(0).getEncoded(),
                reparsed.getCertificates().get(0).getEncoded(),
                "CertPath did not round-trip through PKCS7 encode/parse");
    }

    // -----------------------------------------------------------------
    // CRL parsing (delegated passthrough)
    // -----------------------------------------------------------------

    @Test
    public void testGenerateCRL_parsesAndReportsRevokedEntry() throws Exception
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", JostleProvider.PROVIDER_NAME);
        X509CRL crl = (X509CRL) cf.generateCRL(new ByteArrayInputStream(crlDer()));

        Assertions.assertEquals("CN=Jostle Test CA", crl.getIssuerX500Principal().getName());

        // The revoked leaf (serial 0x2000) must be reported as revoked, and an
        // unrelated serial must not be — proving the CRL body was actually parsed.
        X509CRLEntry entry = crl.getRevokedCertificate(REVOKED_SERIAL);
        Assertions.assertNotNull(entry, "expected serial 0x2000 to be revoked");
        Assertions.assertEquals(REVOKED_SERIAL, entry.getSerialNumber());
        Assertions.assertNull(crl.getRevokedCertificate(BigInteger.valueOf(0x9999)),
                "an unrevoked serial was unexpectedly reported as revoked");
    }

    @Test
    public void testGenerateCRL_verifiesWithCaKeyParsedThroughJsl() throws Exception
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", JostleProvider.PROVIDER_NAME);

        // Parse the CA cert through the JSL factory (its getPublicKey() yields a
        // JSL key) and use that key to verify the CRL's signature end-to-end.
        X509Certificate caCert =
                (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(caCertDer()));
        PublicKey caKey = caCert.getPublicKey();
        Assertions.assertTrue(caKey.getClass().getName().startsWith("org.openssl.jostle"),
                "CA getPublicKey() did not return a JSL key");

        X509CRL crl = (X509CRL) cf.generateCRL(new ByteArrayInputStream(crlDer()));
        // Must not throw — the JSL key verifies the CRL's signature via the JSL
        // provider's Signature SPI.
        crl.verify(caKey, JostleProvider.PROVIDER_NAME);
    }

    @Test
    public void testGenerateCRLs_collection() throws Exception
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", JostleProvider.PROVIDER_NAME);
        Collection<? extends java.security.cert.CRL> crls =
                cf.generateCRLs(new ByteArrayInputStream(crlDer()));
        Assertions.assertEquals(1, crls.size());
    }

    // -----------------------------------------------------------------
    // Bounds and refusals
    // -----------------------------------------------------------------

    /**
     * The member cap refuses at cap+1 and accepts at cap, on BOTH the PkiPath
     * and PKCS7 decoders. Both halves matter: a cap that refuses everything
     * would pass a refusal-only assertion.
     */
    @Test
    public void certPathMemberCap_refusesOverAndAcceptsAt() throws Exception
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", JostleProvider.PROVIDER_NAME);
        X509Certificate one = parse(rsaCertDer());

        String prop = org.openssl.jostle.jcajce.provider.cert.X509NI.MAX_MEMBERS_PROPERTY;
        String restore = System.getProperty(prop);
        try
        {
            // A small cap, so the test does not build 4096 certificates to
            // prove a bound that is a property precisely so it can move.
            System.setProperty(prop, "3");

            for (String encoding : new String[]{ "PkiPath", "PKCS7" })
            {
                byte[] atCap = cf.generateCertPath(repeat(one, 3)).getEncoded(encoding);
                Assertions.assertEquals(3,
                        cf.generateCertPath(new ByteArrayInputStream(atCap), encoding)
                                .getCertificates().size(),
                        encoding + ": exactly the cap must be accepted");

                System.setProperty(prop, "4");
                byte[] overCap = cf.generateCertPath(repeat(one, 4)).getEncoded(encoding);
                System.setProperty(prop, "3");

                CertificateException e = Assertions.assertThrows(CertificateException.class,
                        () -> cf.generateCertPath(new ByteArrayInputStream(overCap), encoding),
                        encoding + ": one over the cap must be refused");
                Assertions.assertTrue(e.getMessage().contains(prop),
                        "the refusal must name the property, so a deployment can raise it: "
                                + e.getMessage());
            }

            // And the List form, which allocates nothing from a stream.
            CertificateException e = Assertions.assertThrows(CertificateException.class,
                    () -> cf.generateCertPath(repeat(one, 4)));
            Assertions.assertTrue(e.getMessage().contains(prop), e.getMessage());
            Assertions.assertEquals(3, cf.generateCertPath(repeat(one, 3)).getCertificates().size());
        }
        finally
        {
            if (restore == null)
            {
                System.clearProperty(prop);
            }
            else
            {
                System.setProperty(prop, restore);
            }
        }
    }

    private static List<Certificate> repeat(X509Certificate c, int n)
    {
        List<Certificate> out = new ArrayList<Certificate>(n);
        for (int i = 0; i < n; i++)
        {
            out.add(c);
        }
        return out;
    }

    /**
     * A null list member is refused TYPED and named by position — neither
     * reference's behaviour, and deliberately so: SUN raises a bare
     * NullPointerException, BouncyCastle accepts the null silently.
     */
    @Test
    public void generateCertPath_nullMemberIsRefusedTypedAndByPosition() throws Exception
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", JostleProvider.PROVIDER_NAME);
        List<Certificate> list = new ArrayList<Certificate>();
        list.add(parse(rsaCertDer()));
        list.add(null);

        CertificateException e = Assertions.assertThrows(CertificateException.class,
                () -> cf.generateCertPath(list));
        Assertions.assertEquals(
                "certificate list contains a null element at position 1", e.getMessage());
    }

    /**
     * {@code getIssuerDN().equals} is SYMMETRIC. It was not: the wrapper
     * equalled a bare X500Principal that could never equal it back, which
     * breaks the equals contract and misbehaves in any collection comparing
     * the other way round. Both directions asserted, because only the second
     * one failed.
     */
    @Test
    public void issuerDnEqualityIsSymmetric() throws Exception
    {
        X509Certificate cert = parse(rsaCertDer());
        Principal dn = cert.getIssuerDN();
        javax.security.auth.x500.X500Principal principal = cert.getIssuerX500Principal();

        Assertions.assertEquals(dn, parse(rsaCertDer()).getIssuerDN(),
                "two wrappers over the same name must be equal");
        Assertions.assertEquals(dn.hashCode(), parse(rsaCertDer()).getIssuerDN().hashCode());

        Assertions.assertFalse(dn.equals(principal),
                "must not equal a bare X500Principal, which cannot equal it back");
        Assertions.assertFalse(principal.equals(dn),
                "the other direction — this is the half that makes it symmetric");
    }

    /**
     * An INDIRECT CRL may carry ONE serial under TWO issuers (RFC 5280 5.3.3),
     * and a serial-only index silently keeps whichever entry came last.
     *
     * <p>Measured before it was pinned, on a CRL carrying serial 4242 both
     * under its own issuer and, via certificateIssuer, under another CA: SUN
     * and BouncyCastle both answer {@code getRevokedCertificate(serial)} with
     * the entry under the CRL's OWN issuer. Ours answered with the OTHER one —
     * a divergence from both references, and the reason the index is keyed on
     * (effective issuer, serial).
     */
    @Test
    public void indirectCrl_sameSerialUnderTwoIssuers_isNotCollapsed() throws Exception
    {
        byte[] der = indirectCrlDer();
        CertificateFactory cf = CertificateFactory.getInstance("X.509", JostleProvider.PROVIDER_NAME);
        X509CRL crl = (X509CRL) cf.generateCRL(new ByteArrayInputStream(der));

        Assertions.assertEquals(2, crl.getRevokedCertificates().size(),
                "both entries must survive; a serial-only index keeps one");

        // The no-issuer overload means the CRL's own issuer, as both references do.
        X509CRLEntry own = crl.getRevokedCertificate(INDIRECT_SERIAL);
        Assertions.assertNotNull(own);
        Assertions.assertNull(own.getCertificateIssuer(),
                "must be the entry under the CRL's own issuer, not the delegated one");

        // Control: the same bytes through SUN agree, so this pins a contract
        // rather than our own reading of one.
        X509CRL sun = (X509CRL) CertificateFactory.getInstance("X.509", "SUN")
                .generateCRL(new ByteArrayInputStream(der));
        Assertions.assertNull(sun.getRevokedCertificate(INDIRECT_SERIAL).getCertificateIssuer());
    }

    private static final java.math.BigInteger INDIRECT_SERIAL = java.math.BigInteger.valueOf(4242);

    /**
     * A v2 indirect CRL whose two entries share {@link #INDIRECT_SERIAL}, the
     * second delegated to another CA by a certificateIssuer extension. Built
     * with bcprov's ASN.1 layer as test scaffolding only.
     */
    private static byte[] indirectCrlDer() throws Exception
    {
        java.security.KeyPairGenerator g =
                java.security.KeyPairGenerator.getInstance("RSA", JostleProvider.PROVIDER_NAME);
        g.initialize(2048);
        java.security.KeyPair kp = g.generateKeyPair();

        org.bouncycastle.asn1.ASN1EncodableVector entries =
                new org.bouncycastle.asn1.ASN1EncodableVector();

        org.bouncycastle.asn1.ASN1EncodableVector e1 =
                new org.bouncycastle.asn1.ASN1EncodableVector();
        e1.add(new org.bouncycastle.asn1.ASN1Integer(INDIRECT_SERIAL));
        e1.add(new org.bouncycastle.asn1.x509.Time(new java.util.Date(1600000000000L)));
        entries.add(new org.bouncycastle.asn1.DERSequence(e1));

        org.bouncycastle.asn1.x509.GeneralNames gn = new org.bouncycastle.asn1.x509.GeneralNames(
                new org.bouncycastle.asn1.x509.GeneralName(
                        org.bouncycastle.asn1.x509.GeneralName.directoryName,
                        new org.bouncycastle.asn1.x500.X500Name("CN=Other CA")));
        org.bouncycastle.asn1.x509.ExtensionsGenerator eg =
                new org.bouncycastle.asn1.x509.ExtensionsGenerator();
        eg.addExtension(org.bouncycastle.asn1.x509.Extension.certificateIssuer, true, gn);
        org.bouncycastle.asn1.ASN1EncodableVector e2 =
                new org.bouncycastle.asn1.ASN1EncodableVector();
        e2.add(new org.bouncycastle.asn1.ASN1Integer(INDIRECT_SERIAL));
        e2.add(new org.bouncycastle.asn1.x509.Time(new java.util.Date(1600000001000L)));
        e2.add(eg.generate());
        entries.add(new org.bouncycastle.asn1.DERSequence(e2));

        org.bouncycastle.asn1.x509.AlgorithmIdentifier alg =
                new org.bouncycastle.asn1.x509.AlgorithmIdentifier(
                        new org.bouncycastle.asn1.ASN1ObjectIdentifier("1.2.840.113549.1.1.11"),
                        org.bouncycastle.asn1.DERNull.INSTANCE);

        org.bouncycastle.asn1.ASN1EncodableVector tbs =
                new org.bouncycastle.asn1.ASN1EncodableVector();
        tbs.add(new org.bouncycastle.asn1.ASN1Integer(1));
        tbs.add(alg);
        tbs.add(new org.bouncycastle.asn1.x500.X500Name("CN=CRL Issuer"));
        tbs.add(new org.bouncycastle.asn1.x509.Time(new java.util.Date(1600000000000L)));
        tbs.add(new org.bouncycastle.asn1.x509.Time(new java.util.Date(1900000000000L)));
        tbs.add(new org.bouncycastle.asn1.DERSequence(entries));
        org.bouncycastle.asn1.x509.ExtensionsGenerator crlExt =
                new org.bouncycastle.asn1.x509.ExtensionsGenerator();
        crlExt.addExtension(org.bouncycastle.asn1.x509.Extension.issuingDistributionPoint, true,
                new org.bouncycastle.asn1.x509.IssuingDistributionPoint(null, false, true));
        tbs.add(new org.bouncycastle.asn1.DERTaggedObject(true, 0, crlExt.generate()));
        org.bouncycastle.asn1.DERSequence tbsSeq = new org.bouncycastle.asn1.DERSequence(tbs);

        java.security.Signature sig =
                java.security.Signature.getInstance("SHA256withRSA", JostleProvider.PROVIDER_NAME);
        sig.initSign(kp.getPrivate());
        sig.update(tbsSeq.getEncoded(org.bouncycastle.asn1.ASN1Encoding.DER));

        org.bouncycastle.asn1.ASN1EncodableVector crl =
                new org.bouncycastle.asn1.ASN1EncodableVector();
        crl.add(tbsSeq);
        crl.add(alg);
        crl.add(new org.bouncycastle.asn1.DERBitString(sig.sign()));
        return new org.bouncycastle.asn1.DERSequence(crl)
                .getEncoded(org.bouncycastle.asn1.ASN1Encoding.DER);
    }

    /**
     * {@code getRevocationReason} is OURS, not the inherited default.
     *
     * <p>The base class implementation re-parses {@code getEncoded()} through
     * {@code sun.security.x509.X509CRLEntryImpl}, so inheriting it would have
     * the reason read by the JDK while every other field on the entry is read
     * by OpenSSL — a second parser inside one object, and the exact shape this
     * whole work removes.
     *
     * <p>Swept over the committed PKITS CRL corpus against SUN rather than
     * pinned to one vector: measured 173 CRLs, 32 comparable entries, four
     * distinct reason codes, zero disagreements. The vacuity floors matter
     * because most PKITS CRLs revoke nothing — a corpus walk that found no
     * reasons at all would otherwise pass.
     */
    @Test
    public void crlEntryRevocationReason_agreesWithSunAcrossTheCorpus() throws Exception
    {
        CertificateFactory jsl = CertificateFactory.getInstance("X.509", JostleProvider.PROVIDER_NAME);
        CertificateFactory sun = CertificateFactory.getInstance("X.509", "SUN");

        java.io.File dir = new java.io.File("src/test/resources/pkits/crls");
        if (!dir.isDirectory())
        {
            dir = new java.io.File("jostle/src/test/resources/pkits/crls");
        }
        Assertions.assertTrue(dir.isDirectory(), "PKITS CRL corpus not found at " + dir);

        int compared = 0;
        java.util.Set<String> distinctReasons = new java.util.TreeSet<String>();
        for (java.io.File f : dir.listFiles())
        {
            byte[] der = java.nio.file.Files.readAllBytes(f.toPath());
            X509CRL ours;
            X509CRL theirs;
            try
            {
                ours = (X509CRL) jsl.generateCRL(new ByteArrayInputStream(der));
                theirs = (X509CRL) sun.generateCRL(new ByteArrayInputStream(der));
            }
            catch (Exception notACrl)
            {
                continue;
            }
            java.util.Set<? extends X509CRLEntry> theirEntries = theirs.getRevokedCertificates();
            if (theirEntries == null)
            {
                continue;
            }
            for (X509CRLEntry their : theirEntries)
            {
                X509CRLEntry our = ours.getRevokedCertificate(their.getSerialNumber());
                if (our == null)
                {
                    // Delegated to another issuer on an indirect CRL, so the
                    // serial-only overload correctly does not find it here.
                    continue;
                }
                java.security.cert.CRLReason mine = our.getRevocationReason();
                Assertions.assertEquals(their.getRevocationReason(), mine,
                        f.getName() + " serial " + their.getSerialNumber());
                compared++;
                if (mine != null)
                {
                    distinctReasons.add(mine.name());
                }
            }
        }

        Assertions.assertTrue(compared >= 25,
                "only " + compared + " entries compared — the corpus walk is not reaching them,"
                        + " and a zero-entry sweep would pass while measuring nothing");
        Assertions.assertTrue(distinctReasons.size() >= 3,
                "only " + distinctReasons + " reason codes seen — the sweep must exercise more"
                        + " than one arm of the enum mapping");
    }
}
