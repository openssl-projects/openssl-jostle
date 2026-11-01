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
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Assertions;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * Certificates and CRLs minted with BouncyCastle (an instance, never installed) and parsed through the factory
 * under test, verified with a {@link RecordingSignatureProvider} at position 1. Nothing is compared across
 * providers: BouncyCastle only mints.
 */
public final class VerifyCascadeFixtures
{
    public static final Provider BC = new BouncyCastleProvider();
    public static final String MD5_RSA = "MD5withRSA";
    public static final String SHA256_RSA = "SHA256withRSA";
    public static final String RIPEMD160_RSA = "RIPEMD160withRSA";
    /** What the factory reports from getSigAlgName for RIPEMD160withRSA: no name row, so the dotted OID. */
    public static final String RIPEMD160_RSA_OID = "1.3.36.3.3.1.2";

    private static final int RSA_BITS = 2048;
    private static final long HOUR_MILLIS = 3_600_000L;

    private VerifyCascadeFixtures()
    {
    }

    /** One verify call: the certificate or CRL, the key, and the overload under test. */
    public interface Verify<T>
    {
        void verify(T object, PublicKey key) throws Exception;
    }

    public static KeyPair rsaKeyPair() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", BC);
        kpg.initialize(RSA_BITS);
        return kpg.generateKeyPair();
    }

    /** A certificate for {@code subjectKey} named {@code subject}, signed by {@code issuer} under {@code alg}. */
    public static byte[] certificate(String alg, KeyPair issuer, String issuerName, PublicKey subjectKey,
                                     String subject) throws Exception
    {
        Date now = new Date();
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(new X500Name(issuerName),
                BigInteger.valueOf(now.getTime()), new Date(now.getTime() - HOUR_MILLIS),
                new Date(now.getTime() + HOUR_MILLIS), new X500Name(subject), subjectKey);
        return builder.build(signer(alg, issuer)).getEncoded();
    }

    public static byte[] selfSigned(String alg, KeyPair kp, String name) throws Exception
    {
        return certificate(alg, kp, name, kp.getPublic(), name);
    }

    public static byte[] crl(String alg, KeyPair issuer, String issuerName) throws Exception
    {
        Date now = new Date();
        X509v2CRLBuilder builder = new X509v2CRLBuilder(new X500Name(issuerName), now);
        builder.setNextUpdate(new Date(now.getTime() + HOUR_MILLIS));
        return builder.build(signer(alg, issuer)).getEncoded();
    }

    private static ContentSigner signer(String alg, KeyPair kp) throws Exception
    {
        return new JcaContentSignerBuilder(alg).setProvider(BC).build(kp.getPrivate());
    }

    public static X509Certificate parse(CertificateFactory cf, byte[] der) throws Exception
    {
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der));
    }

    /**
     * Verifies a self-signed {@code alg} certificate parsed through {@code factoryProvider} with the recorder at
     * position 1 delegating to {@code delegate}, and returns how many verifications reached the recorder. An
     * unrelated key of the same family is refused with SignatureException through the same overload.
     */
    public static int certificateVerifications(Provider factoryProvider, Provider delegate, String alg,
                                               Verify<X509Certificate> verify) throws Exception
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", factoryProvider);
        X509Certificate cert = parse(cf, selfSigned(alg, rsaKeyPair(), "CN=Cascade Subject"));
        PublicKey unrelated = parse(cf, selfSigned(alg, rsaKeyPair(), "CN=Cascade Other")).getPublicKey();

        try (ProviderRegistrySnapshot ignored = new ProviderRegistrySnapshot())
        {
            RecordingSignatureProvider recorder = new RecordingSignatureProvider(delegate, cert.getSigAlgName());
            ProviderRegistrySnapshot.insertFirst(recorder);

            verify.verify(cert, cert.getPublicKey());
            int verifications = recorder.verifications();
            Assertions.assertThrows(SignatureException.class, () -> verify.verify(cert, unrelated),
                    "an unrelated key must not verify");
            return verifications;
        }
    }

    /** The CRL twin of {@link #certificateVerifications}; the keys come from certificates the factory parsed. */
    public static int crlVerifications(Provider factoryProvider, Provider delegate, String alg,
                                       Verify<X509CRL> verify) throws Exception
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", factoryProvider);
        KeyPair issuer = rsaKeyPair();
        PublicKey issuerKey = parse(cf, selfSigned(alg, issuer, "CN=Cascade Issuer")).getPublicKey();
        PublicKey unrelated = parse(cf, selfSigned(alg, rsaKeyPair(), "CN=Cascade Other")).getPublicKey();
        X509CRL crl = (X509CRL) cf.generateCRL(new ByteArrayInputStream(crl(alg, issuer, "CN=Cascade Issuer")));

        try (ProviderRegistrySnapshot ignored = new ProviderRegistrySnapshot())
        {
            RecordingSignatureProvider recorder = new RecordingSignatureProvider(delegate, crl.getSigAlgName());
            ProviderRegistrySnapshot.insertFirst(recorder);

            verify.verify(crl, issuerKey);
            int verifications = recorder.verifications();
            Assertions.assertThrows(SignatureException.class, () -> verify.verify(crl, unrelated),
                    "an unrelated key must not verify");
            return verifications;
        }
    }
}
