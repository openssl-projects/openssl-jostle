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

package org.openssl.jostle.test.fips;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.V1TBSCertificateGenerator;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * Each provider's X.509 factory answers with ITS OWN module's capability: the
 * same certificate bytes, a key on one provider and a typed refusal on the
 * other when the module does not serve the algorithm.
 *
 * <p><b>This cell does NOT discriminate the native library wiring, and saying
 * so is the point.</b> It was written to, and measured not to: with
 * {@code ProvFIPSX509} deliberately re-wired to the BASE NI it still PASSED.
 * The reason is the design it post-dates — {@code getPublicKey()} rebuilds the
 * key through the OWNING PROVIDER's KeyFactory, so the refusal comes from
 * JSLFIPS having no Ed25519 KeyFactory (measured: 0 Ed25519 services on 3.1.2,
 * 4 on 3.5.8) and not from which library parsed the bytes. Once the key stopped
 * coming from the NI, no key-shaped assertion could see the NI.
 *
 * <p>The wiring is guarded by two other things, both falsified against exactly
 * that sabotage: {@code FIPSNativeBindingIsolationTest}, which walks the SPI's
 * fields and fails naming the class and field, and
 * {@code FIPSX509CertificateFactoryBindingTest}, which aborted the JVM when the
 * base lib ctx was uninitialised. This cell is a capability contract, which is
 * worth having on its own terms — it is simply not the wiring guard.
 *
 * <p>The discriminator is Ed25519, whose availability DIFFERS between the two
 * supported modules (measured: absent on 3.1.2, present on 3.5.8). So the
 * assertion is written against the module's actual capability rather than
 * against one module's answer — the standing rule for anything the two modules
 * disagree about.
 *
 * <p>Gated in a {@code @BeforeEach}, so every cell here needs the module.
 */
public class FIPSX509LibraryBindingTest
{
    private static final String ED25519_SIG_OID = "1.3.101.112";

    private Provider fips;

    @BeforeEach
    public void before()
    {
        fips = FIPSTestUtil.assumeFipsProvider();
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    /**
     * An Ed25519 certificate, built through JSL because the point is to hand
     * the SAME BYTES to both factories.
     */
    private static byte[] ed25519Certificate()
        throws Exception
    {
        KeyPairGenerator g = KeyPairGenerator.getInstance("Ed25519", JostleProvider.PROVIDER_NAME);
        KeyPair kp = g.generateKeyPair();
        return selfSigned(kp.getPublic().getEncoded(), "Ed25519", ED25519_SIG_OID, kp.getPrivate());
    }

    private static byte[] selfSigned(byte[] spki, String sigAlgName, String sigOid, PrivateKey signer)
        throws Exception
    {
        AlgorithmIdentifier sigAlgId = new AlgorithmIdentifier(new ASN1ObjectIdentifier(sigOid));
        V1TBSCertificateGenerator tbsGen = new V1TBSCertificateGenerator();
        tbsGen.setSerialNumber(new ASN1Integer(BigInteger.valueOf(1)));
        tbsGen.setSignature(sigAlgId);
        tbsGen.setIssuer(new X500Name("CN=Jostle Library Binding Test"));
        tbsGen.setStartDate(new Time(new Date(1700000000000L)));
        tbsGen.setEndDate(new Time(new Date(1900000000000L)));
        tbsGen.setSubject(new X500Name("CN=Jostle Library Binding Test"));
        tbsGen.setSubjectPublicKeyInfo(SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(spki)));
        TBSCertificate tbs = tbsGen.generateTBSCertificate();

        Signature s = Signature.getInstance(sigAlgName, JostleProvider.PROVIDER_NAME);
        s.initSign(signer);
        s.update(tbs.getEncoded(ASN1Encoding.DER));
        byte[] sig = s.sign();

        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(tbs);
        v.add(sigAlgId);
        v.add(new DERBitString(sig));
        return new DERSequence(v).getEncoded(ASN1Encoding.DER);
    }

    /** Whether THIS module serves Ed25519 keys, asked rather than assumed. */
    private boolean moduleServesEd25519()
    {
        try
        {
            java.security.KeyFactory.getInstance("Ed25519", fips);
            return true;
        }
        catch (Exception absent)
        {
            return false;
        }
    }

    @Test
    public void theSameCertificateGetsTheModulesAnswerNotTheBaseLibrarys()
        throws Exception
    {
        byte[] der = ed25519Certificate();

        // Through JSL: parses, and the key is always available — mainline
        // libcrypto serves Ed25519 on every version we build against.
        X509Certificate viaJsl = (X509Certificate) CertificateFactory
                .getInstance("X.509", JostleProvider.PROVIDER_NAME)
                .generateCertificate(new ByteArrayInputStream(der));
        PublicKey jslKey = viaJsl.getPublicKey();
        Assertions.assertNotNull(jslKey);
        Assertions.assertTrue(jslKey.getClass().getName().startsWith("org.openssl.jostle."),
                "expected a Jostle key from JSL, got " + jslKey.getClass().getName());

        // Through JSLFIPS: the SAME bytes. The certificate must parse either
        // way — a key the module cannot build is not a reason to refuse the
        // certificate — and only the KEY depends on the module.
        X509Certificate viaFips = (X509Certificate) CertificateFactory
                .getInstance("X.509", fips)
                .generateCertificate(new ByteArrayInputStream(der));

        Assertions.assertEquals(viaJsl.getSubjectX500Principal(), viaFips.getSubjectX500Principal(),
                "both factories must parse the same certificate identically");
        Assertions.assertArrayEquals(viaJsl.getEncoded(), viaFips.getEncoded());

        if (moduleServesEd25519())
        {
            // 3.5.8: the module serves it, so the key must actually build.
            PublicKey fipsKey = viaFips.getPublicKey();
            Assertions.assertNotNull(fipsKey);
            Assertions.assertEquals(jslKey.getAlgorithm(), fipsKey.getAlgorithm());
        }
        else
        {
            // 3.1.2: the module does NOT serve it, so the provider-bound
            // KeyFactory lookup must refuse, naming the algorithm.
            ProviderException e = Assertions.assertThrows(ProviderException.class,
                    viaFips::getPublicKey,
                    "JSLFIPS returned a key its module does not serve");
            Assertions.assertTrue(e.getMessage().contains(ED25519_SIG_OID),
                    "the refusal must name the algorithm OID, got: " + e.getMessage());
        }
    }
}
