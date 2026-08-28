/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.dh;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.DomainParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.spec.DHDomainParameterSpec;
import org.openssl.jostle.util.Arrays;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import java.math.BigInteger;
import java.security.AlgorithmParameterGenerator;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.DSAParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * X9.42 ({@code dhpublicnumber}) DH, folded into the single {@code DH}
 * surface exactly as BouncyCastle does — no separate JCE algorithm name.
 *
 * <p>The form is decided by whether the subgroup order q is present:
 * {@link DHDomainParameterSpec} produces X9.42, a plain
 * {@link DHParameterSpec} produces PKCS#3, and a decoded key keeps whichever
 * form its encoding carried.
 *
 * <p>Domain parameters are generated ONCE per JVM rather than per test: a
 * 2048-bit DSA parameter search is seconds of work, and generating fresh
 * parameters per trial would dominate the run. They are still random per JVM,
 * never a pinned fixture.
 */
public class DHX942Test
{
    private static final ASN1ObjectIdentifier DH_PUBLIC_NUMBER =
            new ASN1ObjectIdentifier("1.2.840.10046.2.1");
    private static final ASN1ObjectIdentifier DH_KEY_AGREEMENT =
            new ASN1ObjectIdentifier("1.2.840.113549.1.3.1");

    private static DHDomainParameterSpec x942;
    private static DHParameterSpec pkcs3;

    @BeforeAll
    public static void beforeAll() throws Exception
    {
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        // BC's DSA parameter generator is the convenient source of a random
        // (p, q, g) triple; DH and DSA share the FFC domain shape.
        AlgorithmParameterGenerator apg = AlgorithmParameterGenerator.getInstance("DSA", "BC");
        apg.init(2048);
        DSAParameterSpec dsa = apg.generateParameters().getParameterSpec(DSAParameterSpec.class);
        x942 = new DHDomainParameterSpec(dsa.getP(), dsa.getQ(), dsa.getG());
        pkcs3 = new DHParameterSpec(dsa.getP(), dsa.getG());
    }

    private static KeyPair jslPair(DHParameterSpec spec) throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH", JostleProvider.PROVIDER_NAME);
        kpg.initialize(spec);
        return kpg.generateKeyPair();
    }

    private static ASN1ObjectIdentifier spkiOid(PublicKey k)
    {
        return SubjectPublicKeyInfo.getInstance(k.getEncoded()).getAlgorithm().getAlgorithm();
    }

    private static ASN1ObjectIdentifier p8Oid(PrivateKey k)
    {
        return PrivateKeyInfo.getInstance(k.getEncoded()).getPrivateKeyAlgorithm().getAlgorithm();
    }

    /** q as carried by the re-encoded SubjectPublicKeyInfo, or null. */
    private static BigInteger encodedQ(PublicKey k)
    {
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(k.getEncoded());
        if (!DH_PUBLIC_NUMBER.equals(spki.getAlgorithm().getAlgorithm()))
        {
            return null;
        }
        return DomainParameters.getInstance(spki.getAlgorithm().getParameters()).getQ();
    }

    private static byte[] agree(String provider, PrivateKey priv, PublicKey pub) throws Exception
    {
        KeyAgreement ka = KeyAgreement.getInstance("DH", provider);
        ka.init(priv);
        ka.doPhase(pub, true);
        return ka.generateSecret();
    }

    /**
     * The property a caller depends on: a q-carrying spec yields the X9.42
     * OID AND q survives into the re-encoded AlgorithmIdentifier. Asserting
     * only that the key re-derives would pass with q silently dropped — the
     * PSS-OID lesson.
     */
    @Test
    public void x942SpecProducesDhPublicNumberCarryingQ() throws Exception
    {
        KeyPair kp = jslPair(x942);

        Assertions.assertEquals(DH_PUBLIC_NUMBER, spkiOid(kp.getPublic()));
        Assertions.assertEquals(DH_PUBLIC_NUMBER, p8Oid(kp.getPrivate()));
        Assertions.assertEquals(x942.getQ(), encodedQ(kp.getPublic()),
                "q must survive into the encoded DomainParameters");
    }

    /** Control: without q, the same code path must still emit PKCS#3. */
    @Test
    public void pkcs3SpecProducesDhKeyAgreementWithoutQ() throws Exception
    {
        KeyPair kp = jslPair(pkcs3);

        Assertions.assertEquals(DH_KEY_AGREEMENT, spkiOid(kp.getPublic()));
        Assertions.assertEquals(DH_KEY_AGREEMENT, p8Oid(kp.getPrivate()));
        Assertions.assertNull(encodedQ(kp.getPublic()));
    }

    /**
     * getParams() must hand q back. Before WI-11 it returned a plain
     * DHParameterSpec, so a caller could not discover the subgroup order of a
     * key that demonstrably had one.
     */
    @Test
    public void getParamsExposesQForX942AndNotForPkcs3() throws Exception
    {
        DHParameterSpec fromX942 = ((DHPublicKey) jslPair(x942).getPublic()).getParams();
        Assertions.assertTrue(fromX942 instanceof DHDomainParameterSpec,
                "an X9.42 key must report its q; got " + fromX942.getClass().getName());
        Assertions.assertEquals(x942.getQ(), ((DHDomainParameterSpec) fromX942).getQ());

        DHParameterSpec fromPkcs3 = ((DHPublicKey) jslPair(pkcs3).getPublic()).getParams();
        Assertions.assertFalse(fromPkcs3 instanceof DHDomainParameterSpec,
                "a PKCS#3 key has no q to report");
    }

    /** Jostle encodes X9.42, BouncyCastle decodes it and agrees. */
    @Test
    public void jslEncodesX942_bcDecodesAndAgrees() throws Exception
    {
        KeyPair a = jslPair(x942);
        KeyPair b = jslPair(x942);
        byte[] jsl = agree(JostleProvider.PROVIDER_NAME, a.getPrivate(), b.getPublic());

        KeyFactory bc = KeyFactory.getInstance("DH", "BC");
        PrivateKey bcPriv = bc.generatePrivate(new PKCS8EncodedKeySpec(a.getPrivate().getEncoded()));
        PublicKey bcPub = bc.generatePublic(new X509EncodedKeySpec(b.getPublic().getEncoded()));

        Assertions.assertEquals(DH_PUBLIC_NUMBER, spkiOid(bcPub),
                "BC must re-emit the X9.42 form it was given");
        Assertions.assertTrue(Arrays.areEqual(jsl, agree("BC", bcPriv, bcPub)));
    }

    /** BouncyCastle encodes X9.42, Jostle decodes it and agrees. */
    @Test
    public void bcEncodesX942_jslDecodesAndAgrees() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH", "BC");
        kpg.initialize(new org.bouncycastle.jcajce.spec.DHDomainParameterSpec(
                x942.getP(), x942.getQ(), x942.getG()));
        KeyPair a = kpg.generateKeyPair();
        KeyPair b = kpg.generateKeyPair();
        byte[] bcSecret = agree("BC", a.getPrivate(), b.getPublic());

        KeyFactory jsl = KeyFactory.getInstance("DH", JostleProvider.PROVIDER_NAME);
        PrivateKey jslPriv = jsl.generatePrivate(new PKCS8EncodedKeySpec(a.getPrivate().getEncoded()));
        PublicKey jslPub = jsl.generatePublic(new X509EncodedKeySpec(b.getPublic().getEncoded()));

        Assertions.assertEquals(DH_PUBLIC_NUMBER, spkiOid(jslPub));
        Assertions.assertEquals(x942.getQ(), encodedQ(jslPub));
        Assertions.assertTrue(Arrays.areEqual(bcSecret,
                agree(JostleProvider.PROVIDER_NAME, jslPriv, jslPub)));
    }

    /**
     * The BouncyCastle divergence, pinned in BOTH directions with matched-form
     * positive controls beside it. OpenSSL routes the two encoding forms to
     * different keymgmts and refuses to pair them even on identical p and g;
     * BC agrees on p, g and x alone and pairs them happily.
     */
    @Test
    public void mixedEncodingFormsAreRefusedBothDirections() throws Exception
    {
        KeyPair x = jslPair(x942);
        KeyPair three = jslPair(pkcs3);

        // Positive controls first: each form agrees with itself, so the
        // refusals below cannot be "DH agreement is broken".
        Assertions.assertNotNull(agree(JostleProvider.PROVIDER_NAME,
                x.getPrivate(), jslPair(x942).getPublic()));
        Assertions.assertNotNull(agree(JostleProvider.PROVIDER_NAME,
                three.getPrivate(), jslPair(pkcs3).getPublic()));

        String expected = "DH doPhase: peer key was decoded from a different DH encoding form "
                + "(PKCS#3 dhKeyAgreement vs X9.42 dhpublicnumber); "
                + "re-encode the peer through this provider's KeyFactory";

        InvalidKeyException a = Assertions.assertThrows(InvalidKeyException.class,
                () -> agree(JostleProvider.PROVIDER_NAME, x.getPrivate(), three.getPublic()));
        Assertions.assertEquals(expected, a.getMessage());

        InvalidKeyException b = Assertions.assertThrows(InvalidKeyException.class,
                () -> agree(JostleProvider.PROVIDER_NAME, three.getPrivate(), x.getPublic()));
        Assertions.assertEquals(expected, b.getMessage());
    }

    /**
     * The d2i family consumes one TLV and ignores what follows, so the decode
     * path must check the consumed length. Exercised on the X9.42 branch,
     * which is the one WI-11 newly makes reachable, with an exact-length
     * positive control proving the boundary sits at consumed == len.
     */
    @Test
    public void x942EncodingsWithTrailingGarbageAreRejected() throws Exception
    {
        KeyPair kp = jslPair(x942);
        KeyFactory jsl = KeyFactory.getInstance("DH", JostleProvider.PROVIDER_NAME);

        byte[] spki = kp.getPublic().getEncoded();
        byte[] p8 = kp.getPrivate().getEncoded();

        // Exact length is accepted — the boundary is where it should be.
        Assertions.assertNotNull(jsl.generatePublic(new X509EncodedKeySpec(spki)));
        Assertions.assertNotNull(jsl.generatePrivate(new PKCS8EncodedKeySpec(p8)));

        for (int extra : new int[]{1, 37})
        {
            byte[] pub = java.util.Arrays.copyOf(spki, spki.length + extra);
            Assertions.assertThrows(java.security.spec.InvalidKeySpecException.class,
                    () -> jsl.generatePublic(new X509EncodedKeySpec(pub)),
                    "SPKI with " + extra + " trailing byte(s) must be rejected");

            byte[] priv = java.util.Arrays.copyOf(p8, p8.length + extra);
            Assertions.assertThrows(java.security.spec.InvalidKeySpecException.class,
                    () -> jsl.generatePrivate(new PKCS8EncodedKeySpec(priv)),
                    "PKCS#8 with " + extra + " trailing byte(s) must be rejected");
        }
    }
}
